// Screen wiring. One screen at a time, one decision per screen (progdisc).
//
// This file renders what ceremony.ts decides and owns nothing security-relevant. The three
// places where that matters:
//   - the verdict buttons are two plain buttons with no default and no Enter handler, so
//     the only way past the safety words is a deliberate press on one of them;
//   - a refusal is rendered from copy.ts and offers no path back into the ceremony;
//   - the vault's idle re-lock is an event the SCREENS have to hear about. session.ts
//     empties the vault on a timer under whatever screen is up, so onLock releases the
//     camera and renders the lock notice, and every await into the ceremony is caught:
//     both are invoked as `void this.x(...)`, where a rejection would otherwise change no
//     screen, tear nothing down, and leave the camera running behind a frozen count.
//
// v0 scope, held on purpose (secondsys): pair in person, then one-to-one text. No groups,
// no attachments, no read receipts, no typing indicators, no notifications, no background
// sync, no settings, no export. Messages are pulled on an interval and on a button.

import { OWN_CARD_SERIAL, PairingSession } from '../pairing-session.js';
import { Messaging, MessagingError, MAX_BODY_BYTES } from '../messaging.js';
import { fromRelayMailboxId, type MailboxCoordinate } from '../mailbox.js';
import { RelayError, type RelayClient } from '../relay-client.js';
import { fromHex, toHex } from '../bytes.js';
import { PairingCeremony, type CeremonyRole, type CeremonyView, type OwnInbox } from './ceremony.js';
import { CameraFailure, OpticalScanner, type ScanProgress } from './camera.js';
import { QrPlayer } from './qr-display.js';
import { IDLE_LOCK_MS, KeyweaveSession } from './session.js';
import { MIN_PASSPHRASE_LENGTH, passphraseHint } from './passphrase.js';
import {
  CAMERA_COPY,
  CONVERSATION_COPY,
  REFUSAL_CANCELLED,
  SUPERSEDE_NOTICE,
  interruptedRefusal,
  lockNotice,
  relayFailureMessage,
  scanCounters,
  syncSummary,
  unlockFailureMessage,
  type Refusal,
} from './copy.js';
import { byId, cloneScreen, role, setHidden, setList, setText, shortHex } from './dom.js';
import type { MessageRecord } from '../vault.js';
import type { BlobStore } from './storage.js';
import type { VaultCrypto } from './vault-crypto.js';

/**
 * How often an open conversation asks the relay for anything. Deliberately a poll on a
 * visible screen rather than a background sync or a push: a service worker would keep
 * fetching a mailbox after the tab is closed, which is traffic the relay can see and the
 * person cannot (residual R3).
 */
export const POLL_INTERVAL_MS = 20_000;

/**
 * Grouping window for the conversation: consecutive messages inside it read as one run.
 *
 * Also, and this is the security-relevant use, the threshold at which heldBack() calls an
 * inbound message relay-withheld. Exported for the same reason the helpers at the foot of
 * this file are: a rule that is only ever read as text is only ever guarded as text.
 */
export const RUN_GAP_MS = 5 * 60_000;

export interface AppDeps {
  crypto: VaultCrypto;
  store: BlobStore;
  relay: RelayClient;
}

export class KeyweaveApp {
  private readonly screens = byId<HTMLElement>('screens');
  private readonly steps = byId<HTMLElement>('steps');
  private readonly tcb = byId<HTMLElement>('tcb');
  private readonly live = byId<HTMLElement>('live');

  private session: KeyweaveSession | undefined;
  private ceremony: PairingCeremony | undefined;
  private player: QrPlayer | undefined;
  private scanner: OpticalScanner | undefined;
  private poll: ReturnType<typeof setInterval> | undefined;

  constructor(private readonly deps: AppDeps) {}

  async start(): Promise<void> {
    const existing = await this.deps.store.load();
    this.renderUnlock(existing === null);
  }

  private announce(message: string): void {
    setText(this.live, message);
  }

  private show(fragment: DocumentFragment): void {
    // Every screen change stops the conversation poll. Doing it HERE rather than in each
    // renderer is what makes it true for the paths nobody remembers: the idle lock, a
    // refusal, a camera failure. The conversation renderer starts a fresh one afterwards.
    this.stopPolling();
    this.screens.replaceChildren(fragment);
    // Focus moves to the new heading on every screen change. Without it a screen reader
    // and a keyboard both stay wherever the last button was, which in a ceremony that
    // swaps the whole page under them is disorienting. The headings carry tabindex="-1"
    // so they are focusable by script and not by Tab.
    this.screens.querySelector('h1')?.focus();
  }

  private setChrome(step: number | null, ceremonyVisible: boolean): void {
    setHidden(this.steps, step === null);
    if (step !== null) setText(this.steps, `Turn ${step} of 3`);
    setHidden(this.tcb, !ceremonyVisible);
  }

  private teardownOptics(): void {
    this.player?.stop();
    this.player = undefined;
    this.scanner?.stop();
    this.scanner = undefined;
  }

  private stopPolling(): void {
    if (this.poll !== undefined) clearInterval(this.poll);
    this.poll = undefined;
  }

  // ---- unlock / first run -------------------------------------------------

  private renderUnlock(firstRun: boolean, notice?: string): void {
    this.setChrome(null, false);
    const fragment = cloneScreen('screen-unlock');
    const title = role<HTMLElement>(fragment, 'title');
    const lede = role<HTMLElement>(fragment, 'lede');
    const noticeSlot = role<HTMLElement>(fragment, 'notice');
    const form = role<HTMLFormElement>(fragment, 'form');
    const input = form.querySelector<HTMLInputElement>('#passphrase')!;
    const confirmField = role<HTMLElement>(fragment, 'confirm-field');
    const confirm = fragment.querySelector<HTMLInputElement>('#passphrase-confirm')!;
    const reveal = role<HTMLButtonElement>(fragment, 'reveal');
    const hint = role<HTMLElement>(fragment, 'hint');
    const error = role<HTMLElement>(fragment, 'error');
    const submit = role<HTMLButtonElement>(fragment, 'submit');
    const busy = role<HTMLElement>(fragment, 'busy');
    const busyText = role<HTMLElement>(fragment, 'busy-text');

    setText(title, firstRun ? 'Create your Keyweave identity' : 'Unlock Keyweave');
    setText(
      lede,
      firstRun
        ? 'Keyweave generates two keys on this device and wraps them with a passphrase you choose. Nothing is uploaded and there is no account.'
        : 'Your keys are on this device, wrapped with your passphrase.',
    );
    setText(submit, firstRun ? 'Create identity' : 'Unlock');
    setHidden(confirmField, !firstRun);
    input.autocomplete = firstRun ? 'new-password' : 'current-password';
    if (notice !== undefined) {
      setText(noticeSlot, notice);
      setHidden(noticeSlot, false);
    }

    const refreshHint = () => {
      if (!firstRun) {
        setText(hint, 'Enter the passphrase you chose when you created this vault.');
        return;
      }
      const result = passphraseHint(input.value);
      setText(hint, `${result.label}. ${result.detail}`);
    };
    refreshHint();
    input.addEventListener('input', refreshHint);

    reveal.addEventListener('click', () => {
      const shown = input.type === 'text';
      input.type = shown ? 'password' : 'text';
      reveal.setAttribute('aria-pressed', String(!shown));
      reveal.setAttribute('aria-label', shown ? 'Show passphrase' : 'Hide passphrase');
      const use = reveal.querySelector('use');
      use?.setAttribute('href', shown ? '#i-eye' : '#i-eye-off');
    });

    form.addEventListener('submit', (event) => {
      event.preventDefault();
      void this.submitPassphrase({
        firstRun,
        passphrase: input.value,
        confirmation: confirm.value,
        error,
        submit,
        busy,
        busyText,
      });
    });

    this.show(fragment);
  }

  private async submitPassphrase(args: {
    firstRun: boolean;
    passphrase: string;
    confirmation: string;
    error: HTMLElement;
    submit: HTMLButtonElement;
    busy: HTMLElement;
    busyText: HTMLElement;
  }): Promise<void> {
    // `diagnostic` is the layer-below Error, kept where a developer can find it and a person
    // cannot: a data attribute is not rendered and is not read out, so it is not a second
    // sentence on the screen. Always assigned or removed, never left over from a previous
    // failure on the same reused element.
    const fail = (message: string, diagnostic?: unknown) => {
      setText(args.error, message);
      if (diagnostic === undefined) delete args.error.dataset.detail;
      else {
        args.error.dataset.detail =
          diagnostic instanceof Error ? diagnostic.message : String(diagnostic);
      }
      setHidden(args.error, false);
      this.announce(message);
    };
    setHidden(args.error, true);

    if (args.firstRun) {
      const hint = passphraseHint(args.passphrase);
      if (!hint.acceptable) {
        fail(`Use at least ${MIN_PASSPHRASE_LENGTH} characters.`);
        return;
      }
      if (args.passphrase !== args.confirmation) {
        fail('The two passphrases are different.');
        return;
      }
    }

    args.submit.disabled = true;
    setHidden(args.busy, false);
    // Argon2id at 256 MiB over 3 passes runs in a worker, so this stays interactive. The
    // wait is the point of the parameters: it is what a stolen vault costs per guess.
    setText(
      args.busyText,
      args.firstRun
        ? 'Deriving your wrapping key. A few seconds, deliberately.'
        : 'Unwrapping your vault. A few seconds, deliberately.',
    );
    this.announce('Working');

    // The idle re-lock is a real event that empties the vault under whatever screen is up.
    // Without this callback nothing in the UI ever hears about it: the ready screen keeps
    // its two buttons, the scan screen keeps the camera running, and the first thing that
    // touches a key throws into a promise nobody is holding.
    const opts = { onLock: () => this.onLock() };
    try {
      this.session = args.firstRun
        ? await KeyweaveSession.createIdentity(
            this.deps.crypto,
            this.deps.store,
            args.passphrase,
            opts,
          )
        : await KeyweaveSession.unlock(this.deps.crypto, this.deps.store, args.passphrase, opts);
      this.renderReady();
    } catch (error) {
      args.submit.disabled = false;
      setHidden(args.busy, true);
      // Through copy.ts like every other user-facing string. This line used to render the
      // raw Error message, which is the most common failure path in the product (a mistyped
      // passphrase) bypassing the one file that says the copy is part of the security.
      fail(unlockFailureMessage(error), error);
    }
  }

  // ---- ready --------------------------------------------------------------

  private renderReady(): void {
    this.teardownOptics();
    this.ceremony = undefined;
    // Reached from a plain click handler on the paired and refused screens, so a throw here
    // would be an uncaught error and a button that does nothing.
    if (this.locked()) {
      this.onLock();
      return;
    }
    this.setChrome(null, false);
    const session = this.requireSession();
    const fragment = cloneScreen('screen-ready');

    setText(
      role<HTMLElement>(fragment, 'identity'),
      `This device identity starts ${shortHex(toHex(session.identityPublicKey()))}.`,
    );
    role<HTMLButtonElement>(fragment, 'show-first').addEventListener('click', () => {
      void this.beginCeremony('show-first');
    });
    role<HTMLButtonElement>(fragment, 'scan-first').addEventListener('click', () => {
      void this.beginCeremony('scan-first');
    });

    const peers = session.peers();
    if (peers.length > 0) {
      const list = role<HTMLElement>(fragment, 'contact-list');
      list.replaceChildren(
        ...peers.map((peerId) => {
          const row = cloneScreen('tpl-contact');
          setText(role<HTMLElement>(row, 'label'), `Identity ${shortHex(toHex(peerId))}`);
          role<HTMLButtonElement>(row, 'open').addEventListener('click', () => {
            this.renderConversation(peerId);
          });
          return row;
        }),
      );
      setHidden(role<HTMLElement>(fragment, 'contacts'), false);
    }

    this.show(fragment);
    this.announce('Ready to pair in person.');
  }

  // ---- the idle re-lock ---------------------------------------------------

  private locked(): boolean {
    return this.session === undefined || this.session.isLocked();
  }

  /**
   * The vault locked itself. Release the camera FIRST (a live camera behind a frozen screen
   * is the failure this whole path exists to prevent), drop the ceremony, and say which
   * thing happened. The passphrase is already forgotten: session.ts hangs forget() on the
   * vault's own lock path, so it happens whether or not this callback runs.
   */
  private onLock(): void {
    this.teardownOptics();
    this.ceremony = undefined;
    this.session = undefined;
    this.renderUnlock(false, lockNotice(Math.round(IDLE_LOCK_MS / 60_000)));
    this.announce('Keyweave locked itself.');
  }

  /**
   * Anything that threw out of the ceremony. Terminal, like every other refusal: there is
   * no resuming from a half-finished exchange, and leaving the scan screen up would leave
   * the camera running with no phase change coming to tear it down.
   */
  private failCeremony(error: unknown): void {
    if (this.locked()) {
      this.onLock();
      return;
    }
    this.teardownOptics();
    this.ceremony = undefined;
    this.setChrome(null, false);
    this.renderRefusal(interruptedRefusal(error));
  }

  // ---- ceremony -----------------------------------------------------------

  /**
   * Reserve the drop box THIS device will read for this pairing, and split it: the peer gets
   * the id and the write cap optically, we keep the pull token.
   *
   * A fresh box per pairing is the point (R8: a mailbox's budgets belong to the mailbox, so
   * two pairings sharing one would let either peer spend the other's quota). A relay that
   * cannot be reached returns undefined rather than stopping the ceremony: pairing is the
   * in-person part and it works with no network at all, so refusing to pin a key because a
   * server was down would be the wrong trade. Messaging is then not connected for that
   * contact, and the paired screen says exactly that.
   */
  private async reserveInbox(): Promise<
    { coordinate: MailboxCoordinate; own: OwnInbox } | undefined
  > {
    try {
      const created = await this.deps.relay.createMailbox();
      const id = fromRelayMailboxId(created.mailboxId);
      return {
        coordinate: { id, writeCap: created.writeCap },
        own: { id, pullToken: created.pullToken },
      };
    } catch {
      // Deliberately swallowed. Nothing here is security-relevant and the consequence is
      // visible on the next screen, which is the only place it means anything to anyone.
      return undefined;
    }
  }

  private async beginCeremony(role_: CeremonyRole): Promise<void> {
    try {
      const session = this.requireSession();
      const inbox = await this.reserveInbox();
      // The lock timer can have fired during that round trip, and keys() is the next thing
      // this touches.
      if (this.locked()) {
        this.onLock();
        return;
      }
      const pairing = await PairingSession.begin(
        session.keys(),
        OWN_CARD_SERIAL,
        {},
        inbox?.coordinate,
      );
      this.ceremony = PairingCeremony.begin(pairing, session, role_, inbox?.own);
      this.renderCeremony();
    } catch (error) {
      this.failCeremony(error);
    }
  }

  private renderCeremony(): void {
    const ceremony = this.ceremony;
    if (!ceremony) return;
    const view = ceremony.view();
    this.teardownOptics();
    switch (view.phase) {
      case 'show':
        this.renderShow(view);
        break;
      case 'scan':
        void this.renderScan(view);
        break;
      case 'compare':
        this.renderCompare(view);
        break;
      case 'paired':
        this.renderPaired(view);
        break;
      case 'refused':
        this.renderRefused(view);
        break;
    }
  }

  private renderShow(view: CeremonyView): void {
    this.setChrome(view.step, true);
    const fragment = cloneScreen('screen-show');
    setText(role<HTMLElement>(fragment, 'title'), view.heading);
    setText(role<HTMLElement>(fragment, 'lede'), view.lede);
    const canvas = role<HTMLCanvasElement>(fragment, 'canvas');
    const status = role<HTMLElement>(fragment, 'status');
    setText(
      status,
      view.playlist.length > 1
        ? `${view.playlist.length} codes, shown in turn. Let it cycle at least once.`
        : 'One code.',
    );
    canvas.setAttribute('aria-label', 'Animated pairing code for the other camera');

    role<HTMLButtonElement>(fragment, 'done').addEventListener('click', () => {
      this.ceremony?.handOff();
      this.renderCeremony();
    });
    role<HTMLButtonElement>(fragment, 'cancel').addEventListener('click', () => this.cancel());

    this.show(fragment);
    this.player = new QrPlayer(canvas);
    this.player.play(view.playlist);
    this.announce(`${view.heading}. Turn ${view.step} of ${view.totalSteps}.`);
  }

  private async renderScan(view: CeremonyView): Promise<void> {
    this.setChrome(view.step, true);
    const fragment = cloneScreen('screen-scan');
    setText(role<HTMLElement>(fragment, 'title'), view.heading);
    setText(role<HTMLElement>(fragment, 'lede'), view.lede);
    const video = role<HTMLVideoElement>(fragment, 'video');
    const progress = role<HTMLElement>(fragment, 'progress');
    const counters = role<HTMLElement>(fragment, 'counters');
    const cameraNote = role<HTMLElement>(fragment, 'camera-note');
    const error = role<HTMLElement>(fragment, 'error');
    const retry = role<HTMLButtonElement>(fragment, 'retry');
    role<HTMLButtonElement>(fragment, 'cancel').addEventListener('click', () => this.cancel());

    this.show(fragment);
    this.announce(`${view.heading}. Turn ${view.step} of ${view.totalSteps}.`);

    const expected = view.expecting.length;
    const describe = (p: ScanProgress) => {
      const collected = this.ceremony?.view().collected.length ?? 0;
      const block = p.k > 0 ? ` Reading a code: ${p.solved} of ${p.k} blocks.` : '';
      setText(progress, `${collected} of ${expected} codes read.${block}`);
      setText(counters, scanCounters(p.malformed, p.capped));
    };
    describe({ k: 0, solved: 0, malformed: 0, capped: 0, dropped: 0 });

    const startScanner = async () => {
      setHidden(error, true);
      setHidden(retry, true);
      // A retry must not leave the previous attempt holding the camera.
      this.scanner?.stop();
      const scanner = new OpticalScanner({
        video,
        onProgress: describe,
        onPayload: (payload) => {
          void this.offerPayload(payload);
        },
      });
      this.scanner = scanner;
      try {
        const notes = await scanner.start();
        const parts: string[] = [];
        if (notes.actualFrameRate !== undefined && notes.actualFrameRate !== notes.requestedFrameRate) {
          parts.push(
            `Asked this camera for ${notes.requestedFrameRate} frames per second, it is running ${notes.actualFrameRate}.`,
          );
        }
        if (notes.refusedLiveChange) parts.push(CAMERA_COPY.refusedLiveChange);
        setText(cameraNote, parts.join(' '));
      } catch (failure) {
        this.scanner = undefined;
        const kind = failure instanceof CameraFailure ? failure.kind : 'unknown';
        setText(error, cameraMessage(kind));
        setHidden(error, false);
        // Only a denial is worth a retry button: the others need something changed first.
        setHidden(retry, kind !== 'denied');
        this.announce(cameraMessage(kind));
      }
    };

    retry.addEventListener('click', () => void startScanner());
    await startScanner();
  }

  private async offerPayload(payload: Uint8Array): Promise<void> {
    const ceremony = this.ceremony;
    if (!ceremony) return;
    const before = ceremony.view();
    let result: Awaited<ReturnType<PairingCeremony['offer']>>;
    try {
      result = await ceremony.offer(payload);
    } catch (error) {
      // A throw leaves the machine on the phase it was already on, so no future frame will
      // change it and renderScan's teardown would never run. Do it here instead.
      this.failCeremony(error);
      return;
    }
    if (result === 'ignored' || result === 'duplicate') return;
    const after = ceremony.view();
    if (after.phase !== before.phase || after.step !== before.step) {
      this.renderCeremony();
      return;
    }
    this.announce(`${after.collected.length} of ${after.expecting.length} codes read.`);
  }

  private renderCompare(view: CeremonyView): void {
    this.setChrome(view.step, true);
    const fragment = cloneScreen('screen-compare');
    const supersede = role<HTMLElement>(fragment, 'supersede');
    if (view.supersede) {
      setText(supersede, SUPERSEDE_NOTICE);
      setHidden(supersede, false);
    }
    setList(role<HTMLElement>(fragment, 'words'), view.words);

    // No default, no autofocus, and no submit handler: the two buttons are the only way
    // out of this screen and neither is reachable by pressing Enter on the previous one.
    role<HTMLButtonElement>(fragment, 'match').addEventListener('click', () => {
      void this.confirmMatch();
    });
    role<HTMLButtonElement>(fragment, 'mismatch').addEventListener('click', () => {
      this.ceremony?.confirmMismatch();
      this.renderCeremony();
    });

    this.show(fragment);
    this.announce('Six words are on screen. Read them out loud and compare.');
  }

  private async confirmMatch(): Promise<void> {
    const ceremony = this.ceremony;
    if (!ceremony) return;
    try {
      await ceremony.confirmMatch();
    } catch (error) {
      // A lock and a failed write are different events with different advice. Naming the
      // wrong one here would tell somebody their browser refused to store a contact when
      // in fact the app emptied its own vault under them.
      if (this.locked()) {
        this.onLock();
        return;
      }
      // A failed write is not a pin. Say so instead of showing a paired screen.
      this.renderWriteFailure(error);
      return;
    }
    this.renderCeremony();
  }

  private renderPaired(view: CeremonyView): void {
    this.teardownOptics();
    this.setChrome(null, false);
    const fragment = cloneScreen('screen-paired');
    setText(
      role<HTMLElement>(fragment, 'lede'),
      'The words matched, so this key is pinned on this device. A different card for this identity will require another ceremony in person.',
    );
    setText(role<HTMLElement>(fragment, 'identity'), view.peer?.identityHex ?? '');
    setText(role<HTMLElement>(fragment, 'serial'), String(view.peer?.serial ?? ''));
    setText(role<HTMLElement>(fragment, 'metadata'), CONVERSATION_COPY.metadataNote);

    const message = role<HTMLButtonElement>(fragment, 'message');
    const peerHex = view.peer?.identityHex;
    if (view.mailboxLinked && peerHex !== undefined) {
      message.addEventListener('click', () => this.renderConversation(fromHex(peerHex)));
    } else {
      // Pinned, but with nowhere to put a message. Saying so here is the difference between
      // a working button and a button that fails on the screen after this one.
      message.disabled = true;
      const notice = role<HTMLElement>(fragment, 'no-mailbox');
      setText(notice, CONVERSATION_COPY.noMailbox);
      setHidden(notice, false);
    }

    role<HTMLButtonElement>(fragment, 'again').addEventListener('click', () => this.renderReady());
    this.show(fragment);
    this.announce('Paired. The contact is saved on this device.');
  }

  // ---- conversation -------------------------------------------------------

  private renderConversation(peerId: Uint8Array): void {
    if (this.locked()) {
      this.onLock();
      return;
    }
    this.teardownOptics();
    this.ceremony = undefined;
    this.setChrome(null, false);
    const session = this.requireSession();
    const messaging = new Messaging(session, this.deps.relay);
    const fragment = cloneScreen('screen-conversation');

    const thread = role<HTMLElement>(fragment, 'thread');
    const empty = role<HTMLElement>(fragment, 'empty');
    const error = role<HTMLElement>(fragment, 'error');
    const status = role<HTMLElement>(fragment, 'status');
    const form = role<HTMLFormElement>(fragment, 'form');
    const input = form.querySelector<HTMLTextAreaElement>('#message-body')!;
    const send = role<HTMLButtonElement>(fragment, 'send');
    const refresh = role<HTMLButtonElement>(fragment, 'refresh');
    const unavailable = role<HTMLElement>(fragment, 'unavailable');

    setText(role<HTMLElement>(fragment, 'peer'), `Identity ${shortHex(toHex(peerId))}.`);
    setText(role<HTMLElement>(fragment, 'delivery-note'), CONVERSATION_COPY.deliveryNote);
    setText(role<HTMLElement>(fragment, 'metadata-note'), CONVERSATION_COPY.metadataNote);
    setText(role<HTMLElement>(fragment, 'forward-note'), CONVERSATION_COPY.forwardSecrecyNote);
    setText(empty, CONVERSATION_COPY.empty);

    const state = messaging.state(peerId);
    const ready = state === 'ready';
    if (!ready) {
      setText(
        unavailable,
        state === 'not-pinned' ? CONVERSATION_COPY.notPinned : CONVERSATION_COPY.noMailbox,
      );
      setHidden(unavailable, false);
      setHidden(form, true);
      refresh.disabled = true;
    }

    const paint = () => {
      const records = ready ? messaging.conversation(peerId) : [];
      renderThread(thread, records);
      setHidden(empty, records.length > 0);
    };
    const fail = (message: string) => {
      setText(error, message);
      setHidden(error, false);
      this.announce(message);
    };

    // Every path into the relay goes through here. Three reasons it is one function: a
    // rejection in a click handler otherwise changes no screen and leaves a button that
    // silently does nothing; the interval and the two buttons must not run at the same time,
    // because both mutate the vault and both persist; and a lock during a round trip is a
    // different outcome from a relay failure and has to stop the repaint.
    let busy = false;
    const run = async (work: () => Promise<string>) => {
      if (busy) return;
      busy = true;
      setHidden(error, true);
      send.disabled = true;
      refresh.disabled = true;
      let locked = false;
      try {
        setText(status, await work());
      } catch (failure) {
        if (this.locked()) {
          locked = true;
          this.onLock();
        } else {
          fail(describeMessagingFailure(failure));
        }
      } finally {
        busy = false;
        // TWO QUESTIONS, NOT ONE, and they are asked at two different layers on purpose
        // (defdepth). `locked` says THIS pass reported a lock, which is messaging.ts doing
        // its job. `this.locked()` asks the vault directly, and it is the guard for the day
        // some future pass resolves under a lock without saying so: paint() reads the
        // message array, so on an emptied vault it throws inside a finally, out of a `void
        // run(...)` call, where nothing catches it and no screen changes.
        //
        // Vault.isLocked() reads a field and does NOT call touch(), so asking does not rearm
        // the idle timer this is testing for. The state it produces (both buttons left
        // disabled on a screen that has already been replaced) is the one the send path
        // pins, so the two paths now agree rather than differing by which of them threw.
        if (!locked && !this.locked()) {
          send.disabled = false;
          refresh.disabled = !ready;
          paint();
        }
      }
    };

    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const text = input.value;
      if (text.trim().length === 0) return;
      void run(async () => {
        const report = await messaging.send(peerId, text);
        input.value = '';
        return report.failure
          ? `${CONVERSATION_COPY.queued}. ${relayFailureMessage(report.failure.failure)}`
          : CONVERSATION_COPY.relayed;
      });
    });

    refresh.addEventListener('click', () => {
      void run(async () => syncSummary(await messaging.sync(peerId)));
    });

    role<HTMLButtonElement>(fragment, 'back').addEventListener('click', () => this.renderReady());

    paint();
    this.show(fragment);
    this.announce(`Conversation with identity ${shortHex(toHex(peerId))}.`);

    if (!ready) return;
    // Started after show(), which cleared whatever the previous screen had running. The
    // interval is the only background work in the app: no service worker, no push.
    this.poll = setInterval(() => {
      if (this.locked()) {
        this.onLock();
        return;
      }
      void run(async () => syncSummary(await messaging.sync(peerId)));
    }, POLL_INTERVAL_MS);
    void run(async () => syncSummary(await messaging.sync(peerId)));
  }

  private renderRefused(view: CeremonyView): void {
    this.teardownOptics();
    this.setChrome(null, false);
    this.renderRefusal(view.refusal ?? REFUSAL_CANCELLED);
  }

  private renderRefusal(refusal: Refusal): void {
    const fragment = cloneScreen('screen-refused');
    setText(role<HTMLElement>(fragment, 'title'), refusal.title);
    setText(role<HTMLElement>(fragment, 'detail'), refusal.detail);
    setText(role<HTMLElement>(fragment, 'advice'), refusal.advice);
    role<HTMLButtonElement>(fragment, 'again').addEventListener('click', () => this.renderReady());
    this.show(fragment);
    this.announce(refusal.title);
  }

  private renderWriteFailure(error: unknown): void {
    this.teardownOptics();
    this.setChrome(null, false);
    const fragment = cloneScreen('screen-refused');
    setText(role<HTMLElement>(fragment, 'title'), 'The contact could not be saved');
    setText(
      role<HTMLElement>(fragment, 'detail'),
      `The words matched, but writing the vault back to this browser failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    setText(
      role<HTMLElement>(fragment, 'advice'),
      'Treat this as not paired. Private windows and full storage are the usual causes.',
    );
    role<HTMLButtonElement>(fragment, 'again').addEventListener('click', () => this.renderReady());
    this.show(fragment);
    this.announce('The contact could not be saved.');
  }

  private cancel(): void {
    this.ceremony?.cancel();
    this.renderCeremony();
  }

  private requireSession(): KeyweaveSession {
    if (!this.session) throw new Error('app: no unlocked session');
    return this.session;
  }
}

// The helpers below are EXPORTED so the suite can execute them rather than read them.
//
// They were module-private, and the only wall available to a private function is a regex
// over this file's source text. That is not a wall: a measured pass over the assertions
// ui-shell.test.ts makes about this file defeated 19 of 19 single-edit mutations, every one
// of them typechecking clean. `export` costs nothing at runtime and turns each rule below
// into something a test can call and disagree with.
export function cameraMessage(kind: string): string {
  switch (kind) {
    case 'insecure-context':
      return CAMERA_COPY.insecureContext;
    case 'denied':
      return CAMERA_COPY.denied;
    case 'no-camera':
      return CAMERA_COPY.noCamera;
    case 'in-use':
      return CAMERA_COPY.inUse;
    default:
      return CAMERA_COPY.unknown;
  }
}

/**
 * The conversation, oldest at the top and newest at the bottom.
 *
 * gestalt: who sent a message is carried by which side it sits on and by the run it belongs
 * to, not by a name on every line. A run is a stretch of messages from one side inside
 * RUN_GAP_MS, and only the LAST message of a run prints the time and the delivery state, so
 * the reader gets one timestamp per exchange rather than one per bubble.
 *
 * A HELD-BACK message is always a run of its own. The thread sorts on the sender's clock,
 * so a blob the relay sat on and released later lands wherever the sender wrote it, which
 * can be days above the last thing the reader saw. Left inside a neighbouring run it would
 * inherit that run's grouping and, unless it happened to be last in it, print nothing at
 * all: the relay's withholding would render as ordinary already-read history. Its own run
 * means it always prints, and metaFor() says when it actually turned up.
 */
export function renderThread(list: HTMLElement, records: readonly MessageRecord[]): void {
  list.replaceChildren(
    ...records.map((record, at) => {
      const previous = records[at - 1];
      const next = records[at + 1];
      const startsRun =
        previous === undefined ||
        heldBack(record) ||
        heldBack(previous) ||
        previous.direction !== record.direction ||
        record.timestampMs - previous.timestampMs > RUN_GAP_MS;
      const endsRun =
        next === undefined ||
        heldBack(record) ||
        heldBack(next) ||
        next.direction !== record.direction ||
        next.timestampMs - record.timestampMs > RUN_GAP_MS;

      const row = cloneScreen('tpl-message');
      const item = row.querySelector('li')!;
      item.classList.add(record.direction === 'out' ? 'msg-out' : 'msg-in');
      if (startsRun) item.classList.add('msg-start');
      setText(role<HTMLElement>(row, 'body'), decodeBody(record.body));

      const meta = role<HTMLElement>(row, 'meta');
      if (endsRun) setText(meta, metaFor(record));
      else setHidden(meta, true);
      return row;
    }),
  );
}

/**
 * Whether an inbound message reached this device long after its sender wrote it. The gap is
 * the relay's: it may hold a blob for as long as the acceptance window and hand it over
 * whenever it likes, and this device cannot tell a slow relay from a network that was down.
 * The same RUN_GAP_MS the grouping uses, so "not part of the exchange around it" means one
 * thing on this screen. Outbound records have no arrival time and never qualify.
 */
export function heldBack(record: MessageRecord): boolean {
  if (record.direction !== 'in' || record.receivedAtMs === undefined) return false;
  return record.receivedAtMs - record.timestampMs > RUN_GAP_MS;
}

export function metaFor(record: MessageRecord): string {
  const at = clockOf(record.timestampMs);
  if (record.direction === 'in') {
    // Both clocks, and whose each one is, on the messages where they disagree. The sent
    // time is the sender's own signed claim; the arrival time is what this device saw.
    return heldBack(record)
      ? `Reached this device at ${clockOf(record.receivedAtMs!)}, sent at ${at}`
      : `Received, sent at ${at}`;
  }
  const state =
    record.delivery === 'relayed' ? CONVERSATION_COPY.relayed : CONVERSATION_COPY.queued;
  return `${state}, ${at}`;
}

export function clockOf(timestampMs: number): string {
  const at = new Date(timestampMs);
  return Number.isNaN(at.getTime()) ? 'an unreadable time' : at.toLocaleString();
}

/**
 * A body is whatever bytes the sender sealed. It is authentic, which is not the same as
 * being valid UTF-8, so the decoder is the lenient one: a replacement character is a better
 * outcome than a conversation that will not render.
 */
export function decodeBody(body: Uint8Array): string {
  return new TextDecoder().decode(body);
}

/**
 * Never blames the peer. A relay failure is named as the relay's; a message that will not
 * open is not surfaced here at all (messaging.ts counts it and drops it), so there is no
 * wording for it to get wrong.
 */
export function describeMessagingFailure(error: unknown): string {
  if (error instanceof RelayError) return relayFailureMessage(error.failure);
  if (error instanceof MessagingError) {
    if (error.state === 'too-long') return CONVERSATION_COPY.tooLong(MAX_BODY_BYTES);
    if (error.state === 'no-mailbox') return CONVERSATION_COPY.noMailbox;
    if (error.state === 'not-pinned') return CONVERSATION_COPY.notPinned;
    // The screen the conversation shows when a pass ended in the vault emptying itself.
    // Unreachable from renderConversation as it stands, because run() rules the lock out
    // before it calls this and hands that case to onLock instead; it is here because the
    // line below renders a developer's sentence, and a state with no branch is one refactor
    // away from putting 'messaging: the vault locked itself part way through this pass' on
    // screen. Executed by the suite through this function rather than through the screen.
    if (error.state === 'locked') return CONVERSATION_COPY.locked;
    return error.message;
  }
  return `Keyweave could not finish that: ${error instanceof Error ? error.message : String(error)}`;
}
