// @vitest-environment happy-dom

// The idle re-lock, driven through the real screens.
//
// WHY THIS FILE EXISTS. app.ts had no executable coverage at all: every rule it carries was
// guarded by a regex over its own source text, and a measured pass defeated 19 of 19
// single-edit mutations, each one typechecking clean. Two of those defeats are why this file
// leads with the camera. Gutting teardownOptics, so a lock never calls stop() on the
// scanner, left the whole suite green; and an earlier review found the same failure for
// real, with the lock wired in the session layer and no screen listening for it. What that
// looks like from across the room is a camera still running behind a page that says the app
// locked itself, which is the one failure this path exists to prevent.
//
// WHAT IS FAKE, AND WHY. happy-dom has no media stack, no canvas raster and no Worker, so a
// 2d context, a video frame callback, a Worker and a camera stand in for a browser. Above
// those four stubs everything is the real thing:
// the real OpticalScanner opens the fake camera and its stop() reaches a real track object,
// the real ceremony state machine drives the screens, and the VAULT'S OWN idle timer is what
// fires every lock here, at the constant the product ships. The KDF is the one deliberate
// exception. Argon2id at the shipped parameters is about three seconds per call, so
// VaultCrypto is faked, and faked faithfully in the one respect a lock depends on: session.ts
// hangs crypto.forget() on the vault's lock path, so a seal that lands after a lock fails.
//
// CHARACTERIZATION (Feathers, WELC), and what came of it. This file was written to pin what
// the code did TODAY, including one thing that looked wrong: a failed write told the person
// to treat the pairing as not paired, over a contact that was already pinned in memory and
// was listed as a contact on the very next screen. That pin did its job. The behaviour was
// fixed in its own later commit, the characterization test went RED there, and it was
// rewritten in the same commit into the rule it now states, one assertion at a time, which
// is the whole reason for pinning a suspected defect before touching it.
//
// THE SCAN SCREEN'S OWN CONTROLS ARE ALSO HERE, and not because they are about locking. The
// coverage review wrote them off as unreachable, quoting app-ceremony-wiring.test.ts, whose
// header says plainly that "the scan screen needs a camera, so its cancel button is pinned
// nowhere". That is true of THAT file. It is false of this one: the fake camera above is
// exactly the missing piece, and renderScan's controls are reachable here and nowhere else.
// What was unpinned is the only way off that screen. Delete the one line that wires Stop
// pairing and the app typechecks, every other test stays green, and a person who wants out
// is left on a live camera with no button that does anything.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from '@noble/hashes/utils.js';
import { KeyweaveApp, POLL_INTERVAL_MS } from '../src/ui/app.js';
import { IDLE_LOCK_MS, KeyweaveSession } from '../src/ui/session.js';
import { CAMERA_COPY, lockNotice, REFUSAL_CANCELLED, STEP_COPY } from '../src/ui/copy.js';
import { PairingCeremony } from '../src/ui/ceremony.js';
import { shortHex } from '../src/ui/dom.js';
import { OWN_CARD_SERIAL, PairingSession } from '../src/pairing-session.js';
import { OpticalReceiver, type CardFrameStream } from '../src/optical.js';
import type { OpticalScanner, ScanProgress } from '../src/ui/camera.js';
import { RelayClient } from '../src/relay-client.js';
import { createSignedCard } from '../src/card.js';
import { generateKeyManager } from '../src/keys.js';
import { fromHex, toHex } from '../src/bytes.js';
import { SEED_LEN } from '../src/constants.js';
import { HostileRelay } from './hostile-relay.js';
import type { BlobStore } from '../src/ui/storage.js';
import type { VaultCrypto } from '../src/ui/vault-crypto.js';
import type { VaultData } from '../src/vault.js';

const PASSPHRASE = 'seven unrelated words make a passable line here';
/** Derived, never typed out: the notice and the timer must not be able to drift apart. */
const LOCK_MINUTES = Math.round(IDLE_LOCK_MS / 60_000);
const SEALED = Uint8Array.from([0x01, 0x02, 0x03, 0x04]);
/** Long enough for several display refreshes, short enough to cost nothing. */
const FRAME_BURST_MS = 200;

// Captured before vi.useFakeTimers() replaces the global. The key backend under this runtime
// is WebCrypto, which finishes on the EVENT LOOP rather than on the microtask queue, so a
// promise chain through it needs real macrotasks to settle, and the faked setTimeout would
// never deliver one.
const realSetTimeout = globalThis.setTimeout;

/**
 * Real macrotasks until the app stops changing anything this file can see.
 *
 * Every screen change in app.ts is fire and forget (`void this.beginCeremony(...)` and the
 * rest), so there is nothing for a test to await. A FIXED number of turns is a race: measured
 * on an idle box this file needs three, so the six it was first written with is two turns of
 * margin for a signature on a machine several agents are sharing, and losing that race is a
 * flaky red rather than an honest one. Waiting for quiet has no margin to be wrong about.
 */
async function settle(): Promise<void> {
  let seen = fingerprint();
  let quiet = 0;
  for (let turn = 0; turn < 600; turn++) {
    await new Promise((resolve) => realSetTimeout(resolve, 1));
    const now = fingerprint();
    if (now !== seen) {
      seen = now;
      quiet = 0;
    } else if (++quiet === 8) {
      return;
    }
  }
  throw new Error(`test: the app never went quiet (screen: ${screenText()})`);
}

/**
 * Real macrotasks until a condition holds, or a generous bound is reached.
 *
 * Unlike settle() this NEVER THROWS: whether the thing happened is the assertion's business
 * and not the helper's, so a build that broke the wiring prints the value it actually had
 * instead of a helper's opinion about it. settle() cannot stand in, because the fingerprint
 * it watches for quiet cannot see the live region, and a payload handed over the way the
 * scanner hands it over is fire and forget with nothing to await.
 */
async function settleUntil(ready: () => boolean): Promise<void> {
  for (let turn = 0; turn < 400 && !ready(); turn++) {
    await new Promise((resolve) => realSetTimeout(resolve, 1));
  }
}

/** Everything the assertions can see, cheaply, so "nothing changed" is decidable. */
function fingerprint(): string {
  const screens = document.getElementById('screens');
  return [
    screens?.textContent?.length ?? -1,
    screenText(),
    camera.opened,
    camera.stops,
    painted,
    relay.calls.length,
  ].join('|');
}

// ---- the browser bits happy-dom does not have -----------------------------

/** Flipped off by the one test that needs a browser to refuse a 2d context. */
let canvasContextAvailable = true;
/** QR frames painted. Only the player paints; the capture canvas only ever reads. */
let painted = 0;

function installEnvironment(): void {
  canvasContextAvailable = true;
  painted = 0;
  const canvas = window.HTMLCanvasElement.prototype as unknown as Record<string, unknown>;
  canvas.getContext = (): unknown =>
    canvasContextAvailable
      ? {
          drawImage: () => undefined,
          putImageData: () => {
            painted++;
          },
          getImageData: (_x: number, _y: number, w: number, h: number) => ({
            data: new Uint8ClampedArray(w * h * 4),
            width: w,
            height: h,
          }),
        }
      : null;
  // A headless page delivers no video frames. Accepting the callback and never calling back
  // is what a camera pointed at nothing looks like, and it keeps the capture loop out of the
  // way; the payloads a decode would have produced are handed over directly below.
  const video = window.HTMLVideoElement.prototype as unknown as Record<string, unknown>;
  video.requestVideoFrameCallback = () => 0;
  // The decode pool constructs one Worker per core. Nothing here decodes.
  (globalThis as unknown as Record<string, unknown>).Worker = class FakeWorker {
    onmessage: unknown = null;
    postMessage(): void {}
    terminate(): void {}
  };
}

interface FakeCamera {
  /** getUserMedia calls, so "the track was never stopped" cannot pass as "no track". */
  opened: number;
  /** stop() calls on the video track. THE assertion this file is built around. */
  stops: number;
  /**
   * Set by a test to make the browser refuse. The SEAM IS HERE, in the double, and not in
   * camera.ts: what a refusal costs a person is which sentence renderScan puts on the screen
   * and whether it offers the camera again, and both of those are chosen from the failure's
   * `name` by the shipped code. Handing the shipped code a refusal shaped like a browser's
   * leaves that choice where it is. Cleared by installFakeCamera on every test.
   */
  refuseWith: Error | undefined;
  /**
   * What the track reports back after the scanner asked for its default. Left AT that
   * default, so every other test here sees a camera that did as it was told and the quiet
   * note under the picture stays empty; the one test that wants the note sets it lower.
   */
  frameRate: number;
}

/**
 * A refusal shaped like a browser's. camera.ts reads `.name` and nothing else off these, so
 * the name is the whole payload: NotAllowedError is the person saying no, NotFoundError is a
 * device with no camera at all, and the two must not land on the same screen.
 */
function browserRefusal(name: string): Error {
  const refusal = new Error(`test: the browser answered ${name}`);
  refusal.name = name;
  return refusal;
}

function installFakeCamera(): FakeCamera {
  const camera: FakeCamera = { opened: 0, stops: 0, refuseWith: undefined, frameRate: 30 };
  const track = {
    kind: 'video',
    stop: () => {
      camera.stops++;
    },
    // Read late rather than captured, so a test can set the rate before the app asks.
    getSettings: () => ({ frameRate: camera.frameRate, width: 1280, height: 720 }),
    applyConstraints: async () => undefined,
  };
  // A REAL MediaStream, because HTMLMediaElement.srcObject checks the type of what it is
  // given at runtime and the scanner assigns the stream to the <video>. Its track list is
  // the stand-in, since happy-dom refuses to construct a MediaStreamTrack.
  const stream = new MediaStream();
  Object.assign(stream as unknown as Record<string, unknown>, {
    getTracks: () => [track],
    getVideoTracks: () => [track],
  });
  Object.defineProperty(navigator, 'mediaDevices', {
    configurable: true,
    value: {
      getUserMedia: async () => {
        // Counted BEFORE the refusal, because how many times the browser was asked is itself
        // an assertion: a denial is one prompt, and camera.ts's constraint ladder is three.
        camera.opened++;
        if (camera.refuseWith) throw camera.refuseWith;
        return stream;
      },
    },
  });
  return camera;
}

// ---- the seams the app is constructed with --------------------------------

function freshVault(): VaultData {
  return {
    identitySeed: randomBytes(SEED_LEN),
    encryptionSeed: randomBytes(SEED_LEN),
    contacts: [],
    highWater: [],
    seen: [],
    messages: [],
    mailboxes: [],
  };
}

/**
 * The KDF seam, faked for speed. LocalVaultCrypto is the real one and the rest of the suite
 * drives it; here Argon2id at the shipped parameters would cost seconds per screen.
 *
 * The one behaviour kept exactly is the one a lock rides on: forget() drops the passphrase
 * and a later seal() fails. The check sits BEHIND the gate rather than in front of it because
 * that is where the shipped seam puts it (vault-worker.ts seals across a postMessage), so a
 * lock can land while a seal is in the air. That window is a real one, and it is the window
 * confirmMatch's two branches exist to tell apart.
 */
class FakeVaultCrypto implements VaultCrypto {
  private passphrase: string | undefined;
  /** Set by a test to hold a seal open, so a lock can be fired mid write. */
  sealGate: Promise<void> | undefined;

  constructor(private readonly seed: () => VaultData) {}

  async createIdentity(passphrase: string): Promise<{ blob: Uint8Array; data: VaultData }> {
    this.passphrase = passphrase;
    return { blob: SEALED, data: this.seed() };
  }

  async unlock(_blob: Uint8Array, passphrase: string): Promise<VaultData> {
    this.passphrase = passphrase;
    return this.seed();
  }

  async seal(_data: VaultData): Promise<Uint8Array> {
    if (this.sealGate) await this.sealGate;
    if (this.passphrase === undefined) throw new Error('vault-crypto: locked');
    return SEALED;
  }

  forget(): void {
    this.passphrase = undefined;
  }
}

class FakeBlobStore implements BlobStore {
  /** A store that refuses a write: a private window, or one that is full. */
  failSave: Error | undefined;
  /** Writes that landed, so a refusal promising "nothing was saved" is a count, not a hope. */
  saves = 0;

  constructor(private blob: Uint8Array | null = null) {}

  async load(): Promise<Uint8Array | null> {
    return this.blob;
  }

  async save(blob: Uint8Array): Promise<void> {
    if (this.failSave) throw this.failSave;
    this.saves++;
    this.blob = blob;
  }

  async clear(): Promise<void> {
    this.blob = null;
  }
}

// ---- reading and driving the screens --------------------------------------

function loadShell(): void {
  // happy-dom installs its own URL global, which node's fileURLToPath will not take, so the
  // shell is found the plain way rather than through import.meta.
  const path = join(__dirname, '..', 'index.html');
  const html = readFileSync(path, 'utf8');
  const body = /<body[^>]*>([\s\S]*)<\/body>/.exec(html);
  if (!body) throw new Error(`test: no <body> in ${path}`);
  // The module entry is stripped: it bootstraps the real app, this file constructs
  // KeyweaveApp itself, and happy-dom logs a DOMException for every script it will not fetch.
  document.body.innerHTML = body[1]!.replace(/<script\b[\s\S]*?<\/script>/g, '');
}

function screenText(): string {
  return document.querySelector('#screens h1')?.textContent ?? '';
}

/**
 * The live region, which is OUTSIDE #screens and so out of at()'s reach. It is the only
 * thing a screen reader is told when the page swaps under it, and on the scan screen it is
 * the only place a camera refusal is spoken at all.
 */
function announced(): string {
  return document.getElementById('live')?.textContent ?? '';
}

/** A hook on the screen that is up, by the same data-role app.ts looks it up with. */
function at<T extends HTMLElement>(name: string): T {
  const found = document.querySelector<T>(`#screens [data-role="${name}"]`);
  if (!found) throw new Error(`test: no [data-role="${name}"] on the screen showing`);
  return found;
}

function press(name: string): void {
  at<HTMLButtonElement>(name).click();
}

/**
 * Press a button and wait for the screen it is on to be replaced. Neutral on purpose: it
 * waits for the OLD screen to go, never for the new one to arrive, so which screen answers
 * is still the assertion's business and not the helper's.
 */
async function pressAndLeave(name: string): Promise<void> {
  const from = screenText();
  press(name);
  for (let i = 0; i < 50; i++) {
    await settle();
    if (screenText() !== from) return;
  }
  throw new Error(`test: pressing ${name} never left "${from}"`);
}

function chrome(id: 'steps' | 'tcb'): HTMLElement {
  const element = document.getElementById(id);
  if (!element) throw new Error(`test: no #${id}`);
  return element;
}

interface Harness {
  app: KeyweaveApp;
  store: FakeBlobStore;
  /** Named for what it is rather than `crypto`, which is a global this file also uses. */
  kdf: FakeVaultCrypto;
}

let relay!: HostileRelay;
let camera!: FakeCamera;

/** The app, opened the way a person opens it: passphrase in, submit, ready screen. */
async function boot(existing?: VaultData): Promise<Harness> {
  const store = new FakeBlobStore(existing ? SEALED : null);
  const kdf = new FakeVaultCrypto(() => existing ?? freshVault());
  const api = new RelayClient({
    baseUrl: 'https://relay.test/',
    fetch: relay.fetch,
    timeoutMs: 2_000,
  });
  const app = new KeyweaveApp({ crypto: kdf, store, relay: api });
  await app.start();
  await settle();

  document.querySelector<HTMLInputElement>('#passphrase')!.value = PASSPHRASE;
  document.querySelector<HTMLInputElement>('#passphrase-confirm')!.value = PASSPHRASE;
  await pressAndLeave('submit');
  expect(screenText()).toBe('Pair in person');
  return { app, store, kdf };
}

function sessionAbsent(app: KeyweaveApp): boolean {
  return (app as unknown as { session: KeyweaveSession | undefined }).session === undefined;
}

function ceremonyAbsent(app: KeyweaveApp): boolean {
  return (app as unknown as { ceremony: PairingCeremony | undefined }).ceremony === undefined;
}

function sessionOf(app: KeyweaveApp): KeyweaveSession {
  const session = (app as unknown as { session: KeyweaveSession | undefined }).session;
  if (!session) throw new Error('test: the app has no session');
  return session;
}

/**
 * What the app is showing, read the way the peer's camera reads it. The playlist is private
 * to the app because nothing in the product needs it; standing in for the other device is
 * the one job that does.
 */
function showing(app: KeyweaveApp): readonly CardFrameStream[] {
  const ceremony = (app as unknown as { ceremony: PairingCeremony | undefined }).ceremony;
  if (!ceremony) throw new Error('test: no ceremony in flight');
  return ceremony.view().playlist;
}

/**
 * One decoded payload, handed to the app exactly as the scanner hands it over: the callback
 * app.ts registers is `(payload) => void this.offerPayload(payload)`, and this is the same
 * call with the promise kept, so the test can wait for it instead of guessing.
 */
function scan(app: KeyweaveApp, payload: Uint8Array): Promise<void> {
  return (app as unknown as { offerPayload: (p: Uint8Array) => Promise<void> }).offerPayload(
    payload,
  );
}

/**
 * What app.ts actually handed the scanner it is holding. Returned rather than invoked so the
 * test can say out loud that the callbacks are THERE: nothing decodes in happy-dom, so a
 * callback that was written down but never passed on looks exactly like a quiet camera. Same
 * move scan() makes, one seam earlier.
 *
 * BOTH callbacks are returned on purpose. scan() reaches offerPayload directly, which is the
 * right shortcut for a test about the ceremony and the wrong one for a test about the wiring:
 * driven that way, every payload in this file arrives without the scanner's own callback ever
 * being called, so its body can be emptied with nothing to notice.
 */
interface ScannerOptions {
  onPayload: (payload: Uint8Array) => void;
  onProgress?: (p: ScanProgress) => void;
}

function scannerOptions(app: KeyweaveApp): ScannerOptions {
  const scanner = (app as unknown as { scanner: OpticalScanner | undefined }).scanner;
  if (!scanner) throw new Error('test: no scanner is running');
  return (scanner as unknown as { opts: ScannerOptions }).opts;
}

function readStream(stream: CardFrameStream): Uint8Array {
  const rx = new OpticalReceiver();
  for (let seq = 0; seq < 400; seq++) {
    const status = rx.feed(stream.frame(seq));
    if (status.kind === 'complete') return status.payload;
  }
  throw new Error('test: the stream never completed');
}

/** The other device: a real session, a real ceremony, its own drop box at the relay. */
async function peerDevice(): Promise<{ session: KeyweaveSession; ceremony: PairingCeremony }> {
  const session = await KeyweaveSession.createIdentity(
    new FakeVaultCrypto(freshVault),
    new FakeBlobStore(),
    PASSPHRASE,
    // idleMs 0 leaves no timer behind: the only lock in this file is the app's own.
    { idleMs: 0 },
  );
  const box = relay.mint();
  const coordinate = { id: fromHex(box.mailboxId), writeCap: box.writeCap };
  const pairing = await PairingSession.begin(session.keys(), OWN_CARD_SERIAL, {}, coordinate);
  return {
    session,
    ceremony: PairingCeremony.begin(pairing, session, 'show-first', {
      id: coordinate.id,
      pullToken: box.pullToken,
    }),
  };
}

/**
 * Both cameras, pointed at each other, up to the app's LAST scan: three turns, six payloads,
 * with the app taking the scan-first role so it is holding the camera for most of them.
 */
async function driveToLastScan(
  app: KeyweaveApp,
): Promise<{ peer: { session: KeyweaveSession; ceremony: PairingCeremony }; proof: Uint8Array }> {
  const peer = await peerDevice();
  await pressAndLeave('scan-first');

  // Turn 1: the peer shows its card and its pairing info, and the app reads both.
  for (const stream of peer.ceremony.view().playlist) await scan(app, readStream(stream));
  // Turn 2: the app shows card, info and proof; the peer reads all three.
  peer.ceremony.handOff();
  for (const stream of showing(app)) await peer.ceremony.offer(readStream(stream));
  await pressAndLeave('done');

  // Turn 3: the peer's proof is the last thing the app needs before the words.
  return { peer, proof: readStream(peer.ceremony.view().playlist[0]!) };
}

async function driveToCompare(
  app: KeyweaveApp,
): Promise<{ session: KeyweaveSession; ceremony: PairingCeremony }> {
  const { peer, proof } = await driveToLastScan(app);
  await scan(app, proof);
  expect(screenText()).toBe('Say these six words out loud');
  return peer;
}

/** A vault that has already been through a ceremony: one pinned card, one pair of boxes. */
async function pairedVault(): Promise<{ data: VaultData; peerId: Uint8Array }> {
  const peer = await generateKeyManager('noble');
  const data = freshVault();
  data.contacts = [await createSignedCard(peer.manager, OWN_CARD_SERIAL)];
  const inbox = relay.mint();
  const outbox = relay.mint();
  data.mailboxes = [
    {
      peerId: peer.manager.identityPublicKey(),
      inboxId: fromHex(inbox.mailboxId),
      inboxPullToken: inbox.pullToken,
      outboxId: fromHex(outbox.mailboxId),
      outboxWriteCap: outbox.writeCap,
    },
  ];
  return { data, peerId: peer.manager.identityPublicKey() };
}

beforeEach(() => {
  // The vault arms its idle timer at construction and re-arms it on every access, so the
  // clock has to be fake before the app is built or the lock is five real minutes away.
  vi.useFakeTimers();
  loadShell();
  installEnvironment();
  camera = installFakeCamera();
  relay = new HostileRelay();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('the idle lock, from the scan screen', () => {
  it('releases the camera and puts the unlock screen up', async () => {
    const { app } = await boot();
    await pressAndLeave('scan-first');

    // Positive control: the camera really is open, so "never stopped" cannot pass as
    // "there was no track".
    expect(screenText()).toBe('Point your camera at their screen');
    expect(camera.opened).toBe(1);
    expect(camera.stops).toBe(0);

    vi.advanceTimersByTime(IDLE_LOCK_MS);
    await settle();

    // THE assertion. A camera left running behind a locked screen is what this path exists
    // to prevent, and it is invisible to every rule that reads app.ts as text.
    expect(camera.stops).toBe(1);
    expect(screenText()).toBe('Unlock Keyweave');
    expect(sessionAbsent(app)).toBe(true);
    // Dropping the session and dropping the ceremony are two separate lines in onLock, and
    // the notice on this screen promises the second one in those words: the pairing that was
    // running "has been dropped". A surviving PairingCeremony is the peer's card, the pairing
    // keys and the playlist still in memory behind a screen that says they are gone, and the
    // camera assertion above cannot see it, because teardownOptics is a different line again.
    expect(ceremonyAbsent(app)).toBe(true);
  });

  it('stops the code on screen too, which is the other half of the same teardown', async () => {
    await boot();
    // The show turn: an animated QR on a canvas, a wake lock in a real browser, no camera.
    // teardownOptics stops the player and the scanner in one breath, so a rule that only
    // watches the camera leaves half of it unguarded, and the half it leaves is the one that
    // keeps a device awake repainting a pairing code nobody is looking at.
    await pressAndLeave('show-first');
    expect(screenText()).toBe('Show this to their camera');

    // Positive control: the animation really is running, so a frozen count below means
    // stopped rather than never started.
    const before = painted;
    vi.advanceTimersByTime(FRAME_BURST_MS);
    expect(painted).toBeGreaterThan(before);

    vi.advanceTimersByTime(IDLE_LOCK_MS);
    await settle();
    expect(screenText()).toBe('Unlock Keyweave');

    const frozen = painted;
    vi.advanceTimersByTime(FRAME_BURST_MS);
    expect(painted).toBe(frozen);
  });

  it('says how long it waited, in the words the constant actually enforces', async () => {
    await boot();
    await pressAndLeave('scan-first');
    vi.advanceTimersByTime(IDLE_LOCK_MS);
    await settle();

    // Asserted on the RENDERED string. The old rule called lockNotice(5) itself and never
    // looked at what app.ts passed, so the app could tell somebody three minutes while
    // locking after five. Both sides here come off IDLE_LOCK_MS.
    const notice = at('notice');
    expect(notice.hidden).toBe(false);
    expect(notice.textContent).toBe(lockNotice(LOCK_MINUTES));
    expect(notice.textContent).toContain(`${LOCK_MINUTES} minutes`);
  });

  it('takes the ceremony chrome down with it', async () => {
    await boot();
    await pressAndLeave('scan-first');
    // While the ceremony is up: the turn counter and the banner that names R1.
    expect(chrome('steps').hidden).toBe(false);
    expect(chrome('steps').textContent).toBe('Turn 1 of 3');
    expect(chrome('tcb').hidden).toBe(false);

    vi.advanceTimersByTime(IDLE_LOCK_MS);
    await settle();

    // The unlock screen is not part of a ceremony, and a banner about comparing words above
    // a passphrase box is a claim about a ceremony that is over.
    expect(chrome('steps').hidden).toBe(true);
    expect(chrome('tcb').hidden).toBe(true);
  });
});

describe('the scan screen answers its own controls', () => {
  it('cancels the ceremony and hands the camera back', async () => {
    const { app, store } = await boot();
    await pressAndLeave('scan-first');

    // Two positive controls, both load-bearing. The camera really is open, so a stop that
    // never happens cannot pass as "there was no camera to stop". And the screen really is
    // the SCAN screen, which matters more than it looks: app.ts wires cancel on the show
    // screen and on the scan screen with two byte-identical lines, only one of them was
    // pinned anywhere, and a mutation aimed at the wrong one proves nothing.
    expect(screenText()).toBe(STEP_COPY.scanPeer.heading);
    expect(camera.opened).toBe(1);
    expect(camera.stops).toBe(0);
    // A third, for the two chrome assertions further down: the ceremony's own furniture is
    // up while the ceremony is running, so "taken down" below cannot pass as "never raised".
    expect(chrome('steps').hidden).toBe(false);
    const savesBefore = store.saves;

    // Deliberately not pressAndLeave: that helper reds with its own wording, which would
    // report that a button did nothing without ever printing the screen it was left on.
    press('cancel');
    await settle();

    expect(screenText()).toBe(REFUSAL_CANCELLED.title);
    expect(at('detail').textContent).toBe(REFUSAL_CANCELLED.detail);
    expect(at('advice').textContent).toBe(REFUSAL_CANCELLED.advice);
    // The teardown a dead button skips, and the reason this one is worth a test of its own:
    // Stop pairing is the ONLY way off the scan screen, so a listener that is not there
    // leaves a person on a live camera with no control that answers.
    expect(camera.stops).toBe(1);
    // A refusal nobody is told about is not a refusal. This is the same live region the
    // camera failures further down are read out of, and every refusal in the app is spoken
    // by one shared line: the cancel, the interrupted ceremony, the mismatch. The screen
    // swaps under a screen reader and that line is the whole announcement.
    expect(announced()).toBe(REFUSAL_CANCELLED.title);
    // The ceremony's furniture goes down with the ceremony. A turn counter and a banner
    // about comparing words are claims about a pairing that is running; sitting above a
    // screen that says the pairing stopped they are claims about nothing. The lock path
    // pins this already, and cancelling is the other way a ceremony ends.
    expect(chrome('steps').hidden).toBe(true);
    expect(chrome('tcb').hidden).toBe(true);
    // The advice above, made checkable rather than decorative. Corroboration, honestly: no
    // single edit was found that reds either of these on its own. They are here because a
    // cancel that quietly kept the peer is the failure worth having a reader for if one is
    // ever introduced, and because the screen makes the claim in those words.
    expect(store.saves).toBe(savesBefore);
    expect(sessionOf(app).peers()).toHaveLength(0);
  });

  it('says what it is waiting for before a single frame has arrived', async () => {
    await boot();
    await pressAndLeave('scan-first');

    // The lede slot is EMPTY in index.html, so this pins the assignment rather than the
    // template it is written into.
    expect(at('lede').textContent).toBe(STEP_COPY.scanPeer.lede);
    // Turn 1 waits for two codes, the card and the pairing info, and renderScan takes that
    // count off the ceremony instead of carrying its own. A screen that promises one code
    // and then keeps waiting after one has landed is a screen a person walks away from.
    expect(at('progress').textContent).toBe('0 of 2 codes read.');
    // The resting state of the quiet counter line. On its own it is corroboration and not a
    // wall, because an empty slot is also what a slot nobody ever wrote to looks like; the
    // next test is the one that can tell those two apart.
    expect(at('counters').textContent).toBe('');
    expect(announced()).toBe(`${STEP_COPY.scanPeer.heading}. Turn 1 of 3.`);
  });

  it('counts the codes it has read, and the noise it decided to ignore', async () => {
    const { app } = await boot();
    await pressAndLeave('scan-first');

    // The wiring first, because it is the part that can vanish silently: onProgress is
    // OPTIONAL on the scanner, so a build that never passes it typechecks, and the screen
    // then sits on its opening line for the whole turn while the camera is in fact locking
    // on to codes. Nothing in happy-dom decodes, so this is the only place it shows.
    const onProgress = scannerOptions(app).onProgress;
    expect(onProgress).toBeTypeOf('function');
    onProgress!({ k: 5, solved: 2, malformed: 3, capped: 1, dropped: 0 });

    expect(at('progress').textContent).toBe('0 of 2 codes read. Reading a code: 2 of 5 blocks.');
    // Other people's QR codes in frame are NOISE and say so quietly, while a frame refused
    // by the header caps is the signal those caps exist for. The empty string is the resting
    // state of this slot, so a report with something in it is the only way to tell the
    // assignment from a slot nobody ever wrote to.
    expect(at('counters').textContent).toBe(
      '3 other codes in view, ignored. 1 Keyweave frame refused for being out of bounds',
    );
  });

  it('takes a code through the callback it handed the scanner, and counts it', async () => {
    const { app } = await boot();
    const peer = await peerDevice();
    await pressAndLeave('scan-first');

    // Turn 1 waits for two codes, so the FIRST one leaves the ceremony exactly where it is:
    // the phase does not change, renderScan never runs again, and the only things that move
    // are the live region and the closure holding the progress line. Nothing else in this
    // file visits that window, and three separate lines live in it.
    expect(at('progress').textContent).toBe('0 of 2 codes read.');
    const opening = `${STEP_COPY.scanPeer.heading}. Turn 1 of 3.`;
    expect(announced()).toBe(opening);

    // Handed over through the callback app.ts gave the SCANNER, and not through offerPayload
    // the way scan() does. Every other payload in this file takes that shortcut, so the
    // callback's body can be emptied and every code a person patiently holds up goes on the
    // floor with the file still green. The callback is REQUIRED by the scanner's options, so
    // what a careless edit leaves behind is not a missing field: it is an arrow that runs and
    // does nothing, which typechecks and reads as wired.
    const opts = scannerOptions(app);
    opts.onPayload(readStream(peer.ceremony.view().playlist[0]!));
    await settleUntil(() => announced() !== opening);

    // Still the scan screen: one code of the two is in, so there is nothing to re-render.
    expect(screenText()).toBe(STEP_COPY.scanPeer.heading);
    // The only thing a screen reader is told when a code lands mid turn. Without it the
    // page is silent from the opening line until the whole turn is done, which on a screen
    // whose entire job is to say whether it is working is the difference between holding a
    // code up for another second and giving up on it.
    expect(announced()).toBe('1 of 2 codes read.');
    // And the count on the screen, which renderScan reads off the CEREMONY on every report
    // rather than carrying its own. Before this it was only ever observed at zero, which is
    // also exactly what a hardcoded zero looks like: a screen still promising nothing has
    // arrived while the person is standing there watching it not change.
    opts.onProgress!({ k: 0, solved: 0, malformed: 0, capped: 0, dropped: 0 });
    expect(at('progress').textContent).toBe('1 of 2 codes read.');
  });

  it('says when the camera came up slower than it was asked for', async () => {
    // A camera that will not give the rate the scanner wants: an old webcam, a laptop lid
    // camera, or one another tab already has open.
    camera.frameRate = 15;
    await boot();
    await pressAndLeave('scan-first');

    // The quiet note under the picture, and the only place a person is told why a scan that
    // looks perfectly fine is taking so long. Its slot is empty in index.html AND empty is
    // what the healthy matching-rate case writes into it, so a camera that disagrees with
    // the request is the only way to tell the assignment from a slot nobody ever wrote to:
    // the same trap the counters line above sits in. 30 is the scanner's own default, spelled
    // out rather than imported, because changing it changes what this screen says.
    expect(at('camera-note').textContent).toBe(
      'Asked this camera for 30 frames per second, it is running 15.',
    );
  });

  it('shows the refusal the browser chose, and offers the camera again for a no', async () => {
    camera.refuseWith = browserRefusal('NotAllowedError');
    await boot();
    await pressAndLeave('scan-first');
    await settle();

    const error = at('error');
    expect(error.hidden).toBe(false);
    expect(error.textContent).toBe(CAMERA_COPY.denied);
    // A refusal nobody is told about is not a refusal. The live region is the only channel
    // a screen reader has here: the screen otherwise still looks like a camera coming up.
    expect(announced()).toBe(CAMERA_COPY.denied);
    // A no is answerable, so the one control that can help is offered.
    expect(at('retry').hidden).toBe(false);
    // Last, because it belongs to camera.ts rather than to the screen: one prompt, not the
    // three of the constraint ladder. Somebody who said no is not asked twice more.
    expect(camera.opened).toBe(1);
  });

  it('does not offer the camera again when there is no camera to ask for', async () => {
    camera.refuseWith = browserRefusal('NotFoundError');
    await boot();
    await pressAndLeave('scan-first');
    await settle();

    expect(at('error').hidden).toBe(false);
    expect(at('error').textContent).toBe(CAMERA_COPY.noCamera);
    // THE assertion here, and the one the copy is chosen for: asking again for a camera the
    // device does not have is a button that can only fail, on the screen of somebody who is
    // already stuck. Only a denial has something behind it to change.
    expect(at('retry').hidden).toBe(true);
  });

  it('a retry that works clears the refusal off the screen', async () => {
    camera.refuseWith = browserRefusal('NotAllowedError');
    await boot();
    await pressAndLeave('scan-first');
    await settle();
    expect(at('error').hidden).toBe(false);
    expect(at('retry').hidden).toBe(false);

    // What the person went and did: opened the browser's site settings and allowed it.
    camera.refuseWith = undefined;
    press('retry');
    await settle();

    // Both slots are cleared at the TOP of the attempt, before the camera is asked. Left
    // behind they are a refusal printed under a camera that is now running, over a button
    // offering to ask for a camera the app is already holding.
    expect(at('error').hidden).toBe(true);
    expect(at('retry').hidden).toBe(true);
    expect(camera.opened).toBe(2);
    expect(camera.stops).toBe(0);
  });

  it('a retry never leaves the previous attempt holding the camera', async () => {
    await boot();
    await pressAndLeave('scan-first');
    expect(camera.opened).toBe(1);
    expect(camera.stops).toBe(0);

    // Pressed while the camera IS running, which the screen does not normally offer: the
    // button hides itself the moment an attempt succeeds. The line under test is defensive
    // for that reason, and the press is artificial for that reason, but what it defends
    // against is worth pinning: a second scanner built over a live one leaves the first
    // one's track running with nothing left holding a reference that could stop it, which
    // is a camera light on for the rest of the session.
    press('retry');
    await settle();

    expect(camera.stops).toBe(1);
    expect(camera.opened).toBe(2);
  });

  it('hands the camera back the moment the ceremony leaves the scan screen', async () => {
    const { app } = await boot();
    const peer = await peerDevice();
    await pressAndLeave('scan-first');
    expect(camera.opened).toBe(1);
    expect(camera.stops).toBe(0);

    // Turn 1's two codes, which is what moves the ceremony on to the show turn.
    for (const stream of peer.ceremony.view().playlist) await scan(app, readStream(stream));
    await settle();
    expect(screenText()).toBe(STEP_COPY.showCardAndProof.heading);

    // MEASURED GAP, and the reason this is a test of its own rather than one more line on
    // the turn-3 test below. renderScan's own guard stops a stale scanner the NEXT time a
    // scan screen is built, so anything read on turn 3 cannot tell a teardown that ran on
    // the phase change from one that ran late. Read HERE, on the show screen, nothing hides
    // it: deleting the teardown at the top of renderCeremony leaves this at 0, which is a
    // camera running through the whole show turn, behind a page displaying a code.
    expect(camera.stops).toBe(1);
  });

  it('renders the last turn with its own heading, not the template default', async () => {
    const { app } = await boot();
    await driveToLastScan(app);

    // index.html hardcodes TURN ONE's heading into the scan template, so a title assignment
    // that never runs is invisible on turn 1 and this file would be pinning the shell. Turn
    // 3 is where the two strings differ, and it is the only place the difference shows.
    expect(screenText()).toBe(STEP_COPY.scanProof.heading);
    expect(at('lede').textContent).toBe(STEP_COPY.scanProof.lede);
    expect(at('progress').textContent).toBe('0 of 1 codes read.');
    expect(announced()).toBe(`${STEP_COPY.scanProof.heading}. Turn 3 of 3.`);
    // The turn counter takes its number off the same view. Turn 1 is the only scan screen
    // the rest of this file reads it on, and there the argument and a hardcoded 1 are the
    // same string: this is the one screen in the file where the two can disagree.
    expect(chrome('steps').textContent).toBe('Turn 3 of 3');
    // A fresh camera for the fresh screen, and turn 1's handed back on the way past.
    expect(camera.opened).toBe(2);
    expect(camera.stops).toBe(1);
  });
});

describe('confirming the words tells a lock apart from a failed write', () => {
  it('a lock during the write says the app locked itself', async () => {
    const { app, kdf } = await boot();
    await driveToCompare(app);

    let openGate = (): void => undefined;
    kdf.sealGate = new Promise<void>((resolve) => {
      openGate = resolve;
    });

    // Not pressAndLeave: the point of this one is that the screen does NOT change yet. The
    // write is parked at the gate, which is where a person's session actually sits while a
    // slow storage write is in flight.
    press('match');
    await settle();
    // The seal is in the air and the vault has not been touched since it started, so the
    // idle timer is the next thing to happen. This is the window the guard exists for.
    vi.advanceTimersByTime(IDLE_LOCK_MS);
    openGate();
    await settle();

    // Naming a storage failure here would tell somebody their browser refused to keep a
    // contact when in fact the app emptied its own vault under them.
    expect(screenText()).toBe('Unlock Keyweave');
    expect(at('notice').textContent).toBe(lockNotice(LOCK_MINUTES));
  });

  it('a write that fails says the contact could not be saved, and names the cause', async () => {
    const { app, store } = await boot();
    await driveToCompare(app);
    store.failSave = new Error('the storage quota was exceeded');

    await pressAndLeave('match');

    expect(screenText()).toBe('The contact could not be saved');
    expect(at('detail').textContent).toContain('the storage quota was exceeded');
    expect(at('advice').textContent).toContain('Treat this as not paired');
  });

  it('the write failure says not paired, and the app is not paired: the pin is rolled back', async () => {
    // THIS TEST WAS A CHARACTERIZATION AND IS NOW A RULE, and the edit was the point of
    // pinning it first. What it used to assert, verbatim, was the contradiction: session.ts
    // commit() called contacts.pin(card) BEFORE awaiting persist(), so a failed write left
    // the pin in memory for the rest of the session, the refusal screen said "Treat this as
    // not paired", and its only button led to the ready screen, which then listed them.
    //
    // commit() now takes an image of both stores before it mutates and restores them when
    // the write rejects, so the sentence on the screen is true of the device behind it. The
    // assertions below are the inverse of the ones that were here, one for one.
    const { app, store } = await boot();
    const peer = await driveToCompare(app);
    const peerId = peer.session.identityPublicKey();
    store.failSave = new Error('the storage quota was exceeded');

    await pressAndLeave('match');
    expect(screenText()).toBe('The contact could not be saved');
    // The in-memory store, which is what every later screen is built from.
    expect(sessionOf(app).peers().map(toHex)).not.toContain(toHex(peerId));

    // And the screen the refusal's own button leads to, because that is where a person meets
    // the contradiction rather than in a store.
    await pressAndLeave('again');
    expect(screenText()).toBe('Pair in person');
    expect(at('contacts').hidden).toBe(true);
    expect(at('contact-list').children).toHaveLength(0);
  });

  it('the rollback puts the MAILBOX back too, not only the pin', async () => {
    // commit() writes two things in one call: the pin and the pair of drop boxes. A rollback
    // that undid only the first would leave a mailbox for an identity that is no longer
    // pinned, i.e. a device holding a write capability for a peer it has just been told it
    // did not pair with. Asserted through the vault rather than through a screen, because no
    // screen shows a mailbox.
    //
    // CONTROL FIRST: the same drive with the store working really does leave one, so an
    // empty table below means removed rather than never written.
    const good = await boot();
    const goodPeer = await driveToCompare(good.app);
    await pressAndLeave('match');
    expect(screenText()).toBe('Paired');
    expect(
      sessionOf(good.app).mailboxFor(goodPeer.session.identityPublicKey()),
    ).toBeDefined();

    const { app, store } = await boot();
    const peer = await driveToCompare(app);
    store.failSave = new Error('the storage quota was exceeded');
    await pressAndLeave('match');

    expect(screenText()).toBe('The contact could not be saved');
    expect(sessionOf(app).mailboxFor(peer.session.identityPublicKey())).toBeUndefined();
  });
});

describe('a ceremony that throws', () => {
  it('lands on the interrupted refusal when the vault is open', async () => {
    const { app } = await boot();
    // A browser that will not hand out a 2d context: an extension that blocks canvas, or a
    // tab under memory pressure. The QR player cannot start, and it throws from inside the
    // ceremony's own call stack, which is what failCeremony is there to catch.
    canvasContextAvailable = false;
    await pressAndLeave('show-first');

    expect(screenText()).toBe('Stopped: the pairing could not continue');
    expect(at('detail').textContent).toContain('qr-display: no 2d context');
    expect(at('advice').textContent).toContain('the camera has been released');
    expect(sessionAbsent(app)).toBe(false);
  });

  it('lands on the lock notice when the throw was the lock', async () => {
    const { app } = await boot();
    const { proof } = await driveToLastScan(app);

    // The last payload is in and the ceremony is signing when the idle timer fires. A
    // destroyed key manager throws into exactly the same catch a broken pairing would, so
    // the only thing that tells the two apart is the guard at the top of failCeremony.
    const pending = scan(app, proof);
    vi.advanceTimersByTime(IDLE_LOCK_MS);
    await pending;
    await settle();

    expect(screenText()).toBe('Unlock Keyweave');
    expect(at('notice').textContent).toBe(lockNotice(LOCK_MINUTES));
    expect(camera.stops).toBeGreaterThan(0);
  });

  it('answers Start over with the notice when the vault went while the refusal was up', async () => {
    const { app } = await boot();
    canvasContextAvailable = false;
    await pressAndLeave('show-first');
    expect(screenText()).toBe('Stopped: the pairing could not continue');

    // Held while the refusal is still on screen, because the lock below replaces the screen
    // and a replaced node keeps its listener. That listener is the case renderReady's own
    // lock check exists for: beginCeremony calls requireSession() inside a try and turns a
    // throw into a refusal, but a refusal's Start over hands renderReady straight to a plain
    // click handler with nothing catching anything behind it.
    const again = at<HTMLButtonElement>('again');

    // Positive control: the vault really is gone before the press, so what is measured below
    // is the guard and not a press that happened to land on an open session.
    vi.advanceTimersByTime(IDLE_LOCK_MS);
    await settle();
    expect(screenText()).toBe('Unlock Keyweave');
    expect(sessionAbsent(app)).toBe(true);
    const noticeFromTheTimer = at('notice');

    let uncaught: unknown;
    try {
      again.click();
    } catch (error) {
      uncaught = error;
    }
    await settle();

    // In a browser a throw out of that handler is a console line nobody sees and a button
    // that does nothing. happy-dom hands it back to whoever dispatched the click, which is
    // the only reason this file can say the word out loud instead of inferring it.
    expect(uncaught).toBeUndefined();
    // The other half, and the one a browser would show: the press has to be ANSWERED. A dead
    // button leaves the screen the timer rendered sitting there untouched, which reads as the
    // right screen, so what is pinned is a FRESH notice rather than that one, still carrying
    // the words the lock owes. Answering with a bare unlock screen is not an answer either.
    expect(at('notice')).not.toBe(noticeFromTheTimer);
    expect(at('notice').textContent).toBe(lockNotice(LOCK_MINUTES));
  });
});

describe('the conversation poll', () => {
  it('stops when the screen changes', async () => {
    const { data, peerId } = await pairedVault();
    await boot(data);
    expect(at('label').textContent).toBe(`Identity ${shortHex(toHex(peerId))}`);

    await pressAndLeave('open');
    expect(screenText()).toBe('Conversation');
    const afterOpening = relay.calls.length;
    expect(afterOpening).toBeGreaterThan(0);

    // POSITIVE CONTROL: while the conversation is up the interval really does reach the
    // relay. Without this the assertion below would pass on a poll that never started.
    vi.advanceTimersByTime(POLL_INTERVAL_MS);
    await settle();
    expect(relay.calls.length).toBeGreaterThan(afterOpening);

    await pressAndLeave('back');
    expect(screenText()).toBe('Pair in person');
    const afterLeaving = relay.calls.length;

    // The interval is cleared by the one function every screen change goes through, so the
    // lock path and the refusal path get it for free. Left running it is a mailbox this
    // device keeps asking for on a screen that is not showing it: traffic the relay sees
    // and the person does not.
    vi.advanceTimersByTime(POLL_INTERVAL_MS * 3);
    await settle();
    expect(relay.calls.length).toBe(afterLeaving);
  });
});
