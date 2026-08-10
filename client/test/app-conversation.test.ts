// @vitest-environment happy-dom
//
// The conversation ORCHESTRATION, executed against the real screens.
//
// Three rules in renderConversation were, until this file existed, justified by reading the
// code rather than by running it: the reentrancy latch that stops two relay passes from
// overlapping, the composer being disabled for the WHOLE of a sync, and the interaction
// between the 20 second poll and the vault's idle re-lock. None of the three is decidable
// from a regex over app.ts, because each one is about what happens over TIME: a latch that
// is present in the source and inverted, and a latch that is absent, read identically to a
// text gate and behave in opposite ways.
//
// legacy: this began as a CHARACTERIZATION suite, pinning what the code did TODAY, and one
// of the behaviours below arrived as a suspected defect: the poll rearms the idle lock, so a
// conversation left open does not idle-lock. It has since been ACCEPTED rather than fixed,
// on grounds that are written down (docs/NAMED-RESIDUALS.md R17, resting on R5 and the
// threat model's out-of-scope row for a live unlocked device), so its title now says DECIDED
// EXCEPTION rather than CHARACTERIZATION and its comment carries the grounds. It keeps its
// negative control, which is what stops a pinned decision from decaying into a test that
// would pass on a vault whose idle timer was never armed at all.
//
// WHAT STANDS IN FOR PRODUCTION, and what does not. The screens, the templates, the session,
// the vault, the contact store and Messaging are all real. Two things are fixtures: the
// Argon2id pass (256 MiB, measured at about 3 seconds per call, and this file makes many
// sessions) and the relay transport. The relay is a stand-in rather than the real
// RelayClient over a fake fetch because the questions here are about WHEN a pass resolves,
// and a real client puts a Response body and its own deadline timer between the test and
// that moment.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { KeyweaveApp, POLL_INTERVAL_MS, describeMessagingFailure } from '../src/ui/app.js';
import { CONVERSATION_COPY, relayFailureMessage, syncSummary } from '../src/ui/copy.js';
import { MAX_BODY_BYTES, MessagingError } from '../src/messaging.js';
import { RelayError } from '../src/relay-client.js';
import { IDLE_LOCK_MS } from '../src/ui/session.js';
import { MemoryBlobStore } from '../src/ui/storage.js';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard } from '../src/card.js';
import type { BlobSummary, RelayClient } from '../src/relay-client.js';
import type { MailboxPairing, VaultData } from '../src/vault.js';
import type { VaultCrypto } from '../src/ui/vault-crypto.js';

const PASSPHRASE = 'seven unrelated words make a passable line here';

/**
 * The real templates, from the real index.html. Every screen the app renders is cloned out
 * of the document, so a stub written here would test a fixture instead of the shipped
 * markup, and a renamed data-role would go unnoticed by exactly the tests that exist to
 * catch it.
 */
function loadShell(): void {
  const html = readFileSync(join(__dirname, '..', 'index.html'), 'utf8');
  const body = /<body[^>]*>([\s\S]*)<\/body>/.exec(html);
  if (!body) throw new Error('no <body> in index.html');
  document.body.innerHTML = body[1]!;
}

/**
 * Every promise chain that is not waiting on a timer, run to the end. Nothing in these
 * fixtures touches the network or the KDF, so turns of the microtask queue are the whole of
 * it, and this works unchanged under fake timers (vitest fakes timers, not microtasks).
 */
async function settle(): Promise<void> {
  for (let turn = 0; turn < 24; turn++) await Promise.resolve();
}

/**
 * The same, plus the macrotask queue. Needed once per test, at unlock: keys.ts probes
 * WebCrypto for Ed25519 and X25519 support, and a WebCrypto promise is resolved by the
 * event loop rather than by a microtask. Only ever called while the real timers are
 * installed.
 */
async function drain(): Promise<void> {
  for (let turn = 0; turn < 8; turn++) await new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * The same again, for a fake clock. Sending seals a message, and a signature is one more
 * WebCrypto promise, so a send needs the event loop even though it waits on no timer.
 * advanceTimersByTimeAsync(0) is what reaches it: it yields to the REAL event loop between
 * the (zero) fake timers it runs, which is the only reason a signature can complete while
 * the clock this test is driving does not move.
 */
async function drainFakeClock(): Promise<void> {
  for (let turn = 0; turn < 8; turn++) await vi.advanceTimersByTimeAsync(0);
  await settle();
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** What the relay hands back for a message it took. */
const ACCEPTED: BlobSummary = { blobId: 'bl-20260809T120000Z.000000000000', size: 0 };

/**
 * A relay whose answers arrive when this test says so.
 *
 * `holdLists` is the whole point: a sync that is in flight is not observable from a report
 * or from an elapsed time, only from the window in which it has started and not finished,
 * and the reentrancy latch and the disabled composer are both statements about that window.
 */
class FixtureRelay {
  listCalls = 0;
  pullCalls = 0;
  putCalls = 0;
  /** Read by the Messaging constructor to cap its own pull floor. */
  readonly requestCeilingMs = 15_000;
  /** While true, a list resolves only when releaseLists() is called. */
  holdLists = false;
  /** What a list answers with once it does answer. */
  listing: readonly BlobSummary[] = [];
  /** What a pull of a listed id answers with. A RelayError here is THROWN, as the client does. */
  pullAnswer: (blobId: string) => Uint8Array | null | RelayError = () => null;
  /** Set to refuse every put, the way a relay refuses one: by throwing at the client. */
  putFailure: RelayError | undefined = undefined;
  /** While true, a put resolves only when releasePuts() is called. */
  holdPuts = false;

  private readonly heldLists: Array<Deferred<BlobSummary[]>> = [];
  private readonly heldPuts: Array<Deferred<BlobSummary>> = [];

  async listBlobs(): Promise<BlobSummary[]> {
    this.listCalls++;
    if (!this.holdLists) return [...this.listing];
    const held = deferred<BlobSummary[]>();
    this.heldLists.push(held);
    return held.promise;
  }

  releaseLists(): void {
    for (const held of this.heldLists.splice(0)) held.resolve([...this.listing]);
  }

  async pullBlob(_mailboxId: string, blobId: string): Promise<Uint8Array | null> {
    this.pullCalls++;
    const answer = this.pullAnswer(blobId);
    if (answer instanceof RelayError) throw answer;
    return answer;
  }

  async putBlob(): Promise<BlobSummary> {
    this.putCalls++;
    if (this.putFailure) throw this.putFailure;
    if (!this.holdPuts) return ACCEPTED;
    const held = deferred<BlobSummary>();
    this.heldPuts.push(held);
    return held.promise;
  }

  releasePuts(): void {
    for (const held of this.heldPuts.splice(0)) held.resolve(ACCEPTED);
  }
}

/**
 * The app takes a RelayClient, a class with private fields, so a structural stand-in cannot
 * be assigned to it without a cast. The cast lives here once, named, rather than at each
 * call site.
 */
const asRelay = (fixture: FixtureRelay): RelayClient => fixture as unknown as RelayClient;

/**
 * Argon2id, replaced by nothing at all.
 *
 * This is a VaultCrypto in the same sense LocalVaultCrypto is: it hands the session a
 * VaultData and holds the passphrase until forget() drops it. What it does not do is spend
 * three seconds per call deriving a wrapping key, and what it can do that the real one
 * cannot is hand back a vault that already has a contact pinned, which is how these tests
 * reach a conversation screen without driving an optical ceremony first.
 */
class FixtureCrypto implements VaultCrypto {
  private open = false;

  constructor(private readonly data: VaultData) {}

  async createIdentity(): Promise<{ blob: Uint8Array; data: VaultData }> {
    this.open = true;
    return { blob: Uint8Array.from([0xfa, 0xce]), data: this.data };
  }

  async unlock(): Promise<VaultData> {
    this.open = true;
    return this.data;
  }

  async seal(): Promise<Uint8Array> {
    // Same refusal as the real one, so a persist attempted after the vault locked itself
    // fails here rather than quietly writing with a passphrase nobody is holding.
    if (!this.open) throw new Error('vault-crypto: locked');
    return Uint8Array.from([0xfa, 0xce]);
  }

  forget(): void {
    this.open = false;
  }
}

interface Fixture {
  data: VaultData;
  peerId: Uint8Array;
}

/**
 * A vault with one identity and one pinned contact, and optionally the pair of drop boxes
 * that make that contact messageable. The card is a real signed card from a real key
 * manager, because the session re-imports every stored card through the strict validator on
 * the way back in and would refuse anything less.
 */
async function fixtureVault(opts: { mailbox: boolean }): Promise<Fixture> {
  const own = await generateKeyManager('noble');
  const peer = await generateKeyManager('noble');
  const peerId = peer.manager.identityPublicKey();
  const mailbox: MailboxPairing = {
    peerId,
    inboxId: new Uint8Array(16).fill(0xa1),
    inboxPullToken: 'pull-token-aaaaaaaaaaaa',
    outboxId: new Uint8Array(16).fill(0xb2),
    outboxWriteCap: 'write-cap-bbbbbbbbbbbbb',
  };
  return {
    peerId,
    data: {
      identitySeed: own.identitySeed,
      encryptionSeed: own.encryptionSeed,
      contacts: [await createSignedCard(peer.manager, 1)],
      highWater: [],
      seen: [],
      messages: [],
      mailboxes: opts.mailbox ? [mailbox] : [],
    },
  };
}

const find = <T extends HTMLElement>(selector: string): T =>
  document.querySelector<T>(selector) as T;

/** Start the app on the fixture vault and get as far as the ready screen. */
async function bootstrap(fixture: Fixture, relay: FixtureRelay): Promise<KeyweaveApp> {
  loadShell();
  const app = new KeyweaveApp({
    crypto: new FixtureCrypto(fixture.data),
    store: new MemoryBlobStore(),
    relay: asRelay(relay),
  });
  await app.start();
  // The store is empty, so this is the first-run screen and the fixture vault is what
  // createIdentity hands back.
  find<HTMLInputElement>('#passphrase').value = PASSPHRASE;
  find<HTMLInputElement>('#passphrase-confirm').value = PASSPHRASE;
  find<HTMLFormElement>('[data-role="form"]').dispatchEvent(
    new Event('submit', { bubbles: true, cancelable: true }),
  );
  await drain();
  return app;
}

/** Click the one contact on the ready screen, which is the only way into a conversation. */
function openContact(): void {
  find<HTMLButtonElement>('[data-role="contact-list"] [data-role="open"]').click();
}

/**
 * Type a message and press send, and hand back the composer so a test can see what the
 * handler left in it.
 *
 * The submit EVENT is what the app listens for, so that is what this fires. Clicking the
 * button would be the more faithful gesture but it is not available to every test here: the
 * composer is disabled for the whole of a sync, and a disabled button fires no click at all,
 * which is how an earlier test in this file passed with the rule it was written for deleted.
 */
function compose(text: string): HTMLTextAreaElement {
  const input = find<HTMLTextAreaElement>('#message-body');
  input.value = text;
  find<HTMLFormElement>('[data-role="form"]').dispatchEvent(
    new Event('submit', { bubbles: true, cancelable: true }),
  );
  return input;
}

const sendButton = () => find<HTMLButtonElement>('[data-role="send"]');
const refreshButton = () => find<HTMLButtonElement>('[data-role="refresh"]');
const statusLine = () => find<HTMLElement>('[data-role="status"]');
const errorLine = () => find<HTMLElement>('[data-role="error"]');
const liveRegion = () => find<HTMLElement>('#live');

afterEach(() => {
  vi.useRealTimers();
});

describe('one sync at a time, because both ends of it mutate the vault', () => {
  it('a poll that fires while a sync is in flight is DROPPED, not queued', async () => {
    // The latch is `if (busy) return`, and what it protects is not the screen: the poll and
    // the two buttons all reach flush() and receive(), both of which mutate the message
    // array and persist it, so two overlapping passes are two writers on one vault.
    //
    // DRIVEN BY THE POLL, and the first draft of this test drove it by clicking refresh
    // instead, which was worthless: the composer is disabled for the whole of a sync, and a
    // disabled button does not fire a click at all, so that test passed with the latch
    // DELETED. It was measuring the disabled attribute. The interval has no such gate, it
    // fires on a timer whatever the buttons look like, and it is the reentrancy the comment
    // in app.ts is actually about.
    const relay = new FixtureRelay();
    relay.holdLists = true;
    await bootstrap(await fixtureVault({ mailbox: true }), relay);
    vi.useFakeTimers();

    openContact();
    await settle();
    // The screen opens with a sync of its own, and it is still waiting on the list.
    expect(relay.listCalls).toBe(1);

    // Three ticks land inside the window where the first pass has not answered.
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS * 3);
    expect(relay.listCalls).toBe(1);

    // Dropped rather than deferred: finishing the first pass releases no backlog.
    relay.holdLists = false;
    relay.releaseLists();
    await settle();
    expect(relay.listCalls).toBe(1);

    // CONTROL, and the test is worth nothing without it: the interval really is running, so
    // the three ticks above were refused by the latch rather than never delivered.
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    expect(relay.listCalls).toBe(2);
  });

  it('the composer is disabled for the WHOLE of a sync', async () => {
    // Not for the moment the button was pressed. A sync is flush and then receive, and
    // messaging.ts budgets both halves specifically because this screen holds the composer
    // for the sum of them, so a relay that stalls decides when a person may write.
    const relay = new FixtureRelay();
    relay.holdLists = true;
    await bootstrap(await fixtureVault({ mailbox: true }), relay);

    openContact();
    await settle();

    expect(relay.listCalls).toBe(1); // the pass really is in flight
    expect(sendButton().disabled).toBe(true);
    expect(refreshButton().disabled).toBe(true);
  });

  it('the composer is enabled again once the sync resolves', async () => {
    const relay = new FixtureRelay();
    relay.holdLists = true;
    await bootstrap(await fixtureVault({ mailbox: true }), relay);

    openContact();
    await settle();
    expect(sendButton().disabled).toBe(true);

    relay.releaseLists();
    await settle();
    expect(sendButton().disabled).toBe(false);
    expect(refreshButton().disabled).toBe(false);
  });

  it('a pass that ended because the VAULT LOCKED hands the composer back to nobody', async () => {
    // The third way a pass can end, and the only one with a security meaning. run() keeps a
    // `locked` flag for it, and what the flag guards is the whole of the finally: the two
    // buttons, and the repaint that would otherwise read a vault with no keys in it.
    //
    // DRIVEN BY A SEND, which is not an arbitrary choice of button. run()'s catch is reached
    // only when work() itself throws, and a pass need not throw: receive() catches its own
    // transport failures into the report, so a refresh with nothing to hand over and nothing
    // left to collect RESOLVES even when the lock landed in the middle of it. A send always
    // ends in a write, because flush() persists once the relay has taken the bytes, so it is
    // the path that meets a locked vault at an await with no catch of its own. The refresh
    // path under the same lock is the test after this one.
    const relay = new FixtureRelay();
    relay.holdPuts = true;
    await bootstrap(await fixtureVault({ mailbox: true }), relay);
    vi.useFakeTimers();

    openContact();
    await settle();
    const send = sendButton();
    const refresh = refreshButton();

    compose('this one is with the relay when the timer fires');
    await drainFakeClock();
    expect(relay.putCalls).toBe(1); // in flight, and holding the last read of the vault
    expect(send.disabled).toBe(true);

    // The idle lock can only fire here because nothing touches the vault while the put is
    // held: every poll tick in this window finds run() busy and returns without reading
    // anything, so the timer that a read would rearm is left alone. That is the suspended
    // machine, in a form a test can drive.
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS + 1);
    expect(document.querySelector('#passphrase')).not.toBeNull();

    relay.releasePuts();
    await drainFakeClock();

    // Both still disabled, on a screen that is no longer shown. Handing them back would put
    // a live composer on a detached screen whose keys are gone, and the next press would
    // throw out of a click handler instead of saying what happened.
    expect(send.disabled).toBe(true);
    expect(refresh.disabled).toBe(true);
  });

  it('a REFRESH that ended because the VAULT LOCKED hands them back to nobody either', async () => {
    // THE PATH THIS FILE USED TO FILE RATHER THAN PIN, and the reason it could not be pinned
    // was the defect, not the fixture: a lock landing while the LIST was held used to leave
    // messaging.sync RESOLVING, because receive() swallowed the vault's own error into
    // `unopenable` and returned a report. run()'s catch never fired, its `locked` flag stayed
    // false, and the finally called paint() into an emptied vault. Measured on this source
    // before the fix, and this is the observed text, not a prediction:
    //
    //   Unhandled Rejection: Error: vault: locked
    //     at Vault.assertUnlocked (src/vault.ts:524) <- Messaging.conversation <- paint
    //     <- run (src/ui/app.ts)
    //
    // THAT REJECTION NEEDS NO ASSERTION OF ITS OWN, and this comment is here so nobody later
    // tidies away a test that appears to assert nothing about it: vitest 4 fails the whole
    // RUN on an unhandled rejection (`dangerouslyIgnoreUnhandledErrors` defaults false), so
    // a regression that brings it back turns this file red with an Errors line even if every
    // expect below still passes. That is how it was observed at all.
    const relay = new FixtureRelay();
    relay.holdLists = true;
    await bootstrap(await fixtureVault({ mailbox: true }), relay);
    vi.useFakeTimers();

    openContact();
    await settle();
    const send = sendButton();
    const refresh = refreshButton();

    // CONTROLS FIRST, because without them the whole test is vacuous: a sync that never
    // started and a lock that never landed would satisfy every assertion at the end.
    expect(relay.listCalls).toBe(1); // the opening sync really is in flight
    expect(send.disabled).toBe(true); // and it is holding the composer

    // Nothing touches the vault while the list is held (the poll ticks find run() busy and
    // return without reading anything), so the idle timer is free to fire.
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS + 1);
    expect(document.querySelector('#passphrase')).not.toBeNull(); // the lock landed mid sync

    relay.holdLists = false;
    relay.releaseLists();
    await settle();

    // The lock screen is intact: the pass that resolved afterwards did not repaint over it,
    // did not re-hide it, and did not replace the notice with a conversation.
    expect(document.querySelector('#passphrase')).not.toBeNull();
    expect(document.querySelector('[data-role="thread"]')).toBeNull();
    expect(liveRegion().textContent).toBe('Keyweave locked itself.');

    // On the CAPTURED DETACHED elements, which is the only place the difference shows: the
    // screen they belong to has already been replaced, so re-enabling them is invisible by
    // eye and is exactly what the finally used to do.
    expect(send.disabled).toBe(true);
    expect(refresh.disabled).toBe(true);
  });
});

describe('what a refresh says it did comes from the copy module', () => {
  /**
   * A relay that lists two ids and then refuses the first pull with a 429.
   *
   * Chosen because it drives syncSummary through three of its four branches at once: the
   * count, the shortfall (`unread`), and a named relay failure that is NOT the interrupted
   * one, so the reassuring timeout line is not suppressed. A fixture that produced only
   * "0 new messages." would be satisfied by almost any re-implementation.
   */
  function refusingRelay(): { relay: FixtureRelay; expected: string } {
    const relay = new FixtureRelay();
    relay.listing = [
      { blobId: 'bl-20260809T120000Z.aaaaaaaaaaaa', size: 120 },
      { blobId: 'bl-20260809T120001Z.bbbbbbbbbbbb', size: 120 },
    ];
    // A status the relay CHOSE, which messaging.ts decides was not an interrupted pull: the
    // shipped relay refuses in _authz, before anything is deleted.
    relay.pullAnswer = () => new RelayError('rate-limited', 'relay: refused', 429);
    const expected = syncSummary({
      flush: { relayed: 0, queued: 0, stuck: 0, failure: undefined },
      receive: {
        listed: 2,
        accepted: 0,
        vanished: 0,
        unopenable: 0,
        duplicate: 0,
        stale: 0,
        defective: 0,
        unread: 1,
        interrupted: 0,
        failure: new RelayError('rate-limited', 'relay: refused', 429),
      },
    });
    return { relay, expected };
  }

  it('the opening sync prints syncSummary of its own report, exactly', async () => {
    const { relay, expected } = refusingRelay();
    await bootstrap(await fixtureVault({ mailbox: true }), relay);

    openContact();
    await settle();

    expect(statusLine().textContent).toBe(expected);
    // The fixture really did reach the branches it was built for, rather than passing on a
    // string both sides shortened to the same thing.
    expect(expected).toContain('1 still waiting at the relay');
    expect(expected).toContain(relayFailureMessage('rate-limited'));
    // AND THE SENTENCE ITSELF, written out. The assertion above is not a wall on its own:
    // `expected` is built by calling syncSummary, so an edit INSIDE syncSummary moves both
    // sides of it equally and it stays green while the screen changes. A singular arm swapped
    // with its plural, or the '. ' between the counts turned into a space, are both invisible
    // to it and both visible here. This is the line a person reads.
    expect(statusLine().textContent).toContain('0 new messages. 1 still waiting at the relay.');
  });

  it('a refresh prints syncSummary of its own report, exactly', async () => {
    const { relay, expected } = refusingRelay();
    await bootstrap(await fixtureVault({ mailbox: true }), relay);

    // Open on an empty mailbox, so the opening sync leaves a DIFFERENT line behind and the
    // assertion below is about the refresh handler rather than about what was already there.
    const listing = relay.listing;
    relay.listing = [];
    openContact();
    await settle();
    const opening = statusLine().textContent;
    expect(opening).toBe(
      syncSummary({
        flush: { relayed: 0, queued: 0, stuck: 0, failure: undefined },
        receive: {
          listed: 0,
          accepted: 0,
          vanished: 0,
          unopenable: 0,
          duplicate: 0,
          stale: 0,
          defective: 0,
          unread: 0,
          interrupted: 0,
          failure: undefined,
        },
      }),
    );

    relay.listing = listing;
    refreshButton().click();
    await settle();

    expect(statusLine().textContent).toBe(expected);
    expect(statusLine().textContent).not.toBe(opening);
    // Same two literals the opening test carries, and for the same reason: every comparison
    // above this line is against a string this test computed, so the refresh handler could
    // print a summary with its counts run together, or with the relay's own refusal dropped
    // from the end, and nothing above would move. The counts, the stop between them and the
    // failure sentence are pinned to copy.ts here rather than to syncSummary's own output.
    expect(statusLine().textContent).toContain('0 new messages. 1 still waiting at the relay.');
    expect(statusLine().textContent).toContain('The relay is rate limiting this device.');
  });
});

describe('what a SEND says it did, and the one thing it may never say', () => {
  // The delivery distinction, executed. copy.ts states the rule and the fineprint on the
  // screen explains it to the person reading it, but the choice between the two sentences is
  // made here, in the submit handler, from `report.failure`. Getting that ternary the wrong
  // way round is a one-character edit that no reading of copy.ts would catch, and it is the
  // send-path twin of swapping the two verdict buttons: the screen would tell somebody the
  // relay has their message at the moment it is sitting on their own device.

  it('a send the relay took says the relay took it, and empties the composer', async () => {
    const relay = new FixtureRelay();
    await bootstrap(await fixtureVault({ mailbox: true }), relay);

    openContact();
    await settle();

    const input = compose('the ferry leaves at six');
    await drain();

    expect(relay.putCalls).toBe(1);
    expect(statusLine().textContent).toBe(CONVERSATION_COPY.relayed);
    // Emptied by the HANDLER, and only after send() resolved. The submit is prevented, so
    // nothing else resets this field, and a message still sitting in the box after it went
    // is one a person sends twice.
    expect(input.value).toBe('');
  });

  it('a send the relay REFUSED says queued, and never says the relay took it', async () => {
    // The put is refused the way a relay refuses one, before it has taken anything: the
    // message is sealed, written to the vault and still on this device.
    const relay = new FixtureRelay();
    relay.putFailure = new RelayError('rate-limited', 'relay: refused', 429);
    await bootstrap(await fixtureVault({ mailbox: true }), relay);

    openContact();
    await settle();

    compose('this one is still here');
    await drain();

    expect(relay.putCalls).toBe(1); // control: the relay really was offered the message

    // THE RULE, first and on its own. The test above shows this same screen saying this
    // exact sentence a moment earlier, so this is a statement about which of the two a
    // refused put produces, not about a string that never appears anywhere.
    expect(statusLine().textContent).not.toContain(CONVERSATION_COPY.relayed);
    // The whole line, which is also where the relay's own reason for refusing gets said: a
    // status that says only "queued" leaves the person with no idea whether to wait.
    expect(statusLine().textContent).toBe(
      `${CONVERSATION_COPY.queued}. ${relayFailureMessage('rate-limited')}`,
    );
    // And the wording itself, because every assertion above moves with copy.ts: a `queued`
    // constant reworded into something that reads like an acknowledgement would satisfy all
    // of them and still tell somebody their message went.
    expect(statusLine().textContent).toContain('Queued on this device');
  });
});

describe('the poll is the only background work in the app', () => {
  /**
   * Fake timers are installed AFTER the unlock and BEFORE the conversation opens, which is
   * the window in which both timers under test are armed: renderConversation's interval, and
   * the vault's idle re-lock, which is re-armed on every unlocked read. Unlock itself stays
   * on the real clock because the WebCrypto probe resolves on the event loop, not on a timer.
   */
  async function openUnderFakeClock(relay: FixtureRelay): Promise<void> {
    await bootstrap(await fixtureVault({ mailbox: true }), relay);
    vi.useFakeTimers();
    openContact();
    await settle();
  }

  it('one poll interval triggers exactly one more sync, and anything short of it triggers none', async () => {
    const relay = new FixtureRelay();
    await openUnderFakeClock(relay);
    expect(relay.listCalls).toBe(1); // the opening sync, not the poll

    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS - 1);
    expect(relay.listCalls).toBe(1);

    await vi.advanceTimersByTimeAsync(1);
    expect(relay.listCalls).toBe(2);

    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    expect(relay.listCalls).toBe(3);
  });

  it('DECIDED EXCEPTION (residual R17): the 20 second poll rearms the 5 minute idle lock, so an open conversation does not idle-lock', async () => {
    // A PINNED DECISION, not a pinned defect, and the difference is the whole point of this
    // comment. It arrived as an accident and it is kept on purpose; declaring it is what
    // turns one into the other, and docs/NAMED-RESIDUALS.md R17 is where it is declared.
    //
    // THE MECHANISM, which is not obvious from any one file: the poll calls messaging.sync,
    // sync calls flush, flush calls require(), require() reads the mailbox out of the vault,
    // and every unlocked read goes through Vault.assertUnlocked(), which calls touch().
    // Twenty seconds is shorter than five minutes, so the timer is reset before it can ever
    // fire while a conversation screen is open.
    //
    // WHY IT IS ACCEPTED RATHER THAN FIXED. The threat the idle lock answers on this screen
    // is a live unlocked session on a device somebody else has, and that is out of scope by
    // name: docs/THREAT-MODEL.md rules "steal an unlocked / live-session device" out, and
    // NAMED-RESIDUALS R5 says the same. No published claim is falsified by it. The half of
    // the idle lock that IS load bearing here is the camera release, and that one is
    // verified working on hardware (R15) and is not on this screen at all, because
    // renderConversation tears the optics down before it renders.
    //
    // WHAT WOULD REOPEN IT, stated so a later reader has a test rather than an opinion: any
    // claim that Keyweave locks itself after a period of inactivity regardless of screen, or
    // a change that puts key material on this screen which the camera-release argument does
    // not cover. Either one makes the sentence in copy.ts false again, and copy.ts is where
    // it was corrected: the notice no longer says "with nothing happening".
    const relay = new FixtureRelay();
    await openUnderFakeClock(relay);

    // Twenty poll intervals is four hundred seconds, well past the five minute lock.
    for (let tick = 0; tick < 20; tick++) await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    expect(POLL_INTERVAL_MS * 20).toBeGreaterThan(IDLE_LOCK_MS);

    // Still the conversation, and the lock never announced itself.
    expect(document.querySelector('[data-role="thread"]')).not.toBeNull();
    expect(document.querySelector('#passphrase')).toBeNull();
    expect(liveRegion().textContent).not.toBe('Keyweave locked itself.');

    // NEGATIVE CONTROL, on the same app and the same clock. show() stops the poll on every
    // screen change, so the ready screen is the same session with nothing touching the vault,
    // and there the idle lock does exactly what it is supposed to do. Without this half the
    // test above would also pass on a vault whose idle timer was never armed at all.
    find<HTMLButtonElement>('[data-role="back"]').click();
    await settle();
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS + POLL_INTERVAL_MS);

    expect(document.querySelector('#passphrase')).not.toBeNull();
    expect(liveRegion().textContent).toBe('Keyweave locked itself.');
  });
});

describe('describeMessagingFailure, called rather than read', () => {
  it('a RelayError becomes the relay copy for its own failure code', () => {
    // PINNED EVEN THOUGH THE CONVERSATION SCREEN MAY NEVER REACH IT. flush() and receive()
    // catch every transport failure and put it in the report, so what run() catches from a
    // sync is a MessagingError or a bug, not a RelayError. The branch is still worth having
    // and worth pinning: it is one future caller away from being live, and a function whose
    // first line is dead is a function whose first line drifts unnoticed.
    for (const failure of ['timeout', 'rate-limited', 'unauthorized', 'not-found'] as const) {
      expect(describeMessagingFailure(new RelayError(failure, 'relay: nope'))).toBe(
        relayFailureMessage(failure),
      );
    }
    // Distinct copy per code, so the loop above is discriminating rather than four ways of
    // asserting one string.
    expect(relayFailureMessage('timeout')).not.toBe(relayFailureMessage('rate-limited'));
  });

  it('each named MessagingError state becomes its conversation copy', () => {
    expect(describeMessagingFailure(new MessagingError('too-long', 'messaging: too long'))).toBe(
      CONVERSATION_COPY.tooLong(MAX_BODY_BYTES),
    );
    expect(describeMessagingFailure(new MessagingError('no-mailbox', 'messaging: none'))).toBe(
      CONVERSATION_COPY.noMailbox,
    );
    expect(describeMessagingFailure(new MessagingError('not-pinned', 'messaging: none'))).toBe(
      CONVERSATION_COPY.notPinned,
    );
    expect(CONVERSATION_COPY.noMailbox).not.toBe(CONVERSATION_COPY.notPinned);
  });

  it('a pass that ended in a lock gets conversation copy, not the internal sentence', () => {
    // THE COUPLED HALF OF THE MESSAGING FIX (defdepth), and the reason it is a test rather
    // than a line in a commit message: the fallthrough at the end of this function returns
    // `error.message`, so ADDING a MessagingError state without adding a branch here puts a
    // developer's sentence on screen and reads it out to a screen reader. That is the exact
    // defect this file already pins for the unlock path, arriving through a new door.
    //
    // The screen cannot reach this branch today, because run() rules the lock out and calls
    // onLock instead. It is executed here, through the function, rather than argued from the
    // source: an unreachable branch that is never run is a branch that drifts.
    const rendered = describeMessagingFailure(
      new MessagingError('locked', 'messaging: the vault locked itself part way through this pass'),
    );
    expect(rendered).toBe(CONVERSATION_COPY.locked);
    // The negative half, and the one that actually discriminates: the internal string is not
    // what a person sees. Written out rather than compared to the constant, because the
    // assertion above moves with copy.ts and this one does not.
    expect(rendered).not.toContain('messaging:');
    expect(rendered).toContain('Keyweave locked itself');
  });

  it('an unmapped MessagingError keeps its own message, and anything else is wrapped', () => {
    // 'empty' is the one MessagingError state with no entry above. It is not reachable from
    // this screen (the submit handler refuses a blank message before messaging sees it), so
    // what it falls through to is the developer message, unwrapped.
    expect(describeMessagingFailure(new MessagingError('empty', 'messaging: nothing to send'))).toBe(
      'messaging: nothing to send',
    );
    expect(describeMessagingFailure(new Error('storage is full'))).toBe(
      'Keyweave could not finish that: storage is full',
    );
    // Not everything thrown in a browser is an Error.
    expect(describeMessagingFailure('a bare string')).toBe(
      'Keyweave could not finish that: a bare string',
    );
  });

  it('no branch attributes the failure to the other person', () => {
    // The stated invariant of this function, and the reason it exists at all: the relay is
    // the one component nobody trusts, so a screen that says "your contact sent something
    // invalid" teaches people to distrust each other on the word of the liar. Asserted over
    // the rendered strings rather than over the source, because the wording lives in copy.ts
    // and could be changed there without this file moving at all.
    const blame = /\byour contact\b|\bthe other person\b|\bthey sent\b|\btheir message\b/i;
    const rendered = [
      describeMessagingFailure(new RelayError('timeout', 'x')),
      describeMessagingFailure(new RelayError('rate-limited', 'x')),
      describeMessagingFailure(new RelayError('unauthorized', 'x')),
      describeMessagingFailure(new RelayError('malformed', 'x')),
      describeMessagingFailure(new MessagingError('too-long', 'x')),
      describeMessagingFailure(new MessagingError('no-mailbox', 'x')),
      describeMessagingFailure(new MessagingError('not-pinned', 'x')),
    ];
    for (const line of rendered) expect(line).not.toMatch(blame);
    // The pattern is not vacuous: this is the sentence the app is allowed to say elsewhere,
    // about an interrupted pull, and it is the shape being kept out of the list above.
    expect('ask your contact to send it again').toMatch(blame);
  });
});

describe('a conversation that cannot be had says so and offers nothing', () => {
  it('a pairing with no drop box hides the composer, disables refresh and never starts the poll', async () => {
    // The contact is pinned, so the ready screen offers it, and the pairing has no
    // coordinates, so there is nowhere to put a message. Saying so on this screen is the
    // difference between a working button and one that fails on the screen after it.
    const relay = new FixtureRelay();
    await bootstrap(await fixtureVault({ mailbox: false }), relay);
    vi.useFakeTimers();

    openContact();
    await settle();

    const unavailable = find<HTMLElement>('[data-role="unavailable"]');
    expect(unavailable.hidden).toBe(false);
    expect(unavailable.textContent).toBe(CONVERSATION_COPY.noMailbox);
    expect(find<HTMLElement>('[data-role="form"]').hidden).toBe(true);
    expect(refreshButton().disabled).toBe(true);

    // And no relay work at all, now or on any later tick: an unmessageable conversation
    // starts no poll, so nothing here ever throws a not-pinned or no-mailbox error into a
    // screen the person cannot act on.
    //
    // Three intervals, and stated as a precondition rather than assumed, because this screen
    // has nothing touching the vault: run past the idle lock and the assertions below would
    // be failing about the unlock screen instead.
    expect(POLL_INTERVAL_MS * 3).toBeLessThan(IDLE_LOCK_MS);
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS * 3);
    expect(relay.listCalls).toBe(0);
    expect(errorLine().hidden).toBe(true);
    expect(statusLine().textContent).toBe('');
  });

  it('a contact pressed after the vault locked itself renders the lock notice, and throws nothing', async () => {
    // renderConversation is reached from two plain click handlers, the contact list and the
    // paired screen, and neither of them catches anything. The vault can be empty by the
    // time such a click is delivered, because the idle lock replaces the screen from a timer
    // rather than from anything the person did, and the control it belongs to is one that
    // fires precisely when nobody is watching. renderReady carries the same guard for the
    // same reason and says so in a comment.
    //
    // Without the guard the next line is requireSession(), which throws out of an event
    // listener: no screen change, no notice, and a press that does nothing at all. The lock
    // notice already being up is what makes that hard to see by eye, so the two assertions
    // below are on the only things that separate the outcomes.
    const relay = new FixtureRelay();
    await bootstrap(await fixtureVault({ mailbox: true }), relay);
    vi.useFakeTimers();

    // The idle timer is rearmed by every unlocked READ, so it only moves onto the fake clock
    // once something has read the vault under one. Opening the conversation and coming
    // straight back is the cheapest way to do that, and it leaves the ready screen freshly
    // rendered with the row this test is about to press.
    openContact();
    await settle();
    find<HTMLButtonElement>('[data-role="back"]').click();
    await settle();

    const row = find<HTMLButtonElement>('[data-role="contact-list"] [data-role="open"]');
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS + 1);
    const locked = find<HTMLInputElement>('#passphrase');
    expect(locked).not.toBeNull(); // control: the lock landed and rendered its own screen

    // happy-dom lets an exception out of dispatch, where a browser would hand it to
    // window.onerror instead. Either runtime is describing the same event, and neither of
    // them changes the screen or tells the person anything.
    expect(() => row.click()).not.toThrow();
    await settle();

    // And it SAYS so, rather than quietly doing nothing: the notice is rendered again, from
    // the top, so the unlock screen standing here now is a different node from the one the
    // timer left behind. Returning without a word would pass the line above and leave a
    // press that has no effect a person can see.
    expect(find<HTMLInputElement>('#passphrase')).not.toBe(locked);
  });
});

// NOW COVERED, and the note is kept because the reasoning is still the argument for the
// shape of the fix: what run()'s lock flag did on the REFRESH path used to be unpinnable
// rather than merely unpinned. The flag is set in the catch, and a lock that landed
// mid-refresh did not reach the catch at all, because receive() swallowed the vault's own
// error into `unopenable` and RESOLVED; the finally then repainted from an emptied vault and
// the read threw where nobody was holding it. A test over that path was red whatever it
// asserted, since vitest fails the run on the unhandled rejection, and the only way to a
// green one was a process-level handler swallowing unhandled rejections for every other test
// in here too, which trades a filed defect for a suite that has stopped reporting a whole
// class of failure. The fix removed the rejection instead: messaging.ts receive() now THROWS
// when the vault locked under it, so the flag does its job on both paths and both are pinned
// above. Its reachability in a browser is still the same modest claim: it needs a pass
// stalled past the idle lock, which is a suspended machine rather than a slow relay, since
// both halves of a sync are budgeted.
//
// NOT COVERED, and worth saying out loud rather than leaving as an apparent gap: the
// 'not-pinned' arm of the unavailable notice. renderConversation is reachable from exactly
// two places, the contact list (built from the pinned identities) and the paired screen
// (reached by pinning one), so a peerId that is not pinned cannot get there through the UI
// at all. The arm is defence in depth against a future caller, and the only honest way to
// execute it would be to call Messaging.state directly, which tests messaging.ts rather than
// this screen.
