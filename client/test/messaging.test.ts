// Messaging end to end, between two real paired devices, over a relay that lies.
//
// Nothing is mocked between the two parties: real key managers, real encrypted vaults, the
// real optical ceremony, real sealed envelopes. The only thing standing in for production is
// the relay itself, and it stands in as an ADVERSARY (test/hostile-relay.ts), because that
// is what the design says it is.
//
// Argon2id runs at ARGON2_FLOOR for speed, like the other end-to-end suites.

import { describe, it, expect } from 'vitest';
import { generateKeyManager } from '../src/keys.js';
import { ARGON2_FLOOR, decryptVaultBlob } from '../src/vault.js';
import { createSignedCard, importCard } from '../src/card.js';
import { seal } from '../src/seal.js';
import { encodePairingInfo, signMailboxCoordinate, toRelayMailboxId } from '../src/mailbox.js';
import { OpticalReceiver, type CardFrameStream } from '../src/optical.js';
import { OWN_CARD_SERIAL, PairingSession } from '../src/pairing-session.js';
import {
  FLUSH_BUDGET_MS,
  MAX_PULLS_PER_RECEIVE,
  Messaging,
  MessagingError,
} from '../src/messaging.js';
import {
  DEFAULT_TIMEOUT_MS,
  RelayClient,
  type BlobSummary,
  type FetchLike,
} from '../src/relay-client.js';
import { PairingCeremony } from '../src/ui/ceremony.js';
import { KeyweaveSession } from '../src/ui/session.js';
import { MemoryBlobStore } from '../src/ui/storage.js';
import { LocalVaultCrypto } from '../src/ui/vault-crypto.js';
import { HostileRelay } from './hostile-relay.js';

const PASSPHRASE = 'seven unrelated words make a passable line here';
const BASE = 'https://relay.test/';
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

interface Party {
  store: MemoryBlobStore;
  session: KeyweaveSession;
  messaging: Messaging;
  peerId: Uint8Array;
  /** The mailbox THIS device reads. The peer writes to it. */
  inboxId: string;
}

function readStream(stream: CardFrameStream): Uint8Array {
  const rx = new OpticalReceiver();
  for (let seq = 0; seq < 400; seq++) {
    const status = rx.feed(stream.frame(seq));
    if (status.kind === 'complete') return status.payload;
  }
  throw new Error('test: the stream never completed');
}

async function deliver(from: PairingCeremony, to: PairingCeremony): Promise<void> {
  for (const stream of from.view().playlist) await to.offer(readStream(stream));
}

async function newSession(store = new MemoryBlobStore()): Promise<KeyweaveSession> {
  return KeyweaveSession.createIdentity(new LocalVaultCrypto(ARGON2_FLOOR), store, PASSPHRASE, {
    idleMs: 0,
  });
}

/** Two devices, paired in person, each holding one mailbox it reads and one it writes. */
async function pairTwo(relay: HostileRelay): Promise<{ a: Party; b: Party }> {
  const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 2_000 });
  const storeA = new MemoryBlobStore();
  const storeB = new MemoryBlobStore();
  const sessionA = await newSession(storeA);
  const sessionB = await newSession(storeB);

  const boxA = relay.mint();
  const boxB = relay.mint();
  const coordA = { id: hexBytes(boxA.mailboxId), writeCap: boxA.writeCap };
  const coordB = { id: hexBytes(boxB.mailboxId), writeCap: boxB.writeCap };

  const psA = await PairingSession.begin(sessionA.keys(), OWN_CARD_SERIAL, {}, coordA);
  const psB = await PairingSession.begin(sessionB.keys(), OWN_CARD_SERIAL, {}, coordB);
  const cerA = PairingCeremony.begin(psA, sessionA, 'show-first', {
    id: coordA.id,
    pullToken: boxA.pullToken,
  });
  const cerB = PairingCeremony.begin(psB, sessionB, 'scan-first', {
    id: coordB.id,
    pullToken: boxB.pullToken,
  });

  await deliver(cerA, cerB);
  cerA.handOff();
  await deliver(cerB, cerA);
  cerB.handOff();
  await deliver(cerA, cerB);
  cerA.handOff();
  expect(cerA.view().mailboxLinked).toBe(true);
  expect(cerB.view().mailboxLinked).toBe(true);
  await cerA.confirmMatch();
  await cerB.confirmMatch();

  return {
    a: {
      store: storeA,
      session: sessionA,
      messaging: new Messaging(sessionA, api),
      peerId: sessionB.identityPublicKey(),
      inboxId: boxA.mailboxId,
    },
    b: {
      store: storeB,
      session: sessionB,
      messaging: new Messaging(sessionB, api),
      peerId: sessionA.identityPublicKey(),
      inboxId: boxB.mailboxId,
    },
  };
}

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Reopen a device from the bytes actually on disk. The whole durability question. */
async function reopen(party: Party, relay: HostileRelay): Promise<Party> {
  const session = await KeyweaveSession.unlock(
    new LocalVaultCrypto(ARGON2_FLOOR),
    party.store,
    PASSPHRASE,
    { idleMs: 0 },
  );
  const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 2_000 });
  return { ...party, session, messaging: new Messaging(session, api) };
}

/** A list is GET /blobs; a pull is GET /blobs/<id>. The budget tests care which is which. */
const isList = (url: string, method: string) =>
  method === 'GET' && new URL(url).pathname.endsWith('/blobs');

/**
 * An honest relay on a slow LINK. The request is routed first, so the relay's own
 * delete-on-pull really fires, and only then are the bytes paced out over `spreadMs`. That
 * order is what makes it the right shape for every test about the pull floor: a pull aborted
 * part way through this is a message the relay has already destroyed, exactly as
 * relay/keyweave_relay.py does it. Only pulls are slowed; the list answers at full speed, so
 * a test can spend the two phases separately.
 */
function slowPullBody(inner: FetchLike, spreadMs: number, chunks = 7): FetchLike {
  return async (url, init) => {
    const real = await inner(url, init);
    if (!/\/blobs\/bl-/.test(String(url)) || real.status !== 200) return real;
    const body = new Uint8Array(await real.arrayBuffer());
    const size = Math.ceil(body.length / chunks);
    const every = Math.round(spreadMs / chunks);
    return new Response(
      new ReadableStream<Uint8Array>({
        async start(controller) {
          for (let off = 0; off < body.length; off += size) {
            await new Promise((r) => setTimeout(r, every));
            controller.enqueue(body.subarray(off, Math.min(off + size, body.length)));
          }
          controller.close();
        },
      }),
      { status: 200, headers: real.headers },
    );
  };
}

/**
 * A relay that answers a PULL with a status instead of bytes, WITHOUT touching what it
 * holds, which is exactly the order the shipped relay does it in: relay/keyweave_relay.py
 * `_route_get` runs `_authz` first (that is where 401 and 429 are decided) and reaches
 * `store.pull_blob`, the only thing that deletes, only after it. So the blob is still in the
 * mailbox when one of those answers comes back, and the tests using this assert that by
 * collecting the message afterwards rather than by taking the wrapper's word for it.
 */
function statusOnPull(inner: FetchLike, status: number): FetchLike {
  return async (url, init) => {
    if (init.method === 'GET' && /\/blobs\/bl-/.test(String(url))) {
      const body = new TextEncoder().encode(JSON.stringify({ error: 'refused' }));
      return new Response(body, {
        status,
        headers: { 'Content-Type': 'application/json', 'Content-Length': String(body.length) },
      });
    }
    return inner(url, init);
  };
}

/** A relay that refuses every PUT before it stores anything. Leaves records queued. */
function refusePuts(inner: FetchLike): FetchLike {
  return async (url, init) => {
    if (init.method !== 'PUT') return inner(url, init);
    const body = new TextEncoder().encode(JSON.stringify({ error: 'unavailable' }));
    return new Response(body, {
      status: 503,
      headers: { 'Content-Type': 'application/json', 'Content-Length': String(body.length) },
    });
  };
}

/**
 * WHAT DEADLINE THE TRANSPORT WAS ACTUALLY ASKED FOR, per request.
 *
 * A deadline is not visible in the request, so no assertion about a report or about elapsed
 * time can say whether a change moved one. It IS visible where it is set: relay-client.ts
 * arms one timer with `limitMs` and then calls fetch with nothing awaited in between, so the
 * last delay armed before a call is that call's deadline, exactly. This is how "the shipped
 * defaults are unchanged" is measured rather than argued.
 */
function deadlineRecorder(inner: FetchLike): {
  fetch: FetchLike;
  seen: Array<{ kind: string; deadlineMs: number }>;
  install(): void;
  restore(): void;
} {
  const realTimeout = globalThis.setTimeout;
  const seen: Array<{ kind: string; deadlineMs: number }> = [];
  let last = Number.NaN;
  return {
    seen,
    install() {
      seen.length = 0;
      last = Number.NaN;
      globalThis.setTimeout = ((handler: TimerHandler, ms?: number, ...rest: unknown[]) => {
        last = ms ?? 0;
        return (realTimeout as unknown as (...args: unknown[]) => number)(handler, ms, ...rest);
      }) as unknown as typeof globalThis.setTimeout;
    },
    restore() {
      globalThis.setTimeout = realTimeout;
    },
    fetch: async (url, init) => {
      const kind =
        init.method === 'PUT'
          ? 'put'
          : isList(url, init.method)
            ? 'list'
            : /\/blobs\/bl-/.test(String(url))
              ? 'pull'
              : 'other';
      seen.push({ kind, deadlineMs: last });
      return inner(url, init);
    },
  };
}

/**
 * The BUDGET clock, under the test's control.
 *
 * receive() measures its budget with performance.now(), which is monotonic and therefore
 * cannot be moved by skewing Date.now(). What CAN still move it is the machine itself: a
 * frozen tab, a suspended laptop, an event loop that came back late. Real elapsed time
 * passed, and the pass has to cope with discovering that. This expresses exactly that event,
 * and does it by arithmetic rather than by sleeping, so the number under test is exact
 * instead of raced for.
 *
 * `leaveExactly` is called from inside a fetch wrapper, at the moment a response is handed
 * back, and sets the offset so that receive()'s NEXT reading of its budget is the value
 * asked for. It lands a few milliseconds low, because the pass still has to parse and
 * de-duplicate the list before it reads the clock, so every test using it leaves margin.
 */
function budgetClock(): {
  install(): void;
  restore(): void;
  leaveExactly(budgetMs: number, leftMs: number): void;
} {
  const perf = globalThis.performance;
  const real = perf.now.bind(perf);
  let offset = 0;
  let started = 0;
  return {
    install() {
      offset = 0;
      started = real();
      perf.now = () => real() + offset;
    },
    restore() {
      perf.now = real;
    },
    leaveExactly(budgetMs: number, leftMs: number) {
      offset = started + budgetMs - leftMs - real();
    },
  };
}

describe('the pairing hands both devices their mailboxes, durably', () => {
  it('each side stores one box it reads and one it writes, and they cross', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    const mailboxA = a.session.mailboxFor(a.peerId)!;
    const mailboxB = b.session.mailboxFor(b.peerId)!;
    expect(mailboxA).toBeDefined();
    // A writes to the box B reads, and the reverse. Exactly one capability each way.
    expect(toRelayMailboxId(mailboxA.outboxId)).toBe(b.inboxId);
    expect(toRelayMailboxId(mailboxB.outboxId)).toBe(a.inboxId);
    expect(toRelayMailboxId(mailboxA.inboxId)).toBe(a.inboxId);
    expect(mailboxA.outboxWriteCap).not.toBe(mailboxA.inboxPullToken);

    // Durable, not merely in memory.
    const stored = decryptVaultBlob((await a.store.load())!, PASSPHRASE);
    expect(stored.mailboxes).toHaveLength(1);
    expect(toRelayMailboxId(stored.mailboxes[0]!.outboxId)).toBe(b.inboxId);
  });

  it('a pairing where one device could not reserve a box stores no coordinates', async () => {
    // The relay was unreachable for one of them. Pairing still pins the key, and messaging
    // says so rather than offering a conversation that cannot work.
    const relay = new HostileRelay();
    const sessionA = await newSession();
    const sessionB = await newSession();
    const boxA = relay.mint();
    const coordA = { id: hexBytes(boxA.mailboxId), writeCap: boxA.writeCap };

    const psA = await PairingSession.begin(sessionA.keys(), OWN_CARD_SERIAL, {}, coordA);
    const psB = await PairingSession.begin(sessionB.keys()); // no mailbox
    const cerA = PairingCeremony.begin(psA, sessionA, 'show-first', {
      id: coordA.id,
      pullToken: boxA.pullToken,
    });
    const cerB = PairingCeremony.begin(psB, sessionB, 'scan-first');

    await deliver(cerA, cerB);
    cerA.handOff();
    await deliver(cerB, cerA);
    cerB.handOff();
    await deliver(cerA, cerB);
    cerA.handOff();
    expect(cerA.view().phase).toBe('compare');
    expect(cerA.view().mailboxLinked).toBe(false);
    await cerA.confirmMatch();

    expect(sessionA.mailboxFor(sessionB.identityPublicKey())).toBeUndefined();
    const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 2_000 });
    expect(new Messaging(sessionA, api).state(sessionB.identityPublicKey())).toBe('no-mailbox');
  });

  it('a coordinate signed by somebody else refuses the ceremony rather than redirecting', async () => {
    const relay = new HostileRelay();
    const sessionA = await newSession();
    const sessionB = await newSession();
    const attacker = (await generateKeyManager('noble')).manager;

    const boxA = relay.mint();
    const coordA = { id: hexBytes(boxA.mailboxId), writeCap: boxA.writeCap };
    const psA = await PairingSession.begin(sessionA.keys(), OWN_CARD_SERIAL, {}, coordA);
    const psB = await PairingSession.begin(sessionB.keys());
    const cerB = PairingCeremony.begin(psB, sessionB, 'scan-first');

    // A's real card, and an info payload carrying A's real nonce with the attacker's box
    // signed by the attacker. This is the screen-in-the-room case.
    const evil = relay.mint();
    const evilCoord = { id: hexBytes(evil.mailboxId), writeCap: evil.writeCap };
    const forged = encodePairingInfo(
      psA.nonce,
      evilCoord,
      await signMailboxCoordinate(attacker, evilCoord),
    );

    expect(await cerB.offer(readStream(psA.cardFrames))).toBe('accepted');
    expect(await cerB.offer(forged)).toBe('refused');
    expect(cerB.view().phase).toBe('refused');
    expect(cerB.view().refusal?.title).toMatch(/drop box details did not verify/);
    expect(sessionB.mailboxFor(sessionA.identityPublicKey())).toBeUndefined();
  });
});

describe('a message goes from one device to the other', () => {
  it('round-trips, and the sender never sees its own message come back', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);

    const sent = await a.messaging.send(a.peerId, 'meet me at the usual place');
    expect(sent.relayed).toBe(1);
    expect(sent.queued).toBe(0);
    expect(sent.failure).toBeUndefined();

    // The sender polling its own inbox finds nothing: the two directions are two mailboxes,
    // so delete-on-pull can never eat a message the sender itself wrote.
    const selfPull = await a.messaging.receive(a.peerId);
    expect(selfPull.accepted).toBe(0);
    expect(selfPull.listed).toBe(0);

    const got = await b.messaging.receive(b.peerId);
    expect(got.accepted).toBe(1);
    const thread = b.messaging.conversation(b.peerId);
    expect(thread).toHaveLength(1);
    expect(text(thread[0]!.body)).toBe('meet me at the usual place');
    expect(thread[0]!.direction).toBe('in');
  });

  it('the sender records handed-to-the-relay, never delivered', async () => {
    const relay = new HostileRelay();
    const { a } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'one');
    const mine = a.messaging.conversation(a.peerId);
    expect(mine[0]!.direction).toBe('out');
    expect(mine[0]!.delivery).toBe('relayed');
    // The wire bytes are dropped once the relay has them, so a conversation does not carry
    // a second copy of itself forever.
    expect(mine[0]!.wire).toBeUndefined();
  });

  it('refuses an empty message and one past the size cap', async () => {
    const relay = new HostileRelay();
    const { a } = await pairTwo(relay);
    await expect(a.messaging.send(a.peerId, '')).rejects.toBeInstanceOf(MessagingError);
    await expect(a.messaging.send(a.peerId, 'x'.repeat(5000))).rejects.toThrow(/at most 4096/);
  });
});

describe('the relay reorders, and nothing is lost', () => {
  it('a shuffled batch of five arrives complete and reads in sender order', async () => {
    // This is the bug the window plus seen-set design exists for: a monotone high-water gate
    // silently DROPPED anything the relay handed back below the mark, so an out-of-order
    // batch lost messages with no error anywhere.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);

    const base = Date.now();
    for (let i = 0; i < 5; i++) {
      await a.messaging.send(a.peerId, `message ${i}`, base + i * 1000);
    }
    relay.lies.reverseList = true;

    const got = await b.messaging.receive(b.peerId);
    expect(got.accepted).toBe(5);
    expect(got.duplicate).toBe(0);
    expect(got.stale).toBe(0);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'message 0',
      'message 1',
      'message 2',
      'message 3',
      'message 4',
    ]);
  });

  it('an interleaved conversation reads in one order on both devices', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    const base = Date.now();
    await a.messaging.send(a.peerId, 'a1', base + 1000);
    await b.messaging.send(b.peerId, 'b1', base + 2000);
    await a.messaging.send(a.peerId, 'a2', base + 3000);
    relay.lies.reverseList = true;
    await a.messaging.receive(a.peerId);
    await b.messaging.receive(b.peerId);

    const order = (party: Party) => party.messaging.conversation(party.peerId).map((m) => text(m.body));
    expect(order(a)).toEqual(['a1', 'b1', 'a2']);
    expect(order(b)).toEqual(order(a));
  });

  it('a withheld message records when it actually arrived, not only when it was sent', async () => {
    // Reordering a batch is the harmless case. WITHHOLDING is the one that reaches the
    // reader: the thread sorts on the sender's authenticated clock, so a blob the relay
    // sits on for days and releases later files itself into history that has already been
    // read. Sorting on arrival instead would hand the relay the order, so the sort stays;
    // what the record must carry is the local fact that the two clocks disagree.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    const now = Date.now();

    await a.messaging.send(a.peerId, 'the withheld one', now - 6 * 86_400_000);
    const box = relay.boxes.get(b.inboxId)!;
    const withheld = [...box.blobs.values()][0]!;
    box.blobs.clear(); // the relay simply does not offer it

    await a.messaging.send(a.peerId, 'a later message', now - 60_000);
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);

    relay.deposit(b.inboxId, withheld); // and now it hands it over
    expect((await b.messaging.receive(b.peerId, now)).accepted).toBe(1);

    const thread = b.messaging.conversation(b.peerId);
    // Still six days up the thread, because that is when the sender wrote it.
    expect(thread.map((m) => text(m.body))).toEqual(['the withheld one', 'a later message']);
    const held = thread[0]!;
    expect(held.receivedAtMs).toBe(now);
    expect(held.receivedAtMs! - held.timestampMs).toBeGreaterThan(5 * 86_400_000);
    // An outbound record has no arrival time to record: this device wrote it.
    const sent = a.messaging.conversation(a.peerId)[0]!;
    expect(sent.receivedAtMs).toBeUndefined();

    // Durable, or the next unlock loses the only evidence that the relay held it.
    const stored = decryptVaultBlob((await b.store.load())!, PASSPHRASE);
    const persisted = stored.messages.find((m) => text(m.body) === 'the withheld one')!;
    expect(persisted.receivedAtMs).toBe(now);
  });
});

describe('the WP1 caller obligation: an admit that is not saved is lost', () => {
  it('admit, save, reopen, and the same message now dedupes', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);

    // Capture the exact envelope A puts on the wire, so it can be replayed verbatim.
    const envelope = await seal(a.session.keys(), a.session.cardFor(a.peerId)!, new TextEncoder().encode('once'));
    relay.deposit(b.inboxId, envelope);
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);

    // Reopened from the bytes on disk, with no memory of the session that admitted it.
    const reborn = await reopen(b, relay);
    expect(reborn.messaging.conversation(reborn.peerId)).toHaveLength(1);

    relay.deposit(b.inboxId, envelope); // the relay replays it
    const again = await reborn.messaging.receive(reborn.peerId);
    expect(again.accepted).toBe(0);
    expect(again.duplicate).toBe(1);
    expect(reborn.messaging.conversation(reborn.peerId)).toHaveLength(1);
  });

  it('NEGATIVE CONTROL: an admit that never reached the blob IS re-accepted after reopen', async () => {
    // The residual vault.ts lock() names, demonstrated rather than asserted. If this ever
    // starts failing, either the guard became durable without a save (good, and the test
    // above is now redundant) or the test stopped exercising the path.
    const relay = new HostileRelay();
    const { b } = await pairTwo(relay);
    const senderId = b.peerId;
    const msgId = new Uint8Array(64).fill(0x11);
    const at = Date.now();

    expect(b.session.replay().admit(senderId, at, msgId).accepted).toBe(true);
    // No persist(). Reopen from what is actually on disk: the admit is simply gone, and the
    // replay is accepted a second time.
    const reborn = await reopen(b, relay);
    expect(reborn.session.replay().admit(senderId, at, msgId).accepted).toBe(true);

    // The positive half, so this is a control and not a fatalistic assertion: the SAME admit
    // followed by a save does not come back.
    await reborn.session.persist();
    const third = await reopen(reborn, relay);
    expect(third.session.replay().admit(senderId, at, msgId).accepted).toBe(false);
  });

  it('a replayed blob under a NEW id is still a duplicate, because the id is authenticated', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    const envelope = await seal(
      a.session.keys(),
      a.session.cardFor(a.peerId)!,
      new TextEncoder().encode('twice'),
    );
    relay.deposit(b.inboxId, envelope);
    relay.deposit(b.inboxId, envelope); // same bytes, different blob id
    const got = await b.messaging.receive(b.peerId);
    expect(got.accepted).toBe(1);
    expect(got.duplicate).toBe(1);
    expect(b.messaging.conversation(b.peerId)).toHaveLength(1);
  });
});

describe('blobs the relay had no business returning are dropped silently', () => {
  async function expectDiscarded(
    prepare: (relay: HostileRelay, a: Party, b: Party) => Promise<void> | void,
    field: 'unopenable' | 'defective' | 'vanished' = 'unopenable',
  ): Promise<void> {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await prepare(relay, a, b);
    const got = await b.messaging.receive(b.peerId);
    expect(got.accepted).toBe(0);
    expect(got[field]).toBeGreaterThan(0);
    // The user-visible outcome: an empty conversation, and no claim about the peer.
    expect(b.messaging.conversation(b.peerId)).toHaveLength(0);
  }

  it('a blob nobody sent', async () => {
    await expectDiscarded((relay, _a, b) => {
      relay.deposit(b.inboxId, new Uint8Array(200).fill(0x42));
    });
  });

  it('a blob with one byte flipped', async () => {
    await expectDiscarded(async (relay, a, b) => {
      await a.messaging.send(a.peerId, 'tamper me');
      relay.lies.corruptByte = true;
    });
  });

  it('a truncated blob', async () => {
    await expectDiscarded(async (relay, a, b) => {
      await a.messaging.send(a.peerId, 'cut me short');
      relay.lies.truncate = true;
    });
  });

  it('a blob from a DIFFERENT sender, correctly sealed TO this device', async () => {
    // Authentic, well-formed, addressed to B, and not from the one identity B pinned for
    // this conversation. B derives K for (B, A), so the AEAD is what refuses it.
    await expectDiscarded(async (relay, _a, b) => {
      const stranger = await newSession();
      const cardOfB = importCard(await cardBytesOf(b.session));
      const envelope = await seal(
        stranger.keys(),
        cardOfB,
        new TextEncoder().encode('not from your contact'),
      );
      relay.deposit(b.inboxId, envelope);
    });
  });

  it('a blob addressed to somebody else', async () => {
    await expectDiscarded(async (relay, a, b) => {
      const third = await newSession();
      const thirdCard = importCard(await cardBytesOf(third));
      const envelope = await seal(a.session.keys(), thirdCard, new TextEncoder().encode('for C'));
      relay.deposit(b.inboxId, envelope);
    });
  });

  it('a body that streams past the ceiling', async () => {
    await expectDiscarded(async (relay, a, _b) => {
      await a.messaging.send(a.peerId, 'small');
      relay.lies.oversizeBytes = 4 * 1024 * 1024;
    }, 'defective');
  });

  it('a listed blob that is gone by the time it is asked for', async () => {
    await expectDiscarded(async (relay, a, _b) => {
      await a.messaging.send(a.peerId, 'here then gone');
      relay.lies.dropOnPull = true;
    }, 'vanished');
  });

  it('one bad blob does not stop the good one in the same batch', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    relay.deposit(b.inboxId, new Uint8Array(120).fill(0x7f)); // junk, listed first
    await a.messaging.send(a.peerId, 'the real one');
    const got = await b.messaging.receive(b.peerId);
    expect(got.unopenable).toBe(1);
    expect(got.accepted).toBe(1);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual(['the real one']);
  });
});

describe('the relay lies about its own answers', () => {
  it('claiming the mailbox is empty loses nothing: the next refresh gets it', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'still there');
    relay.lies.emptyList = true;
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(0);
    relay.lies.emptyList = false;
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);
  });

  it('a duplicated list pulls each blob once, because ids are de-duplicated first', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'once please');
    relay.lies.duplicateList = 4;
    const got = await b.messaging.receive(b.peerId);
    expect(got.listed).toBe(1);
    expect(got.accepted).toBe(1);
  });

  it('malformed JSON on the list is a named failure with nothing corrupted', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'unreachable for now');
    relay.lies.malformedJson = true;
    const got = await b.messaging.receive(b.peerId);
    expect(got.failure?.failure).toBe('malformed');
    expect(got.accepted).toBe(0);
    relay.lies.malformedJson = false;
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);
  });

  it('valid JSON of the wrong shape is the same story', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'shape');
    relay.lies.wrongShape = 'nested';
    expect((await b.messaging.receive(b.peerId)).failure?.failure).toBe('malformed');
    relay.lies.wrongShape = undefined;
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);
  });

  it('blob ids that fail validation are dropped from the list', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'hidden behind a bad id');
    relay.lies.fakeBlobId = '../../../etc/passwd';
    const got = await b.messaging.receive(b.peerId);
    expect(got.listed).toBe(0);
    expect(got.accepted).toBe(0);
  });

  it('a redirect is a named failure and changes no state', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'behind a redirect');
    relay.lies.redirect = 'throw';
    const got = await b.messaging.receive(b.peerId);
    expect(got.failure?.failure).toBe('network');
    expect(b.messaging.conversation(b.peerId)).toHaveLength(0);
    relay.lies.redirect = undefined;
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);
  });

  it('a list of a thousand ids costs at most MAX_PULLS_PER_RECEIVE pulls', async () => {
    const relay = new HostileRelay();
    const { b } = await pairTwo(relay);
    for (let i = 0; i < 200; i++) relay.deposit(b.inboxId, new Uint8Array(40).fill(i));
    const before = relay.calls.length;
    const got = await b.messaging.receive(b.peerId);
    expect(got.listed).toBe(MAX_PULLS_PER_RECEIVE);
    // One list plus at most the cap in pulls.
    expect(relay.calls.length - before).toBeLessThanOrEqual(MAX_PULLS_PER_RECEIVE + 1);
  });

  it('one pass is bounded by a wall clock budget, not by the number of ids listed', async () => {
    // The cap above bounds the COUNT of relay-chosen work units. It does not bound their
    // COST. A relay that paces the body of every pull to just inside the per-request
    // deadline, and crosses the size ceiling rather than the clock so the loop continues,
    // spends one whole deadline per id it chose to list. The caller holds the composer
    // disabled for the whole pass, so without a budget the relay decides when a person is
    // allowed to write a message.
    const relay = new HostileRelay();
    const { b } = await pairTwo(relay);
    for (let i = 0; i < 6; i++) relay.deposit(b.inboxId, new Uint8Array(40).fill(i));
    relay.lies.tricklePastCeiling = true;
    const api = new RelayClient({
      baseUrl: BASE,
      fetch: relay.fetch,
      timeoutMs: 400,
      maxResponseBytes: 8192,
    });

    // The cost of one unit, measured rather than assumed: with a budget far larger than the
    // pass, all six ids are pulled and each one costs most of a deadline. This is the shape
    // the fix is against, and it is why the assertion below is not merely "it was quick".
    const unbudgeted = new Messaging(b.session, api, { receiveBudgetMs: 60_000 });
    const openStart = Date.now();
    const open = await unbudgeted.receive(b.peerId);
    const openElapsed = Date.now() - openStart;
    expect(open.defective).toBe(6);
    expect(open.unread).toBe(0);
    expect(openElapsed).toBeGreaterThan(1_200); // six deadlines, not one

    // Same relay, same ids (an oversize pull is never delivered, so nothing was deleted),
    // under a budget. The pass ends inside it and says what it did not get to.
    const bounded = new Messaging(b.session, api, { receiveBudgetMs: 800 });
    const started = Date.now();
    const got = await bounded.receive(b.peerId);
    const elapsed = Date.now() - started;
    expect(got.listed).toBe(6);
    expect(elapsed).toBeLessThan(1_100); // one budget plus slack, not six deadlines
    expect(got.unread).toBeGreaterThan(0);
    expect(got.defective + got.unread).toBeLessThanOrEqual(6);
    expect(got.failure?.failure).toBe('timeout');

    // Nothing was lost by giving up early: the ids that were never asked for were never
    // pulled, so they are still in the mailbox when the relay stops stalling.
    relay.lies.tricklePastCeiling = false;
    const after = await b.messaging.receive(b.peerId);
    expect(after.accepted + after.unopenable).toBe(6);
    expect(after.unread).toBe(0);
  });

  it('the budget never starts a pull it cannot finish: a slow HONEST relay loses nothing', async () => {
    // The regression the budget itself introduced. A pull is not a retryable read: the relay
    // deletes the blob before the bytes reach the wire, so a pull aborted mid-body destroys
    // the message, and the sender cannot resend because flush() already dropped its wire
    // bytes. Spending the budget to its last millisecond therefore turns the tail of every
    // pass into a hole, and the case that hits it is not a hostile relay but an honest one
    // on a slow link. The floor is the fix: an id never asked for is still in the mailbox.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);

    for (const body of ['one', 'two', 'three']) {
      await a.messaging.send(a.peerId, body);
    }

    // Honest but slow: the relay's own delete-on-pull fires first (inside relay.fetch), and
    // only then are the real bytes re-served in paced chunks.
    const slowApi = new RelayClient({
      baseUrl: BASE,
      fetch: slowPullBody(relay.fetch, 700),
      timeoutMs: 15_000,
    });
    // A budget that fits roughly two of the three ~700ms pulls, so the third lands in the
    // tail. That third pull is the one the pre-floor code started with a sliver.
    const bounded = new Messaging(b.session, slowApi, {
      receiveBudgetMs: 1_800,
      minPullDeadlineMs: 900,
    });
    const got = await bounded.receive(b.peerId);
    expect(got.listed).toBe(3);
    expect(got.failure?.failure).toBe('timeout'); // the pass did stop early

    // THE PROPERTY: every message is either accepted here or still waiting. None is in the
    // gap between the two. Finish the collection with an unhurried pass and count.
    const rest = await b.messaging.receive(b.peerId);
    expect(got.accepted + rest.accepted).toBe(3);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'one',
      'two',
      'three',
    ]);
  }, 30_000);

  it('a floor above the budget is capped at half of it, so a small budget still collects', async () => {
    // Negative control on the cap, and it pins the CURRENT semantics rather than the ones it
    // was written for: a floor of 30000 under a budget of 5000 becomes 2500, half the
    // budget, not 5000, the whole of it. Half is what leaves the list a share to answer in;
    // an uncapped floor would hand the list Math.max(1, 5000 - 30000), a one millisecond
    // deadline, and the pass would die before it ever reached a pull. Hence the 100ms of
    // honest delay below: without it an in-memory relay can answer inside a deadline of one
    // millisecond and the test would pass with the cap removed.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'still arrives');

    relay.lies.delayMs = 100;
    // Far above the floor, so the budget half-cap is what decides and not the relay client's
    // own per-request ceiling (which is the other cap, pinned separately below).
    const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 15_000 });
    const tiny = new Messaging(b.session, api, {
      receiveBudgetMs: 5_000,
      minPullDeadlineMs: 30_000, // absurdly above the budget, so the cap is what decides
    });
    const got = await tiny.receive(b.peerId);
    expect(got.accepted).toBe(1);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'still arrives',
    ]);
  });

  it('a slow HONEST list never leaves a mailbox nothing can empty', async () => {
    // THE PERMANENTLY EMPTY INBOX. The floor used to be clamped to the whole budget and
    // then checked against whatever the list left behind, which is a check that a slow list
    // always wins: every pass listed the waiting ids, refused to pull a single one, and
    // reported a timeout, so the same ids were listed and refused again on the next refresh
    // for as long as the link stayed slow. Nothing is destroyed by that and nothing is ever
    // collected either, which is the failure the floor's own doc comment says it exists to
    // prevent, reached from the other side.
    //
    // Deterministic on purpose, unlike the millisecond race that made the clamp test flaky:
    // the list here costs half a second of real wall clock, so the budget is measurably
    // spent by the time the first id is considered, every run.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    for (const body of ['one', 'two', 'three']) await a.messaging.send(a.peerId, body);

    // Honest, just slow: every request, the list included, costs 500ms.
    relay.lies.delayMs = 500;
    const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 15_000 });
    const slow = new Messaging(b.session, api, {
      receiveBudgetMs: 2_000,
      // Absurdly above the budget, so the cap is what decides. Under the old clamp this
      // became 2000, equal to the budget, and the list had already spent 500 of it.
      minPullDeadlineMs: 30_000,
    });

    // Refresh until the mailbox is empty, exactly as the poll loop would. The bound is the
    // assertion: a pass that lists ids and attempts none is the regression, and a run of
    // those never terminates however many times it is repeated.
    let passes = 0;
    while (b.messaging.conversation(b.peerId).length < 3 && passes < 6) {
      passes++;
      const pass = await slow.receive(b.peerId);
      if (pass.listed > 0) {
        // attempted, expressed in the report's own terms.
        expect(pass.listed - pass.unread).toBeGreaterThanOrEqual(1);
        expect(pass.accepted).toBeGreaterThanOrEqual(1);
      }
    }
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'one',
      'two',
      'three',
    ]);
  }, 30_000);

  it('a list too slow for its share fails as a LIST timeout, and destroys nothing', async () => {
    // The other side of the reservation. The floor is subtracted from the list's deadline,
    // so a link too slow to leave a pull affordable fails while listing rather than
    // succeeding at listing and then refusing to pull. The distinction is not cosmetic:
    // listing does not delete, so the honest failure costs nothing, and the pass gives up
    // at its shortened list deadline rather than burning the whole budget first.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'waits for a faster moment');

    relay.lies.delayMs = 6_000;
    const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 60_000 });
    const bounded = new Messaging(b.session, api, {
      receiveBudgetMs: 4_000,
      minPullDeadlineMs: 2_000,
    });
    const started = Date.now();
    const got = await bounded.receive(b.peerId);
    const elapsed = Date.now() - started;

    expect(got.failure?.failure).toBe('timeout');
    expect(got.listed).toBe(0); // it never got a list at all
    expect(got.accepted).toBe(0);
    expect(got.interrupted).toBe(0); // nothing was pulled, so nothing could have been lost
    // Budget minus floor (2000), not the whole budget (4000). The bound sits halfway between
    // the two: a full second of timer lateness still passes, and removing the reservation
    // still fails it by a full second. A tighter bound would be a slower machine away from
    // failing on correct code, which is the wrong way round for a timing assertion.
    expect(elapsed).toBeLessThan(3_000);

    // Nothing was destroyed by giving up: the blob was never pulled, so it is still there.
    relay.lies.delayMs = undefined;
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'waits for a faster moment',
    ]);
  }, 30_000);

  it('a budget that is genuinely spent refuses even the reserved first pull', async () => {
    // THE RESERVATION CAN BE EATEN, and when it has been, the exemption is not a licence.
    // The floor is withheld from the list's deadline so the first pull is affordable, and
    // that holds while the list respects the deadline. It does not hold when the machine
    // stops: a frozen tab or a suspended laptop returns from the list with the whole budget
    // already spent, and the reservation spent with it. Starting the pull anyway means
    // handing it the bare floor on a link that has just proved slower than that, and the
    // relay deletes a blob before it sends it, so the abort that follows destroys the
    // message with no way to ask for it again. Refusing costs one poll interval and destroys
    // nothing. That asymmetry is the whole argument, and this is where it is pinned.
    //
    // The stall is applied to the MONOTONIC clock, which is the one the budget uses, at the
    // instant the list is served, and it is arithmetic rather than a real sleep of the whole
    // budget and then some.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'still in the mailbox afterwards');

    const BUDGET = 4_000;
    const FLOOR = 1_500;
    const clock = budgetClock();
    const stalled: FetchLike = async (url, init) => {
      const response = await relay.fetch(url, init);
      // A second past the end of the budget: not an accounting wobble, a real stall.
      if (isList(url, init.method)) clock.leaveExactly(BUDGET, -1_000);
      return response;
    };
    const api = new RelayClient({ baseUrl: BASE, fetch: stalled, timeoutMs: 60_000 });
    const bounded = new Messaging(b.session, api, {
      receiveBudgetMs: BUDGET,
      minPullDeadlineMs: FLOOR,
    });

    const before = relay.calls.length;
    clock.install();
    let got;
    try {
      got = await bounded.receive(b.peerId);
    } finally {
      clock.restore();
    }

    // The list happened. No pull did, and that is checked at the transport, not only in the
    // report: a pull that was started and then abandoned is exactly the outcome being ruled
    // out, and it would still leave listed=1 and accepted=0 behind it.
    expect(got.listed).toBe(1);
    expect(got.unread).toBe(1);
    expect(got.accepted).toBe(0);
    expect(got.interrupted).toBe(0);
    expect(got.failure?.failure).toBe('timeout');
    expect(relay.calls.slice(before).filter((c) => /\/blobs\/bl-/.test(c.url))).toHaveLength(0);

    // And the message is still there, which is the point of refusing rather than trying.
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'still in the mailbox afterwards',
    ]);
  }, 30_000);

  it('a list that eats nearly its whole share still gets its first pull, at the full floor', async () => {
    // The case the exemption exists for, which is the reason it is bounded rather than
    // deleted. The list answers just inside its deadline, so what is left when the first id
    // is considered is a little UNDER the floor: not a stall, just the accounting catching
    // up with a slow answer. Refusing here is the permanently empty inbox, so the pull is
    // attempted, and attempted with the reservation rather than with the leftovers.
    //
    // Both halves are load bearing and both are discriminated by the numbers: the pull needs
    // 1750ms of link, more than the 1500ms left, less than the 2000ms floor. Remove the
    // exemption and nothing is collected; hand the pull the leftovers instead of the floor
    // and it aborts mid-body, which under delete-on-pull destroys the message.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'collected on the reservation');

    const BUDGET = 4_000;
    const FLOOR = 2_000;
    const clock = budgetClock();
    const slow = slowPullBody(relay.fetch, 1_750);
    const nearlySpent: FetchLike = async (url, init) => {
      const response = await slow(url, init);
      if (isList(url, init.method)) clock.leaveExactly(BUDGET, 1_500);
      return response;
    };
    const api = new RelayClient({ baseUrl: BASE, fetch: nearlySpent, timeoutMs: 60_000 });
    const bounded = new Messaging(b.session, api, {
      receiveBudgetMs: BUDGET,
      minPullDeadlineMs: FLOOR,
    });

    clock.install();
    let got;
    try {
      got = await bounded.receive(b.peerId);
    } finally {
      clock.restore();
    }

    expect(got.listed).toBe(1);
    expect(got.unread).toBe(0);
    expect(got.accepted).toBe(1);
    expect(got.interrupted).toBe(0);
    expect(got.failure).toBeUndefined();
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'collected on the reservation',
    ]);
  }, 30_000);

  it('the first pull may spend the reservation only while HALF of it is still there', async () => {
    // THE PUBLISHED NUMBER, PINNED AS A NUMBER. docs/NAMED-RESIDUALS.md tells a reader that a
    // pass can end at most half a pull floor past its budget, and the whole of that claim is
    // the `left * 2 >= floor` conjunct: the exempt first pull is handed the floor, so the
    // overrun is floor minus what was left, and only a threshold at half the floor bounds
    // that by half the floor. Multiply the 2 by five and the published bound quintuples in
    // silence, because the exemption still exists and every other test here still passes; the
    // suite only noticed the conjunct being deleted outright. A doc that publishes a bound
    // needs a test that fails when the bound moves, not one that fails when it disappears.
    //
    // DISCRIMINATING A THRESHOLD TAKES A VALUE ON EACH SIDE OF IT, close enough that only
    // this threshold sits between them. The other tests in this file leave -1000 and +1500
    // against floors of 1500 and 2000, which any line between roughly -0.67 and +0.75 of a
    // floor satisfies. These two leave 800 and 1200 against a floor of 2000, so the line has
    // to be inside (800, 1200]: at 2 it is 1000 and both halves hold, at 3 it is 667 and the
    // refusal below becomes a pull, at 1.5 it is 1333 and the pull above becomes a refusal.
    //
    // MEASURED AT THE TRANSPORT, because a refused pull and an attempted one both leave
    // accepted=0 in the report when the attempt fails, and the difference between them is
    // exactly whether the request was made. The same message is used for both halves: refused
    // in the first pass, collected in the second, which is also the proof that refusing costs
    // a poll interval rather than a message.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'refused once, then collected');

    const BUDGET = 6_000;
    const FLOOR = 2_000;
    // One pass whose list hands back control with exactly `leftMs` of the budget remaining.
    // The stall is arithmetic on the monotonic clock at the instant the list is served, which
    // is the event a frozen tab or a suspended machine produces, expressed exactly.
    const passLeaving = async (leftMs: number) => {
      const clock = budgetClock();
      const stalled: FetchLike = async (url, init) => {
        const response = await relay.fetch(url, init);
        if (isList(url, init.method)) clock.leaveExactly(BUDGET, leftMs);
        return response;
      };
      const api = new RelayClient({ baseUrl: BASE, fetch: stalled, timeoutMs: 60_000 });
      const bounded = new Messaging(b.session, api, {
        receiveBudgetMs: BUDGET,
        minPullDeadlineMs: FLOOR,
      });
      const before = relay.calls.length;
      clock.install();
      try {
        const got = await bounded.receive(b.peerId);
        const pulls = relay.calls.slice(before).filter((c) => /\/blobs\/bl-/.test(c.url)).length;
        return { got, pulls };
      } finally {
        clock.restore();
      }
    };

    // BELOW HALF THE FLOOR the reservation is treated as spent, so the id is left where it is
    // rather than pulled with the bare floor on a link that has just proved slower than that.
    const refused = await passLeaving(800);
    expect(refused.pulls).toBe(0);
    expect(refused.got.listed).toBe(1);
    expect(refused.got.unread).toBe(1);
    expect(refused.got.accepted).toBe(0);
    expect(refused.got.interrupted).toBe(0);
    expect(refused.got.failure?.failure).toBe('timeout');

    // ABOVE IT the pull is attempted, and attempted at the full floor rather than with the
    // leftovers, which is the case the exemption exists for. 400ms either side of the same
    // line, and nothing else about the two passes differs.
    const attempted = await passLeaving(1_200);
    expect(attempted.pulls).toBe(1);
    expect(attempted.got.listed).toBe(1);
    expect(attempted.got.unread).toBe(0);
    expect(attempted.got.accepted).toBe(1);
    expect(attempted.got.failure).toBeUndefined();
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'refused once, then collected',
    ]);
  }, 30_000);

  it('only the FIRST pull may spend the reservation, never the one after it', async () => {
    // The reservation is one floor, withheld once, for the pull that the list's own deadline
    // paid for. A second pull granted the same exemption is spending budget that was never
    // set aside, on an id that is safe where it is, and the shape of that mistake is a
    // one-character edit (attempted === 0 becoming attempted <= 1). Every other test in this
    // file passes with that edit in place, which is why this one exists.
    //
    // Timed so the two ids fall either side of the line: 4000 of budget, a 2000 floor, and
    // 1250 per request. The list leaves 2750, so the first pull clears the floor outright.
    // The pull leaves 1500, which is under the floor and over half of it, so the second pull
    // is refused only because it is not the first. Exempt it and it would be attempted, get
    // the floor, and succeed.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'first');
    await a.messaging.send(a.peerId, 'second');

    relay.lies.delayMs = 1_250;
    const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 15_000 });
    const bounded = new Messaging(b.session, api, {
      receiveBudgetMs: 4_000,
      minPullDeadlineMs: 2_000,
    });

    const before = relay.calls.length;
    const got = await bounded.receive(b.peerId);

    expect(got.listed).toBe(2);
    expect(got.accepted).toBe(1);
    expect(got.unread).toBe(1); // the second id was never asked for
    expect(got.interrupted).toBe(0);
    expect(got.failure?.failure).toBe('timeout');
    expect(relay.calls.slice(before).filter((c) => /\/blobs\/bl-/.test(c.url))).toHaveLength(1);

    // Refused, not lost: the id nobody asked for is still in the mailbox.
    relay.lies.delayMs = undefined;
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'first',
      'second',
    ]);
  }, 30_000);

  it('a wall clock that steps mid pass does not lengthen or shorten the budget', async () => {
    // WHY THE BUDGET IS NOT ON Date.now(). NTP and cellular time sync step the wall clock on
    // the phones this is for, and a budget measured with it inherits both directions: a step
    // backwards inflates every reading of what is left, so the ceiling silently stops
    // applying and the relay holds the composer for as long as it likes, which is the one
    // thing the budget exists to prevent. Ten minutes backwards is an ordinary correction
    // and would have bought a stalling relay ten extra minutes of screen.
    //
    // Same numbers as the test above, so the expected outcome is a value already established
    // by a run with no clock trick at all: one collected, one refused. On a wall-clock budget
    // the second pull would be affordable and both would arrive.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'first');
    await a.messaging.send(a.peerId, 'second');

    relay.lies.delayMs = 1_250;
    const realNow = Date.now;
    let skewMs = 0;
    const stepping: FetchLike = async (url, init) => {
      const response = await relay.fetch(url, init);
      if (isList(url, init.method)) skewMs = -600_000;
      return response;
    };
    const api = new RelayClient({ baseUrl: BASE, fetch: stepping, timeoutMs: 15_000 });
    const bounded = new Messaging(b.session, api, {
      receiveBudgetMs: 4_000,
      minPullDeadlineMs: 2_000,
    });

    Date.now = () => realNow.call(Date) + skewMs;
    let got;
    try {
      // The acceptance window is passed explicitly, from the real clock: it is a different
      // quantity from the budget, it is compared against a sender's authenticated timestamp,
      // and this test is not about it.
      got = await bounded.receive(b.peerId, realNow.call(Date));
    } finally {
      Date.now = realNow;
    }

    expect(got.listed).toBe(2);
    expect(got.accepted).toBe(1);
    expect(got.unread).toBe(1);
    expect(got.failure?.failure).toBe('timeout');
  }, 30_000);

  it('a pull floor the relay client could never honour is capped to what it can', async () => {
    // THE FLOOR IS A CLAIM ABOUT A DEADLINE, and the relay client owns the ceiling on every
    // deadline: `limitMs` is min(its own timeout, whatever the caller asked for). A floor
    // above that ceiling is therefore a promise the transport cannot keep, and the damage is
    // not only to the comment that states it: the pass then refuses ids for wanting budget
    // that could never have been spent on them, so a mailbox empties slower than the link
    // allows for no reason the code can name. Taking the smaller of the two makes the claim
    // true rather than intended.
    //
    // 4500 of budget, a floor asked for at 2250, and a client that will not run any request
    // past 1000ms. Capped, the floor is 1000 and all six ids fit. Uncapped it is 2250, and
    // the pass refuses the last two while every request it did make was bounded by 1000
    // anyway.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    for (const body of ['one', 'two', 'three', 'four', 'five', 'six']) {
      await a.messaging.send(a.peerId, body);
    }

    relay.lies.delayMs = 450;
    const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 1_000 });
    const bounded = new Messaging(b.session, api, {
      receiveBudgetMs: 4_500,
      minPullDeadlineMs: 2_250,
    });
    const got = await bounded.receive(b.peerId);

    expect(got.listed).toBe(6);
    expect(got.accepted).toBe(6);
    expect(got.unread).toBe(0);
    expect(got.failure).toBeUndefined();
  }, 30_000);

  it('a pull that dies mid body is reported as maybe lost, and it really is lost', async () => {
    // THE ONE OUTCOME WHERE "nothing was lost" IS FALSE. The relay deletes a blob inside the
    // critical section before the bytes reach the wire, so a pull that gets part of a body
    // and then times out has destroyed the message: the relay has dropped it, this device
    // never parsed it, and the sender cannot resend it because flush() discarded its wire
    // bytes at the 201. The report has to be able to say so, because the copy for a plain
    // timeout tells the user nothing was lost, and on this path that sentence talks them out
    // of the only thing that recovers the message, which is asking their contact to send it
    // again.
    //
    // The second half of this test is the part that earns the wording: it proves the loss is
    // real rather than assumed, by looking for the message afterwards and not finding it.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'destroyed by a pull that did not finish');

    // 700ms of body against a 300ms ceiling, so the abort lands mid-stream, after the relay
    // has already deleted.
    const api = new RelayClient({
      baseUrl: BASE,
      fetch: slowPullBody(relay.fetch, 700),
      timeoutMs: 300,
    });
    const got = await new Messaging(b.session, api).receive(b.peerId);

    expect(got.listed).toBe(1);
    expect(got.accepted).toBe(0);
    expect(got.interrupted).toBe(1);
    expect(got.failure?.failure).toBe('timeout');

    // Gone. Not waiting for a calmer moment, not recoverable by trying again: an unhurried
    // pass over the same mailbox finds nothing at all.
    const after = await b.messaging.receive(b.peerId);
    expect(after.listed).toBe(0);
    expect(after.accepted).toBe(0);
    expect(after.interrupted).toBe(0);
    expect(b.messaging.conversation(b.peerId)).toHaveLength(0);
  }, 30_000);

  it('a runtime with no monotonic clock still collects, on the wall clock', async () => {
    // The other half of moving the budget off Date.now(): performance.now() is in every
    // browser this targets and in Node, but "is in every runtime we know of" is not the same
    // claim as "is in every runtime", and a messenger that throws on a missing timing API is
    // a worse outcome than one that measures with a clock that can be stepped. The resolver
    // is written to answer that question per pass, so this removes the global and checks the
    // pass still works rather than reading the resolver and agreeing with it.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'collected without a monotonic clock');

    const real = globalThis.performance;
    let got;
    try {
      Object.defineProperty(globalThis, 'performance', { value: undefined, configurable: true });
      got = await b.messaging.receive(b.peerId);
    } finally {
      Object.defineProperty(globalThis, 'performance', { value: real, configurable: true });
    }
    expect(got.accepted).toBe(1);
    expect(got.failure).toBeUndefined();
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'collected without a monotonic clock',
    ]);
  }, 30_000);

  it('a budget that is not a number falls back to the default instead of poisoning the pass', async () => {
    // NaN loses every comparison, so it fails open everywhere it lands: every deadline in
    // the pass becomes NaN, and setTimeout reads that as zero. Measured with the guard
    // removed, on this exact fixture, the pass aborts its own LIST and reports listed=0. On
    // a fast list with a body that takes real time it gets further and worse: the first pull
    // starts with a zero-length deadline, aborts mid-body, and under delete-on-pull that
    // message is unrecoverable afterwards. Nothing in the app passes one; the option is
    // public, so the shape is refused where it enters rather than trusted not to appear.
    //
    // The 100ms below is what makes this a test rather than a formality: on an instant
    // in-memory link a zero-length deadline never fires at all, so a NaN budget looks
    // perfectly healthy, which is precisely the reading a suite would take on trust.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'not destroyed by a bad option');

    relay.lies.delayMs = 100; // so a zero-length deadline is a real abort, not a race
    const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 15_000 });
    const broken = new Messaging(b.session, api, {
      receiveBudgetMs: Number.NaN,
      minPullDeadlineMs: Number.NaN,
    });
    const got = await broken.receive(b.peerId);
    expect(got.accepted).toBe(1);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'not destroyed by a bad option',
    ]);
  }, 30_000);

  it('a status the relay decides BEFORE it deletes is not a message that may be lost', async () => {
    // WHO GETS TOLD THEIR MESSAGE MAY BE GONE. `interrupted` is the count the conversation
    // screen prints "ask your contact to send it again" from, and it used to include every
    // failure that was not a per-blob defect. That swept in the two statuses an ordinary
    // relay sends most often: the shipped relay decides a 401 and a 429 in `_authz`, which
    // runs before `store.pull_blob`, the only thing that deletes. So the blob was never
    // touched, the next refresh collects it, and the person was reading "wait a little
    // before asking it again" and "that one may be gone" in the same status line.
    //
    // The discriminator is the one the transport establishes: an answer carries a status, a
    // deadline that fired or a connection that died does not. The 5xx arm is the other half
    // of the rule and it stays conservative, because the relay's own catch-all wrapper
    // (`_guarded`) turns any unexpected exception into a 500 around the WHOLE route, delete
    // included, so that one really cannot be told apart.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'never touched by a refusal');

    for (const [status, failure] of [
      [429, 'rate-limited'],
      [401, 'unauthorized'],
    ] as const) {
      const api = new RelayClient({
        baseUrl: BASE,
        fetch: statusOnPull(relay.fetch, status),
        timeoutMs: 2_000,
      });
      const got = await new Messaging(b.session, api).receive(b.peerId);
      expect(got.listed, `status ${status}`).toBe(1);
      expect(got.accepted, `status ${status}`).toBe(0);
      expect(got.failure?.failure, `status ${status}`).toBe(failure);
      expect(got.interrupted, `status ${status} counted as a possible loss`).toBe(0);
    }

    // The conservative half, unchanged: a 5xx could have been chosen after the delete.
    const brokenApi = new RelayClient({
      baseUrl: BASE,
      fetch: statusOnPull(relay.fetch, 500),
      timeoutMs: 2_000,
    });
    const broke = await new Messaging(b.session, brokenApi).receive(b.peerId);
    expect(broke.failure?.failure).toBe('server');
    expect(broke.interrupted).toBe(1);

    // THE CLAIM THE REPORT MADE, CHECKED: three refusals later the message is still in the
    // mailbox, so "nothing may have been lost" was true and the screen would have been
    // wrong to say otherwise.
    const after = await b.messaging.receive(b.peerId);
    expect(after.accepted).toBe(1);
    expect(after.interrupted).toBe(0);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'never touched by a refusal',
    ]);
  }, 30_000);

  it('a relay client with a non-finite deadline cannot silently remove the pull floor', async () => {
    // The floor is the smallest of three numbers: the option, half the budget, and the
    // TRANSPORT'S OWN CEILING. The first two go through a guard that refuses a non-finite
    // value; the third did not, and RelayClient does not check its own `timeoutMs` either,
    // so `new RelayClient({timeoutMs: NaN})` arrived here as NaN. One NaN in a Math.min is a
    // NaN floor, and NaN loses every comparison, so `left < floor` is false however spent
    // the budget is: the floor stops existing at exactly the moment it is load bearing.
    //
    // Same shape as the spent-budget test above, because the property at stake is the same
    // one: the list overruns the whole budget, and the pull has to be refused rather than
    // started with a sliver on a link that has just proved slower than that. Measured at the
    // TRANSPORT, since a refused pull and an attempted one both leave accepted=0 behind.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await a.messaging.send(a.peerId, 'still there after a poisoned ceiling');

    const BUDGET = 4_000;
    const clock = budgetClock();
    const stalled: FetchLike = async (url, init) => {
      const response = await relay.fetch(url, init);
      if (isList(url, init.method)) clock.leaveExactly(BUDGET, -1_000);
      return response;
    };
    // NaN, which is what a caller that computed a timeout from a config value can hand over.
    // Nothing else about the pass is unusual: an in-memory link answers before a zero-length
    // deadline can fire, which is why this is decided by the floor and not by the transport.
    const api = new RelayClient({ baseUrl: BASE, fetch: stalled, timeoutMs: Number.NaN });
    const bounded = new Messaging(b.session, api, { receiveBudgetMs: BUDGET });

    const before = relay.calls.length;
    clock.install();
    let got;
    try {
      got = await bounded.receive(b.peerId);
    } finally {
      clock.restore();
    }

    expect(got.listed).toBe(1);
    expect(got.unread).toBe(1);
    expect(got.accepted).toBe(0);
    expect(got.interrupted).toBe(0);
    expect(relay.calls.slice(before).filter((c) => /\/blobs\/bl-/.test(c.url))).toHaveLength(0);

    // Refused, not lost.
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual([
      'still there after a poisoned ceiling',
    ]);
  }, 30_000);
});

describe('the outbox never claims a delivery that did not happen', () => {
  it('a queued record with no wire bytes stays QUEUED, and is never relabelled relayed', async () => {
    // 'relayed' prints "Handed to the relay" under the bubble. For a record the relay never
    // saw, that is a false delivery claim arriving through state instead of through copy,
    // which the honest-copy gate cannot catch. Unreachable from application code today;
    // pinned because the truthful value is the one that is easy to get wrong here.
    const relay = new HostileRelay();
    const { a } = await pairTwo(relay);

    a.session.messages().push({
      peerId: a.peerId,
      direction: 'out',
      timestampMs: Date.now(),
      body: new TextEncoder().encode('never encoded to the wire'),
      delivery: 'queued',
    });

    const before = relay.calls.length;
    const report = await a.messaging.flush(a.peerId);

    expect(report.stuck).toBe(1);
    expect(report.relayed).toBe(0);
    expect(relay.calls.length).toBe(before); // the relay was not contacted
    const record = a.session.messages().find((m) => !m.wire && m.direction === 'out')!;
    expect(record.delivery).toBe('queued');
    expect(report.queued).toBeGreaterThanOrEqual(1);
  });
});

describe('a relay cannot make one mailbox serve both directions', () => {
  it('refuses to link messaging when the peer coordinate equals our own inbox', async () => {
    // A peer signature proves the coordinate came from the peer, not that the relay gave
    // the two devices different boxes. If they collide, this device's own poll pulls its own
    // outbound blob and delete-on-pull destroys it: both sides then sit at "Handed to the
    // relay" and "0 new messages" forever, with nothing on screen to explain it.
    const relay = new HostileRelay();
    const shared = relay.mint();
    const coord = { id: hexBytes(shared.mailboxId), writeCap: shared.writeCap };

    const sessionA = await newSession();
    const sessionB = await newSession();
    const psA = await PairingSession.begin(sessionA.keys(), OWN_CARD_SERIAL, {}, coord);
    const psB = await PairingSession.begin(sessionB.keys(), OWN_CARD_SERIAL, {}, coord);
    const cerA = PairingCeremony.begin(psA, sessionA, 'show-first', {
      id: coord.id,
      pullToken: shared.pullToken,
    });
    const cerB = PairingCeremony.begin(psB, sessionB, 'scan-first', {
      id: coord.id,
      pullToken: shared.pullToken,
    });

    await deliver(cerA, cerB);
    cerA.handOff();
    await deliver(cerB, cerA);
    cerB.handOff();
    await deliver(cerA, cerB);
    cerA.handOff();

    // The identity pairing still succeeds: the humans really did meet, and refusing to pin
    // a key because a server misbehaved would be the wrong trade. Only messaging is refused.
    expect(cerA.view().mailboxLinked).toBe(false);
    expect(cerB.view().mailboxLinked).toBe(false);
    await cerA.confirmMatch();
    const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 2_000 });
    expect(new Messaging(sessionA, api).state(sessionB.identityPublicKey())).toBe('no-mailbox');
  });
});

describe('retry until the relay takes it (R9)', () => {
  it('a refused PUT leaves the message queued, durably, and a later flush sends it once', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);

    relay.lies.status = 507; // relay full
    const first = await a.messaging.send(a.peerId, 'i will keep trying');
    expect(first.relayed).toBe(0);
    expect(first.queued).toBe(1);
    expect(first.failure?.failure).toBe('full');

    // Durable BEFORE the network call, so a crash here does not lose it.
    const stored = decryptVaultBlob((await a.store.load())!, PASSPHRASE);
    expect(stored.messages).toHaveLength(1);
    expect(stored.messages[0]!.delivery).toBe('queued');
    expect(stored.messages[0]!.wire).toBeDefined();

    relay.lies.status = undefined;
    const reborn = await reopen(a, relay);
    const second = await reborn.messaging.flush(reborn.peerId);
    expect(second.relayed).toBe(1);
    expect(second.queued).toBe(0);

    const got = await b.messaging.receive(b.peerId);
    expect(got.accepted).toBe(1);
    expect(text(b.messaging.conversation(b.peerId)[0]!.body)).toBe('i will keep trying');
  });

  it('a flush stops at the first failure so the peer sees them in order', async () => {
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    relay.lies.status = 429;
    const base = Date.now();
    await a.messaging.send(a.peerId, 'first', base + 1);
    await a.messaging.send(a.peerId, 'second', base + 2);
    await a.messaging.send(a.peerId, 'third', base + 3);

    let attempts = 0;
    relay.lies.status = undefined;
    const api = new RelayClient({
      baseUrl: BASE,
      timeoutMs: 2_000,
      fetch: async (url, init) => {
        if (init.method === 'PUT' && ++attempts === 2) {
          return new Response(new TextEncoder().encode('{"error":"rate limited"}'), { status: 429 });
        }
        return relay.fetch(url, init);
      },
    });
    const report = await new Messaging(a.session, api).flush(a.peerId);
    expect(report.relayed).toBe(1);
    expect(report.queued).toBe(2);
    expect(report.failure?.failure).toBe('rate-limited');

    expect((await b.messaging.receive(b.peerId)).accepted).toBe(1);
    expect(text(b.messaging.conversation(b.peerId)[0]!.body)).toBe('first');
  });

  it('a slow relay cannot make the send half cost one deadline per queued message', async () => {
    // THE INVARIANT THE WHOLE BUDGET EXISTS FOR, held on the half that did not have it.
    // ui/app.ts disables the composer for the WHOLE sync and a sync is flush then receive,
    // so an unbounded send half hands the relay the same thing the unbounded receive half
    // did: the right to decide when a person may write. The shape is not a relay that never
    // answers (the first failure ends the pass), it is a relay that answers every push just
    // slowly enough, which costs one deadline per queued record with nothing to stop it.
    //
    // The cost is MEASURED here rather than asserted about: the second pass over the records
    // the first one did not get to is unbudgeted, and it spends one delay on each of them.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);

    const bodies = ['one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight'];
    // Queued the way R9 says they should be: the relay refused each one before it stored
    // anything, so the entry survives with its wire bytes and nothing reached the peer.
    const refusing = new RelayClient({
      baseUrl: BASE,
      fetch: refusePuts(relay.fetch),
      timeoutMs: 2_000,
    });
    const stubborn = new Messaging(a.session, refusing);
    const base = Date.now();
    for (const [at, body] of bodies.entries()) {
      const report = await stubborn.send(a.peerId, body, base + at);
      expect(report.failure?.failure).toBe('server');
    }
    expect((await stubborn.flush(a.peerId)).queued).toBe(bodies.length);

    // FIRST, THE DEADLINE THE PUSH IS GIVEN, which is the half of the budget that is spent
    // rather than merely checked. A relay that accepts the connection and then says nothing
    // costs the budget, not the transport's own 15 second ceiling: without the shortened
    // deadline the pass would sit here for that ceiling before it ever consulted the budget.
    relay.lies.hang = true;
    const api = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 15_000 });
    const hungStarted = Date.now();
    const hung = await new Messaging(a.session, api, { flushBudgetMs: 500 }).flush(a.peerId);
    const hungElapsed = Date.now() - hungStarted;
    expect(hung.relayed).toBe(0);
    expect(hung.queued).toBe(bodies.length);
    expect(hung.failure?.failure).toBe('timeout');
    expect(hungElapsed).toBeLessThan(3_000); // the budget, not the per-request ceiling
    relay.lies.hang = false;

    // Then honest, just slow: 300ms per request, well inside that 15s per-request deadline,
    // which is precisely why the per-request deadline is not the bound that matters here.
    relay.lies.delayMs = 300;
    const bounded = new Messaging(a.session, api, { flushBudgetMs: 1_000 });
    const started = Date.now();
    const got = await bounded.flush(a.peerId);
    const elapsed = Date.now() - started;

    expect(got.relayed).toBeGreaterThanOrEqual(2); // it did make progress
    expect(got.relayed).toBeLessThanOrEqual(4); // and it did not spend eight deadlines
    expect(got.queued).toBe(bodies.length - got.relayed);
    expect(got.failure?.failure).toBe('timeout');
    expect(elapsed).toBeLessThan(1_600); // one budget plus one delay plus slack

    // THE COST THE BUDGET IS AGAINST, on the same relay and the same records: unbudgeted,
    // the pass spends one delay per record it offers. That is the number the bound above is
    // meaningful against, and it is measured rather than assumed.
    const unbudgeted = new Messaging(a.session, api, { flushBudgetMs: 120_000 });
    const restStarted = Date.now();
    const rest = await unbudgeted.flush(a.peerId);
    const restElapsed = Date.now() - restStarted;
    expect(rest.relayed).toBe(bodies.length - got.relayed);
    expect(rest.queued).toBe(0);
    expect(restElapsed).toBeGreaterThan((rest.relayed - 1) * 300);

    // AND NOTHING WAS LOST BY STOPPING EARLY, which is why the send half needs no floor: an
    // abandoned push leaves the record queued, and the next pass offers it again.
    relay.lies.delayMs = undefined;
    const collected = await b.messaging.receive(b.peerId);
    expect(collected.accepted).toBe(bodies.length);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual(bodies);
  }, 30_000);

  it('a budget spent between two offers stops the pass instead of opening another request', async () => {
    // THE GUARD ITSELF, which the test above does not reach. That test proves the budget
    // BOUNDS the pass; this one proves the check that ends it is the thing doing it. Disabling
    // `offered > 0 && left <= 0` leaves this whole file green otherwise, because every push is
    // handed what is left of the budget as its own deadline: on an ordinary slow link the
    // deadline shrinks below what the relay needs before the budget reaches zero, so the loop
    // always leaves through the catch underneath, on a transport timeout. Both exits report
    // `timeout` and the same counts. They differ in the SENTENCE they carry and in whether a
    // request was made at all, so both of those are asserted here.
    //
    // WHAT SPENDS A BUDGET WHILE THE PUSHES ARE STILL SUCCEEDING is time that no deadline
    // bounds: a frozen tab, a suspended laptop, an event loop that came back late. The first
    // push is answered, the machine stops, and the pass discovers on the next record that the
    // budget it was spending is gone. Expressed as arithmetic on the monotonic clock the
    // budget is measured with (budgetClock), so the moment under test is exact rather than
    // raced for, and the relay is left able to answer, which is what makes the negative
    // control meaningful: without the guard the pass really does open the next request.
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);

    const bodies = ['one', 'two', 'three', 'four'];
    // Queued the way R9 says they should be: refused before the relay stored anything, so
    // every entry survives with its wire bytes and nothing reached the peer.
    const refusing = new RelayClient({
      baseUrl: BASE,
      fetch: refusePuts(relay.fetch),
      timeoutMs: 2_000,
    });
    const stubborn = new Messaging(a.session, refusing);
    const base = Date.now();
    for (const [at, body] of bodies.entries()) {
      expect((await stubborn.send(a.peerId, body, base + at)).failure?.failure).toBe('server');
    }
    expect((await stubborn.flush(a.peerId)).queued).toBe(bodies.length);

    // A budget well under the transport's own ceiling, so what bounds each push is the budget
    // and not the client's 15 seconds, and a relay that ANSWERS every push rather than one
    // that hangs: a relay that says nothing costs one deadline and ends the pass at its first
    // failure, which never reaches this guard at all.
    const BUDGET = 1_000;
    const clock = budgetClock();
    let puts = 0;
    relay.lies.delayMs = 200; // slow enough that a sliver of a deadline is a real abort
    const stalling: FetchLike = async (url, init) => {
      const response = await relay.fetch(url, init);
      // Half a second past the end of the budget, at the moment the first push is answered.
      if (init.method === 'PUT' && ++puts === 1) clock.leaveExactly(BUDGET, -500);
      return response;
    };
    const api = new RelayClient({ baseUrl: BASE, fetch: stalling, timeoutMs: 15_000 });
    const bounded = new Messaging(a.session, api, { flushBudgetMs: BUDGET });

    const before = relay.calls.length;
    clock.install();
    let got;
    try {
      got = await bounded.flush(a.peerId);
    } finally {
      clock.restore();
    }

    expect(got.relayed).toBe(1);
    expect(got.queued).toBe(bodies.length - 1);
    expect(got.stuck).toBe(0);
    expect(got.failure?.failure).toBe('timeout');
    // AT THE TRANSPORT FIRST, which is the half a report cannot show: the record that was not
    // offered was not offered. Without the guard the request goes out anyway with a
    // one millisecond deadline, and the relay records the call before aborting it.
    expect(relay.calls.slice(before).filter((c) => c.method === 'PUT')).toHaveLength(1);
    // THEN THE SENTENCE ONLY THIS GUARD BUILDS. The transport's own deadline says "no answer
    // inside the deadline"; this one names the pass rather than the relay, because the relay
    // may have answered everything it was asked and simply not been asked again.
    expect(got.failure?.message).toBe(
      'relay: the pass ran out of time before every queued message was offered',
    );

    // NOTHING WAS LOST BY STOPPING, which is why the send half needs no floor: what was not
    // offered still has its bytes, and the next pass hands it over.
    relay.lies.delayMs = undefined;
    const honest = new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs: 15_000 });
    const rest = await new Messaging(a.session, honest).flush(a.peerId);
    expect(rest.relayed).toBe(bodies.length - 1);
    expect(rest.queued).toBe(0);
    expect((await b.messaging.receive(b.peerId)).accepted).toBe(bodies.length);
    expect(b.messaging.conversation(b.peerId).map((m) => text(m.body))).toEqual(bodies);
  }, 30_000);

  it('the shipped defaults ask the transport for the same deadlines a budget-free pass did', async () => {
    // A BUDGET ON THE PATH EVERY MESSAGE TAKES has to be shown not to have moved the ordinary
    // case, and no report field or elapsed time can show that: the deadline is not in the
    // request. It is read where it is set instead (deadlineRecorder), one number per call.
    //
    // What the shipped pair guarantees: FLUSH_BUDGET_MS is not smaller than the transport's
    // own per-request deadline, so the ordinary send, which is one put, is handed what it
    // was handed before there was a budget at all. The relation is pinned, not the numbers.
    expect(FLUSH_BUDGET_MS).toBeGreaterThanOrEqual(DEFAULT_TIMEOUT_MS);

    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    await b.messaging.send(b.peerId, 'waiting for a');
    await b.messaging.send(b.peerId, 'and another');

    const refusing = new RelayClient({
      baseUrl: BASE,
      fetch: refusePuts(relay.fetch),
      timeoutMs: 2_000,
    });
    const stubborn = new Messaging(a.session, refusing);
    await stubborn.send(a.peerId, 'queued one');
    await stubborn.send(a.peerId, 'queued two');

    const recorder = deadlineRecorder(relay.fetch);
    // Shipped defaults, both sides: no timeoutMs on the client, no options on Messaging.
    const shipped = new Messaging(
      a.session,
      new RelayClient({ baseUrl: BASE, fetch: recorder.fetch }),
    );
    recorder.install();
    let report;
    try {
      report = await shipped.sync(a.peerId);
    } finally {
      recorder.restore();
    }

    expect(report.flush.relayed).toBe(2);
    expect(report.receive.accepted).toBe(2);
    expect(recorder.seen.map((s) => s.kind)).toEqual(['put', 'put', 'list', 'pull', 'pull']);

    // THE READ HALF IS UNTOUCHED: both phases are still capped by the transport's own
    // ceiling, to the millisecond.
    for (const entry of recorder.seen.filter((s) => s.kind !== 'put')) {
      expect(entry.deadlineMs, entry.kind).toBe(DEFAULT_TIMEOUT_MS);
    }
    // AND THE WRITE HALF IS ASKED FOR THE CEILING TOO, short only by the milliseconds the
    // pass has actually spent. Before the budget every put was asked for exactly the
    // ceiling; the difference on an honest link is this margin and nothing else.
    for (const entry of recorder.seen.filter((s) => s.kind === 'put')) {
      expect(entry.deadlineMs).toBeLessThanOrEqual(DEFAULT_TIMEOUT_MS);
      expect(entry.deadlineMs).toBeGreaterThan(DEFAULT_TIMEOUT_MS - 100);
    }
  }, 30_000);
});

/** A session's own signed card, as bytes, so a test can seal something to it. */
async function cardBytesOf(session: KeyweaveSession): Promise<Uint8Array> {
  return createSignedCard(session.keys(), OWN_CARD_SERIAL);
}

// ---------------------------------------------------------------------------
// The vault locking part way through a receive, which used to destroy a message.
// ---------------------------------------------------------------------------

/**
 * How long the vault under test sits idle before it empties itself. Short so the test does
 * not wait, and the real IDLE_LOCK_MS is not the subject here: what is under test is what a
 * pass does once the vault HAS locked, and the timer is only how it gets there.
 */
const SHORT_IDLE_MS = 40;

/**
 * A relay that holds its LIST until this test says otherwise, and that deletes a blob as it
 * hands it over, which is the property the whole defect turns on
 * (relay/keyweave_relay.py pull_blob removes inside the critical section, before the bytes
 * reach the wire, so a pull is not a retryable read).
 *
 * A stand-in rather than the real RelayClient over a fake fetch, for the reason
 * app-conversation.test.ts gives about the same kind of question: this is about the WINDOW
 * in which a pass has started and not finished, and a real client puts a Response body and
 * its own deadline timer between the test and that moment. Everything else here is real:
 * two paired sessions, real cards, a real sealed envelope, a real vault with a real idle
 * timer.
 */
class StallingRelay {
  /** Read by the Messaging constructor to cap its own pull floor. */
  readonly requestCeilingMs = 15_000;
  listCalls = 0;
  pullCalls = 0;
  /** While true, a list resolves only when releaseList() is called. */
  holdLists = false;

  private readonly boxes = new Map<string, Map<string, Uint8Array>>();
  private release: (() => void) | undefined;

  async putBlob(mailboxId: string, _cap: string, bytes: Uint8Array): Promise<BlobSummary> {
    const box = this.box(mailboxId);
    const blobId = `bl-20260809T12000${box.size}Z.00000000000${box.size}`;
    box.set(blobId, Uint8Array.from(bytes));
    return { blobId, size: bytes.length };
  }

  async listBlobs(mailboxId: string): Promise<BlobSummary[]> {
    this.listCalls++;
    const answer = () =>
      [...this.box(mailboxId)].map(([blobId, bytes]) => ({ blobId, size: bytes.length }));
    if (!this.holdLists) return answer();
    return new Promise<BlobSummary[]>((resolve) => {
      this.release = () => resolve(answer());
    });
  }

  releaseList(): void {
    const release = this.release;
    this.release = undefined;
    release?.();
  }

  async pullBlob(mailboxId: string, blobId: string): Promise<Uint8Array | null> {
    this.pullCalls++;
    const box = this.box(mailboxId);
    const bytes = box.get(blobId) ?? null;
    // DELETED BEFORE THE BYTES GO ANYWHERE, exactly as the shipped relay does it. This is
    // what makes an unnecessary pull a destroyed message rather than a wasted request.
    box.delete(blobId);
    return bytes;
  }

  /** Blobs still in a mailbox, i.e. still collectable by a later refresh. */
  waiting(mailboxId: string): number {
    return this.box(mailboxId).size;
  }

  private box(mailboxId: string): Map<string, Uint8Array> {
    let box = this.boxes.get(mailboxId);
    if (!box) {
      box = new Map();
      this.boxes.set(mailboxId, box);
    }
    return box;
  }
}

/** RelayClient has private fields, so a structural stand-in needs the cast once, here. */
const asStallingRelay = (fixture: StallingRelay): RelayClient =>
  fixture as unknown as RelayClient;

/** Wait for a real timer to have fired, without pinning how long the box took to get there. */
async function until(ready: () => boolean, limitMs = 5_000): Promise<void> {
  const deadline = Date.now() + limitMs;
  while (!ready() && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe('a vault that locks mid pass destroys nothing', () => {
  it('a lock while the LIST is held stops the pass before any pull, and the blob survives', async () => {
    // MEASURED ON THIS SOURCE BEFORE THE FIX, and the numbers are why the fix is where it
    // is: the pass RESOLVED with {listed: 1, accepted: 0, unopenable: 1}, pullCalls was 1,
    // and the mailbox was empty afterwards. That is a message permanently destroyed,
    // counted under the one label messaging.ts documents as relay noise rather than the
    // peer, and printed by no summary anywhere, so the person was told "0 new messages."
    const relay = new HostileRelay();
    const { a, b } = await pairTwo(relay);
    const stub = new StallingRelay();

    // One real sealed message from B, waiting in the box A reads.
    await new Messaging(b.session, asStallingRelay(stub)).send(b.peerId, 'the ferry leaves at six');
    expect(stub.waiting(a.inboxId)).toBe(1); // control: there is something to lose

    // A, reopened from its own bytes with an idle lock short enough to drive.
    const sessionA = await KeyweaveSession.unlock(
      new LocalVaultCrypto(ARGON2_FLOOR),
      a.store,
      PASSPHRASE,
      { idleMs: SHORT_IDLE_MS },
    );
    stub.holdLists = true;
    const pass = new Messaging(sessionA, asStallingRelay(stub)).receive(a.peerId);

    // CONTROLS, and the test says nothing without them: the pass really is in flight, and
    // it is in flight on a vault that is still open, so what follows is a lock landing
    // DURING the pass rather than one that had already happened when it started.
    expect(stub.listCalls).toBe(1);
    expect(sessionA.isLocked()).toBe(false);
    await until(() => sessionA.isLocked());
    expect(sessionA.isLocked()).toBe(true);

    // Attached before the release so the rejection is never momentarily unhandled.
    const outcome = pass.then(
      () => 'resolved' as const,
      (error: unknown) => error,
    );
    stub.releaseList();
    const failure = await outcome;

    // The pass says what happened instead of handing back a report that reads like an
    // ordinary empty refresh. ui/app.ts only stops repainting on a THROW.
    expect(failure).toBeInstanceOf(MessagingError);
    expect((failure as MessagingError).state).toBe('locked');

    // THE DISCRIMINATING ASSERTION. Not "the pull failed" and not "the report said so": the
    // request was never made, which is the only outcome under delete-on-pull in which the
    // message still exists.
    expect(stub.pullCalls).toBe(0);
    // And the consequence, at the relay rather than in this device's report: the blob is
    // still in the mailbox, so the next refresh after an unlock collects it.
    expect(stub.waiting(a.inboxId)).toBe(1);
  });
});
