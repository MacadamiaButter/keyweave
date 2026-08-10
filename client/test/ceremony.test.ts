// The ceremony state machine and the vault caller obligation, driven with two REAL
// sessions: real key managers, a real encrypted vault, real optical frames between them.
// Nothing here is a mock except the blob store, which is in memory so the suite does not
// need IndexedDB.
//
// Argon2id runs at ARGON2_FLOOR here, not ARGON2_DEFAULT. That is a test-speed decision
// and nothing else: the floor is the downgrade wall the vault enforces, the default is
// what the application ships, and vault.test.ts already covers the parameter policy.

import { describe, it, expect } from 'vitest';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard, importCard } from '../src/card.js';
import { ARGON2_FLOOR, decryptVaultBlob } from '../src/vault.js';
import { ContactStore } from '../src/contacts.js';
import { OpticalReceiver, type CardFrameStream } from '../src/optical.js';
import { OWN_CARD_SERIAL, PairingSession } from '../src/pairing-session.js';
import { PairingCeremony } from '../src/ui/ceremony.js';
import { KeyweaveSession } from '../src/ui/session.js';
import { MemoryBlobStore } from '../src/ui/storage.js';
import { LocalVaultCrypto } from '../src/ui/vault-crypto.js';

const PASSPHRASE = 'seven unrelated words make a passable line here';

interface Party {
  crypto: LocalVaultCrypto;
  store: MemoryBlobStore;
  session: KeyweaveSession;
}

async function makeParty(): Promise<Party> {
  const crypto = new LocalVaultCrypto(ARGON2_FLOOR);
  const store = new MemoryBlobStore();
  // idleMs 0 leaves no timer behind; the idle re-lock itself is vault.test.ts's subject.
  const session = await KeyweaveSession.createIdentity(crypto, store, PASSPHRASE, { idleMs: 0 });
  return { crypto, store, session };
}

function readStream(stream: CardFrameStream): Uint8Array {
  const rx = new OpticalReceiver();
  for (let seq = 0; seq < 400; seq++) {
    const status = rx.feed(stream.frame(seq));
    if (status.kind === 'complete') return status.payload;
  }
  throw new Error('test: the stream never completed');
}

/** Point one device camera at the other screen for the whole of what it is showing. */
async function deliver(
  from: PairingCeremony,
  to: PairingCeremony,
  reverse = false,
): Promise<void> {
  const streams = [...from.view().playlist];
  if (reverse) streams.reverse();
  for (const stream of streams) await to.offer(readStream(stream));
}

async function beginPair(
  a: Party,
  b: Party,
  serialB: number = OWN_CARD_SERIAL,
): Promise<{ cerA: PairingCeremony; cerB: PairingCeremony }> {
  const psA = await PairingSession.begin(a.session.keys());
  const psB = await PairingSession.begin(b.session.keys(), serialB);
  return {
    cerA: PairingCeremony.begin(psA, a.session, 'show-first'),
    cerB: PairingCeremony.begin(psB, b.session, 'scan-first'),
  };
}

async function runToCompare(
  a: Party,
  b: Party,
  serialB: number = OWN_CARD_SERIAL,
  reverse = false,
): Promise<{ cerA: PairingCeremony; cerB: PairingCeremony }> {
  const { cerA, cerB } = await beginPair(a, b, serialB);
  await deliver(cerA, cerB, reverse); // turn 1: A shows card and nonce
  cerA.handOff();
  await deliver(cerB, cerA, reverse); // turn 2: B shows card, nonce, proof
  cerB.handOff();
  await deliver(cerA, cerB, reverse); // turn 3: A shows its proof
  cerA.handOff();
  return { cerA, cerB };
}

describe('the ceremony reaches the words', () => {
  it('both roles end on compare with the same six words', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA, cerB } = await runToCompare(a, b);

    expect(cerA.view().phase).toBe('compare');
    expect(cerB.view().phase).toBe('compare');
    expect(cerA.view().words).toHaveLength(6);
    expect(cerA.view().words).toEqual(cerB.view().words);
    expect(cerA.view().step).toBe(3);
    expect(cerB.view().step).toBe(3);
  });

  it('the same holds when payloads arrive out of order', async () => {
    // A camera reads whatever is on screen when it locks on, so arrival order is not the
    // sender's to choose.
    const a = await makeParty();
    const b = await makeParty();
    const { cerA, cerB } = await runToCompare(a, b, OWN_CARD_SERIAL, true);
    expect(cerA.view().words).toEqual(cerB.view().words);
    expect(cerA.view().words).toHaveLength(6);
  });

  it('no words are exposed before the compare screen', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA, cerB } = await beginPair(a, b);
    expect(cerA.view().words).toEqual([]);
    expect(cerB.view().words).toEqual([]);

    await deliver(cerA, cerB);
    // B has both of A's parts and has moved on to showing, still with nothing to compare.
    expect(cerB.view().phase).toBe('show');
    expect(cerB.view().words).toEqual([]);
  });

  it('an unexpected or duplicate payload is ignored, not refused', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA, cerB } = await beginPair(a, b);
    // B expects a card and a nonce; a proof-shaped payload is not part of this turn.
    expect(await cerB.offer(new Uint8Array(64))).toBe('ignored');
    const cardBytes = readStream(cerA.view().playlist[0]!);
    expect(await cerB.offer(cardBytes)).toBe('accepted');
    expect(await cerB.offer(cardBytes)).toBe('duplicate');
    expect(cerB.view().phase).toBe('scan');
  });
});

describe('the idle re-lock', () => {
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  /** A detached copy, so the seeds survive the zeroize that lock() does in place. */
  function sealable(session: KeyweaveSession) {
    const live = session.vault.snapshot();
    return {
      ...live,
      identitySeed: Uint8Array.from(live.identitySeed),
      encryptionSeed: Uint8Array.from(live.encryptionSeed),
    };
  }

  it('forgets the passphrase, not only the vault', async () => {
    // The vault holds seeds; the passphrase lives one layer out, in the crypto seam. A lock
    // that empties one and not the other leaves a worker that can still seal, which is not
    // what "locked" says. Nothing in the UI calls session.lock(), so the timer has to be
    // the thing that reaches forget().
    const crypto = new LocalVaultCrypto(ARGON2_FLOOR);
    const store = new MemoryBlobStore();
    let locks = 0;
    const session = await KeyweaveSession.createIdentity(crypto, store, PASSPHRASE, {
      idleMs: 200,
      onLock: () => {
        locks++;
      },
    });
    const data = sealable(session);

    // POSITIVE CONTROL: while unlocked the crypto seals happily, so a rejection below is
    // forget() having run and not seal() being broken.
    await expect(crypto.seal(data)).resolves.toBeInstanceOf(Uint8Array);

    await sleep(500);
    expect(locks).toBe(1);
    expect(session.isLocked()).toBe(true);
    await expect(crypto.seal(data)).rejects.toThrow('vault-crypto: locked');
  });

  it('an explicit lock does the same thing, so the two paths agree', async () => {
    const crypto = new LocalVaultCrypto(ARGON2_FLOOR);
    const store = new MemoryBlobStore();
    const session = await KeyweaveSession.createIdentity(crypto, store, PASSPHRASE, { idleMs: 0 });
    const data = sealable(session);
    await expect(crypto.seal(data)).resolves.toBeInstanceOf(Uint8Array);

    session.lock();
    expect(session.isLocked()).toBe(true);
    await expect(crypto.seal(data)).rejects.toThrow('vault-crypto: locked');
  });

  it('a locked session refuses the calls the ceremony screens make', async () => {
    // What the UI has to survive: the first thing beginCeremony evaluates is keys(), and
    // commit() is what the compare screen awaits. Both throw once the timer has fired.
    const crypto = new LocalVaultCrypto(ARGON2_FLOOR);
    const store = new MemoryBlobStore();
    const session = await KeyweaveSession.createIdentity(crypto, store, PASSPHRASE, { idleMs: 0 });
    session.lock();
    expect(() => session.keys()).toThrowError('vault: locked');
    expect(() => session.vault.snapshot()).toThrowError('vault: locked');
  });
});

describe('the vault caller obligation', () => {
  it('confirming a match pins the contact AND writes it', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const savesBefore = a.store.saveCount;
    const { cerA } = await runToCompare(a, b);

    await cerA.confirmMatch();
    expect(cerA.view().phase).toBe('paired');
    expect(a.store.saveCount).toBe(savesBefore + 1);

    // Durable, not merely in memory: reopen the stored blob from scratch.
    const blob = await a.store.load();
    const data = decryptVaultBlob(blob!, PASSPHRASE);
    expect(data.contacts).toHaveLength(1);
    const reopened = ContactStore.import(data.contacts);
    expect(reopened.size()).toBe(1);
    expect(reopened.isPinned(b.session.identityPublicKey())).toBe(true);
  });

  it('a pin that never reaches save() is gone (negative control)', async () => {
    // This is why commit() persists rather than leaving it to a later save. Same shape as
    // the replay seen-set: an admit that never reaches a blob did not happen.
    const a = await makeParty();
    const stranger = await generateKeyManager('noble');
    const card = importCard(await createSignedCard(stranger.manager, 1));

    a.session.contacts.pin(card);
    expect(a.session.contacts.size()).toBe(1);

    const data = decryptVaultBlob((await a.store.load())!, PASSPHRASE);
    expect(data.contacts).toHaveLength(0);
    expect(ContactStore.import(data.contacts).size()).toBe(0);
  });

  it('refusing the words pins nothing and writes nothing', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await runToCompare(a, b);
    const savesBefore = a.store.saveCount;

    cerA.confirmMismatch();
    expect(cerA.view().phase).toBe('refused');
    expect(cerA.view().refusal?.title).toMatch(/did not match/);
    // The advice must not send them round the loop again over a network.
    expect(cerA.view().refusal?.advice).toMatch(/Do not retry/);
    expect(a.store.saveCount).toBe(savesBefore);
    expect(a.session.contacts.size()).toBe(0);
  });

  it('a refusal is terminal', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await runToCompare(a, b);
    cerA.confirmMismatch();
    await cerA.confirmMatch(); // ignored: not on the compare screen any more
    cerA.handOff();
    expect(cerA.view().phase).toBe('refused');
    expect(a.session.contacts.size()).toBe(0);
  });
});

describe('refusals inside the ceremony', () => {
  it('a peer that cannot prove possession never reaches the words', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA, cerB } = await beginPair(a, b);

    await deliver(cerA, cerB);
    cerA.handOff();
    // Everything B shows except the proof, which is replaced by a valid-length forgery.
    const [cardB, nonceB] = cerB.view().playlist;
    await cerA.offer(readStream(cardB!));
    await cerA.offer(readStream(nonceB!));
    await cerA.offer(new Uint8Array(64));

    expect(cerA.view().phase).toBe('refused');
    expect(cerA.view().words).toEqual([]);
    expect(cerA.view().refusal?.title).toMatch(/could not prove/);
  });

  it('our own card scanned back at us is refused by name', async () => {
    // A mirror, a second window, or a camera pointed at the wrong screen. Note the card is
    // deterministic for a given key and serial, so this IS the card A is showing.
    const a = await makeParty();
    const b = await makeParty();
    const { cerA, cerB } = await beginPair(a, b);
    const ownCard = cerA.view().playlist[0]!;
    await deliver(cerA, cerB);
    cerA.handOff();

    expect(await cerA.offer(readStream(ownCard))).toBe('refused');
    expect(cerA.view().refusal?.title).toMatch(/your own card/);
    expect(cerA.view().phase).toBe('refused');
  });

  it('a card that fails validation is refused with the validator reason', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA, cerB } = await beginPair(a, b);
    await deliver(cerA, cerB);
    cerA.handOff();

    const bytes = readStream(cerB.view().playlist[0]!);
    bytes[bytes.length - 2] ^= 0x01;
    expect(await cerA.offer(bytes)).toBe('refused');
    expect(cerA.view().refusal?.title).toMatch(/did not verify/);
    expect(cerA.view().phase).toBe('refused');
  });

  it('cancelling says plainly that nothing was saved', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await beginPair(a, b);
    cerA.cancel();
    expect(cerA.view().phase).toBe('refused');
    expect(cerA.view().refusal?.advice).toMatch(/Nothing was saved/);
  });
});

describe('pinning, supersession and rollback', () => {
  it('a higher-serial card is flagged, then replaces the pin after a match', async () => {
    const a = await makeParty();
    const b = await makeParty();

    // A has already pinned B at serial 1, the ordinary way.
    const first = await runToCompare(a, b, 1);
    await first.cerA.confirmMatch();
    expect(a.session.contacts.get(b.session.identityPublicKey())?.serial).toBe(1);
    const savesAfterFirst = a.store.saveCount;

    // B now presents serial 2. contacts.ts calls that a supersession and requires a fresh
    // in-person ceremony, which is exactly what this is.
    const second = await runToCompare(a, b, 2);
    expect(second.cerA.view().supersede).toBe(true);
    expect(second.cerA.view().phase).toBe('compare');

    await second.cerA.confirmMatch();
    expect(second.cerA.view().phase).toBe('paired');
    expect(a.session.contacts.get(b.session.identityPublicKey())?.serial).toBe(2);
    expect(a.store.saveCount).toBe(savesAfterFirst + 1);

    const data = decryptVaultBlob((await a.store.load())!, PASSPHRASE);
    expect(ContactStore.import(data.contacts).get(b.session.identityPublicKey())?.serial).toBe(2);
  });

  it('a rollback is refused as soon as the card is read, before the words', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const first = await runToCompare(a, b, 2);
    await first.cerA.confirmMatch();
    const savesBefore = a.store.saveCount;

    const { cerA, cerB } = await beginPair(a, b, 1);
    await deliver(cerA, cerB);
    cerA.handOff();
    expect(await cerA.offer(readStream(cerB.view().playlist[0]!))).toBe('refused');

    expect(cerA.view().phase).toBe('refused');
    expect(cerA.view().words).toEqual([]);
    expect(cerA.view().refusal?.title).toMatch(/goes backwards/);
    expect(a.store.saveCount).toBe(savesBefore);
    expect(a.session.contacts.get(b.session.identityPublicKey())?.serial).toBe(2);
  });

  it('re-pairing on the identical card is idempotent and still writes', async () => {
    const a = await makeParty();
    const b = await makeParty();
    await (await runToCompare(a, b, 1)).cerA.confirmMatch();
    const savesBefore = a.store.saveCount;

    const again = await runToCompare(a, b, 1);
    expect(again.cerA.view().supersede).toBe(false);
    await again.cerA.confirmMatch();
    expect(again.cerA.view().phase).toBe('paired');
    expect(a.session.contacts.size()).toBe(1);
    // Still saved: a save is also how any replay state admitted this session lands.
    expect(a.store.saveCount).toBe(savesBefore + 1);
  });

  it('the session refuses to commit a rejected status even if asked directly', async () => {
    const a = await makeParty();
    const stranger = await generateKeyManager('noble');
    const card = importCard(await createSignedCard(stranger.manager, 1));
    await expect(a.session.commit(card, 'rejected')).rejects.toThrow(/refusing to commit/);
  });
});
