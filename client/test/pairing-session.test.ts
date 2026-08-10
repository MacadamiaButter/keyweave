// The pairing ceremony's crypto seam, driven end to end with two real key managers and
// nothing mocked between them. The optical hop is exercised for real: every payload goes
// out as frames and comes back through a receiver that holds no key material.
//
// The R14 wire assertions live with the rest of the patent firewall in
// optical-patent-invariant.test.ts. What is here is the protocol: three turns, six
// payloads, and the refusals.

import { describe, it, expect } from 'vitest';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard } from '../src/card.js';
import { ED25519_SIG_LEN, PAIR_NONCE_LEN } from '../src/constants.js';
import { OpticalReceiver, type CardFrameStream } from '../src/optical.js';
import {
  PairingSession,
  classifyPairingPayload,
  startCardBroadcast,
  startProofBroadcast,
} from '../src/pairing-session.js';
import { decodePairingInfo, encodePairingInfo } from '../src/mailbox.js';

/** Read a stream the way a camera does: frame by frame, through a keyless receiver. */
function readStream(stream: CardFrameStream): Uint8Array {
  const rx = new OpticalReceiver();
  for (let seq = 0; seq < 400; seq++) {
    const status = rx.feed(stream.frame(seq));
    if (status.kind === 'complete') return status.payload;
  }
  throw new Error('test: the stream never completed');
}

async function twoSessions(): Promise<{ a: PairingSession; b: PairingSession }> {
  const alice = await generateKeyManager('noble');
  const bob = await generateKeyManager('noble');
  return {
    a: await PairingSession.begin(alice.manager),
    b: await PairingSession.begin(bob.manager),
  };
}

describe('payload discrimination', () => {
  it('a bare nonce is 32 bytes and a proof is 64', () => {
    expect(classifyPairingPayload(new Uint8Array(PAIR_NONCE_LEN))).toBe('nonce');
    expect(classifyPairingPayload(new Uint8Array(ED25519_SIG_LEN))).toBe('proof');
  });

  it('the info payload is discriminated by its tag, and is never a fixed-length kind', () => {
    // The nonce now travels inside `info`, whose length varies with the capability token, so
    // it cannot be a length rule. What IS asserted is that adding the kind moved nothing:
    // an info payload is never 32 or 64 bytes, so the two length rules still fire first for
    // exactly the populations they always did.
    const info = encodePairingInfo(new Uint8Array(PAIR_NONCE_LEN).fill(3));
    expect(classifyPairingPayload(info)).toBe('info');
    expect(info.length).not.toBe(PAIR_NONCE_LEN);
    expect(info.length).not.toBe(ED25519_SIG_LEN);
    // And the tag is not something a card can start with.
    expect(classifyPairingPayload(new Uint8Array([0xa2, 0x00, 0x58, 0x4c, 1, 2]))).toBe('card');
  });

  it('a real signed card can be neither, which is what makes length sufficient', async () => {
    // The whole discriminator rests on this. If a card could ever be 32 or 64 bytes the
    // scanner would mislabel it, so the property is asserted rather than assumed.
    const alice = await generateKeyManager('noble');
    for (const serial of [0, 1, 42, 65535, Number.MAX_SAFE_INTEGER]) {
      const card = await createSignedCard(alice.manager, serial);
      expect(card.length).not.toBe(PAIR_NONCE_LEN);
      expect(card.length).not.toBe(ED25519_SIG_LEN);
      expect(classifyPairingPayload(card)).toBe('card');
    }
  });

  it('the non-card payloads refuse a body of the wrong size', () => {
    expect(() => encodePairingInfo(new Uint8Array(31))).toThrow(/nonce is not 32 bytes/);
    expect(() => startProofBroadcast(new Uint8Array(65))).toThrow(/proof is 64 bytes/);
  });
});

describe('the three-turn ceremony', () => {
  it('both sides reach the same six words, over the real optical hop', async () => {
    const { a, b } = await twoSessions();

    // Turn 1: A shows card and nonce, B reads both.
    b.acceptPeerCard(readStream(a.cardFrames));
    b.acceptPeerInfo(readStream(a.infoFrames));

    // B can now sign the transcript, so turn 2 carries its card, nonce and proof.
    const proofFramesB = await b.prove();
    a.acceptPeerCard(readStream(b.cardFrames));
    a.acceptPeerInfo(readStream(b.infoFrames));
    a.acceptPeerProof(readStream(proofFramesB));

    const outcomeA = await a.finalize();
    expect(outcomeA.ok).toBe(true);
    if (!outcomeA.ok) return;

    // Turn 3: A shows its proof, B reads it and finalizes.
    b.acceptPeerProof(readStream(a.proofFrames()));
    const outcomeB = await b.finalize();
    expect(outcomeB.ok).toBe(true);
    if (!outcomeB.ok) return;

    expect(outcomeA.safetyNumber.words).toEqual(outcomeB.safetyNumber.words);
    expect(outcomeA.safetyNumber.words).toHaveLength(6);
    expect(outcomeA.safetyNumber.hex).toBe(outcomeB.safetyNumber.hex);
    // Order independence is the point of sorting the transcript: neither side is "first".
    expect(Buffer.from(outcomeA.transcript).equals(Buffer.from(outcomeB.transcript))).toBe(true);
  });

  it('two independent ceremonies between the same people give different words', async () => {
    // The nonces are fresh per session and the DH is folded in, so a recording of one
    // ceremony is not a script for the next one.
    const wordsOf = async () => {
      const { a, b } = await twoSessions();
      b.acceptPeerCard(readStream(a.cardFrames));
      b.acceptPeerInfo(readStream(a.infoFrames));
      const proofB = await b.prove();
      a.acceptPeerCard(readStream(b.cardFrames));
      a.acceptPeerInfo(readStream(b.infoFrames));
      a.acceptPeerProof(readStream(proofB));
      const outcome = await a.finalize();
      return outcome.ok ? outcome.safetyNumber.hex : 'refused';
    };
    expect(await wordsOf()).not.toBe(await wordsOf());
  });

  it('a nonce swapped between sessions makes the two sides disagree', async () => {
    // A tampered or substituted nonce does not merely fail a signature, it changes the
    // transcript, which is what makes the words the thing worth comparing out loud.
    const { a, b } = await twoSessions();
    const stranger = await PairingSession.begin((await generateKeyManager('noble')).manager);

    b.acceptPeerCard(readStream(a.cardFrames));
    b.acceptPeerInfo(readStream(stranger.infoFrames)); // not A's nonce
    const proofB = await b.prove();
    a.acceptPeerCard(readStream(b.cardFrames));
    a.acceptPeerInfo(readStream(b.infoFrames));
    a.acceptPeerProof(readStream(proofB));

    const outcome = await a.finalize();
    // B signed a different transcript, so A's verification of B's proof fails outright.
    expect(outcome.ok).toBe(false);
  });
});

describe('refusals', () => {
  it('our own card presented back at us throws rather than pairing', async () => {
    const alice = await generateKeyManager('noble');
    const session = await PairingSession.begin(alice.manager);
    expect(() => session.acceptPeerCard(session.cardBytes)).toThrow(/equals our own/);
  });

  it('a card with a flipped byte throws', async () => {
    const { a, b } = await twoSessions();
    const bytes = readStream(b.cardFrames);
    bytes[bytes.length - 1] ^= 0x01;
    expect(() => a.acceptPeerCard(bytes)).toThrow();
  });

  it('a wrong proof is refused, and no safety number is reachable', async () => {
    const { a, b } = await twoSessions();
    b.acceptPeerCard(readStream(a.cardFrames));
    b.acceptPeerInfo(readStream(a.infoFrames));
    await b.prove();
    a.acceptPeerCard(readStream(b.cardFrames));
    a.acceptPeerInfo(readStream(b.infoFrames));
    a.acceptPeerProof(new Uint8Array(ED25519_SIG_LEN)); // all zero, a valid-length forgery

    const outcome = await a.finalize();
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.reason).toMatch(/proof-of-possession/);
    // And the type has no branch that could have handed a caller words anyway.
    expect('safetyNumber' in outcome).toBe(false);
  });

  it('finalizing before the peer parts are in is an error, not an empty pairing', async () => {
    const { a, b } = await twoSessions();
    await expect(a.finalize()).rejects.toThrow(/peer card not scanned/);
    a.acceptPeerCard(readStream(b.cardFrames));
    await expect(a.finalize()).rejects.toThrow(/peer nonce not scanned/);
    a.acceptPeerInfo(readStream(b.infoFrames));
    await expect(a.finalize()).rejects.toThrow(/peer proof not scanned/);
  });

  it('a proof stream is unavailable until there is something to prove', async () => {
    const { a } = await twoSessions();
    expect(() => a.proofFrames()).toThrow(/no proof to broadcast/);
  });
});

describe('what goes on the wire', () => {
  it('the info payload and the proof are plaintext on the wire too', async () => {
    // The card has its own arm in the patent firewall. The other two payloads are public
    // by construction, and this is the check that keeps them that way: the info payload is
    // parsed straight off the wire by a reader holding no key, and the nonce inside it is
    // the one this session generated, byte for byte.
    const { a, b } = await twoSessions();
    const onTheWire = decodePairingInfo(readStream(a.infoFrames));
    expect(Buffer.from(onTheWire.nonce).equals(Buffer.from(a.nonce))).toBe(true);
    expect(onTheWire.mailbox).toBeUndefined();

    b.acceptPeerCard(readStream(a.cardFrames));
    b.acceptPeerInfo(readStream(a.infoFrames));
    const proofFrames = await b.prove();
    const proof = readStream(proofFrames);
    expect(proof).toHaveLength(ED25519_SIG_LEN);

    a.acceptPeerCard(readStream(b.cardFrames));
    a.acceptPeerInfo(readStream(b.infoFrames));
    a.acceptPeerProof(proof);
    expect((await a.finalize()).ok).toBe(true);
  });

  it('a card stream carries exactly the bytes the entry point returned', async () => {
    const alice = await generateKeyManager('noble');
    const broadcast = await startCardBroadcast(alice.manager, 9);
    expect(Buffer.from(readStream(broadcast.frames)).equals(Buffer.from(broadcast.cardBytes))).toBe(
      true,
    );
  });

  it('the ceremony frames stay small enough to stay a low density symbol', async () => {
    // A card is about 150 bytes at five source blocks, so a frame is header plus about 30.
    // Density is what decides whether this decodes across a table, so it is pinned.
    const { a } = await twoSessions();
    for (const stream of [a.cardFrames, a.infoFrames]) {
      expect(stream.frameBytes).toBeLessThanOrEqual(64);
      expect(stream.k).toBeGreaterThanOrEqual(1);
      expect(stream.k).toBeLessThanOrEqual(8);
    }
  });
});
