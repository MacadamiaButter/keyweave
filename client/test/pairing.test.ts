import { describe, it, expect } from 'vitest';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard } from '../src/card.js';
import {
  deriveSafetyNumber,
  newPairingNonce,
  pairingProof,
  pairingTranscript,
  runPairing,
} from '../src/pairing.js';
import { bytesEqual } from '../src/bytes.js';

async function twoParties() {
  const A = await generateKeyManager('noble');
  const B = await generateKeyManager('noble');
  const cardA = await createSignedCard(A.manager, 1);
  const cardB = await createSignedCard(B.manager, 1);
  return { A, B, cardA, cardB };
}

describe('SAS-with-DH pairing', () => {
  it('both sides derive the SAME safety number (order-independent), after mutual PoP', async () => {
    const { A, B, cardA, cardB } = await twoParties();
    const nA = newPairingNonce();
    const nB = newPairingNonce();
    // Phase 1: each computes its own proof and exchanges it optically.
    const pA = await pairingProof(A.manager, cardA, nA, cardB, nB);
    const pB = await pairingProof(B.manager, cardB, nB, cardA, nA);
    // Phase 2: finalize with the peer's proof.
    const rA = await runPairing(A.manager, cardA, nA, cardB, nB, pB.ownProof);
    const rB = await runPairing(B.manager, cardB, nB, cardA, nA, pA.ownProof);
    expect(rA.ok && rB.ok).toBe(true);
    if (rA.ok && rB.ok) {
      expect(rA.safetyNumber.words).toEqual(rB.safetyNumber.words);
      expect(rA.safetyNumber.words).toHaveLength(6);
      for (const w of rA.safetyNumber.words) expect(typeof w).toBe('string');
    }
  });

  it('FP(A,B) == FP(B,A) as a pure function (explicit order swap)', async () => {
    const { A, B } = await twoParties();
    const dh = await A.manager.dh(B.manager.encryptionPublicKey());
    const dh2 = await B.manager.dh(A.manager.encryptionPublicKey());
    expect(bytesEqual(dh, dh2)).toBe(true);
    const fp1 = deriveSafetyNumber(
      A.manager.identityPublicKey(),
      B.manager.identityPublicKey(),
      A.manager.encryptionPublicKey(),
      B.manager.encryptionPublicKey(),
      dh,
    );
    const fp2 = deriveSafetyNumber(
      B.manager.identityPublicKey(),
      A.manager.identityPublicKey(),
      B.manager.encryptionPublicKey(),
      A.manager.encryptionPublicKey(),
      dh2,
    );
    expect(fp1.words).toEqual(fp2.words);
  });

  it('[fix3a] holding the encryption pubkeys FIXED, swapping ONLY the DH value changes the words', async () => {
    // Pins the DH fold: if the DH term were removed from the safety number, these two would
    // be identical and this test would fail.
    const { A, B } = await twoParties();
    const idA = A.manager.identityPublicKey();
    const idB = B.manager.identityPublicKey();
    const xA = A.manager.encryptionPublicKey();
    const xB = B.manager.encryptionPublicKey();
    const dh1 = new Uint8Array(32).fill(1);
    const dh2 = new Uint8Array(32).fill(2);
    const fp1 = deriveSafetyNumber(idA, idB, xA, xB, dh1);
    const fp2 = deriveSafetyNumber(idA, idB, xA, xB, dh2);
    expect(fp1.words).not.toEqual(fp2.words);
  });

  it('[fix3b] holding the DH FIXED, swapping ONLY one encryption pubkey changes the words', async () => {
    // Pins the x_pub fold: if both x_pubs were removed from the safety number, these two
    // would be identical and this test would fail.
    const { A, B } = await twoParties();
    const evil = await generateKeyManager('noble');
    const idA = A.manager.identityPublicKey();
    const idB = B.manager.identityPublicKey();
    const xA = A.manager.encryptionPublicKey();
    const xB = B.manager.encryptionPublicKey();
    const dh = new Uint8Array(32).fill(3); // held constant
    const fpReal = deriveSafetyNumber(idA, idB, xA, xB, dh);
    const fpSub = deriveSafetyNumber(idA, idB, xA, evil.manager.encryptionPublicKey(), dh);
    expect(fpReal.words).not.toEqual(fpSub.words);
  });

  it('[fix3c] a runPairing MITM substituting its own encryption key makes the two sides\' words DIVERGE', async () => {
    // The full interposer, driven through runPairing(): A pairs with M believing M is B,
    // B pairs with M believing M is A. M holds its own keys so PoP passes on both legs, but
    // the DH-folded safety numbers differ -> a face-to-face word compare catches the MITM.
    const { A, B } = await twoParties();
    const M = await generateKeyManager('noble');
    const cardA = await createSignedCard(A.manager, 1);
    const cardB = await createSignedCard(B.manager, 1);
    const cardM = await createSignedCard(M.manager, 1);
    const nA = newPairingNonce();
    const nMA = newPairingNonce();
    const nB = newPairingNonce();
    const nMB = newPairingNonce();

    const pM_A = await pairingProof(M.manager, cardM, nMA, cardA, nA); // M's proof toward A
    const pM_B = await pairingProof(M.manager, cardM, nMB, cardB, nB); // M's proof toward B
    const rA = await runPairing(A.manager, cardA, nA, cardM, nMA, pM_A.ownProof);
    const rB = await runPairing(B.manager, cardB, nB, cardM, nMB, pM_B.ownProof);

    expect(rA.ok && rB.ok).toBe(true); // both legs verify M's PoP
    if (rA.ok && rB.ok) {
      expect(rA.safetyNumber.words).not.toEqual(rB.safetyNumber.words); // ...but the words diverge
    }
  });

  it('[fix6] runPairing yields NO safety number without a verified peer proof (mandatory PoP)', async () => {
    const { A, B, cardA, cardB } = await twoParties();
    const nA = newPairingNonce();
    const nB = newPairingNonce();
    // A bogus proof -> ok:false; the safety number is not even reachable on this branch
    // (discriminated union; TypeScript forbids `bad.safetyNumber`).
    const bogus = new Uint8Array(64).fill(9);
    const bad = await runPairing(A.manager, cardA, nA, cardB, nB, bogus);
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.reason).toMatch(/proof-of-possession/);
    // With B's REAL proof, A gets a safety number.
    const pB = await pairingProof(B.manager, cardB, nB, cardA, nA);
    const good = await runPairing(A.manager, cardA, nA, cardB, nB, pB.ownProof);
    expect(good.ok).toBe(true);
    if (good.ok) expect(good.safetyNumber.words).toHaveLength(6);
  });

  it('a wrong-party proof does not verify (proof-of-possession is bound to this session)', async () => {
    const { A, B, cardA, cardB } = await twoParties();
    const nA = newPairingNonce();
    const nB = newPairingNonce();
    // An unrelated third party's proof is not a valid PoP for B.
    const other = await generateKeyManager('noble');
    const otherCard = await createSignedCard(other.manager, 1);
    const pOther = await pairingProof(other.manager, otherCard, newPairingNonce(), cardA, nA);
    const r = await runPairing(A.manager, cardA, nA, cardB, nB, pOther.ownProof);
    expect(r.ok).toBe(false);
  });

  it('a replayed nonce/session yields a DIFFERENT proof transcript (fresh per session)', async () => {
    const { cardA, cardB } = await twoParties();
    const t1 = pairingTranscript(cardA, newPairingNonce(), cardB, newPairingNonce());
    const t2 = pairingTranscript(cardA, newPairingNonce(), cardB, newPairingNonce());
    expect(Buffer.from(t1).equals(Buffer.from(t2))).toBe(false);
  });

  it('refuses to pair with your own card (self-pairing guard)', async () => {
    const { A, cardA } = await twoParties();
    const bogus = new Uint8Array(64);
    await expect(
      runPairing(A.manager, cardA, newPairingNonce(), cardA, newPairingNonce(), bogus),
    ).rejects.toThrow(/equals our own/);
  });
});
