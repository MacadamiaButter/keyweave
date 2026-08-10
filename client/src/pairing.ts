// SAS-with-DH pairing (must-fix #2, owner DECISION 1) with MANDATORY proof-of-possession
// (must-fix #6 hardening).
//
// A static SignedCard is a replayable artifact and a safety number over two PUBLIC
// keys proves nothing about possession. So in one optical session we ALSO:
//   - exchange fresh per-session nonces,
//   - each side signs CTX_PAIR || sort(cardA,cardB) || sort(nonceA,nonceB) and
//     verifies the peer's signature (proof of possession of the IDENTITY secret,
//     bound to this session - liveness),
//   - fold the X25519 DH shared secret into the DISPLAYED safety number (proof of
//     possession of the ENCRYPTION secret).
// The safety number is ORDER-INDEPENDENT: min/max over each public key + the
// symmetric DH, so both screens show the same words.
//
// PoP is mandatory IN THE TYPE: runPairing() takes the peer's proof and returns a
// discriminated union - the safety number is reachable ONLY from the proof-verified
// `ok: true` branch. There is no code path that yields a usable safety number without
// a verified peer proof. Callers first compute their own proof with pairingProof()
// (both sides need the other's card+nonce to sign), exchange proofs optically, then
// finalize with runPairing().
//
// Anchor `kerckhoffs`: the entire computation is public; its meaning rests on the
// user comparing the words FACE TO FACE (a compromised bundle can fake them - R1).

import { sha512 } from '@noble/hashes/sha2.js';
import {
  CTX_PAIR,
  CTX_SAS,
  PAIR_NONCE_LEN,
  SAS_BITS,
  SAS_WORD_COUNT,
} from './constants.js';
import { concatBytes, sortPair } from './bytes.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { importCard, type ContactCard } from './card.js';
import { verifyEd25519 } from './validate.js';
import { BIP39_ENGLISH } from './bip39-english.js';
import type { KeyManager } from './keys.js';

export interface SafetyNumber {
  /** The BIP-39 words shown to the user for face-to-face comparison. */
  readonly words: string[];
  /** The leading SAS bits, hex, for logging/tests (NOT for display). */
  readonly hex: string;
}

/**
 * Result of a pairing ceremony. The safety number is ONLY present on the `ok: true`
 * branch, which is only reachable when the peer's proof-of-possession verified.
 */
export type PairingOutcome =
  | {
      readonly ok: true;
      readonly peerCard: ContactCard;
      readonly safetyNumber: SafetyNumber;
      /** Our pairing proof; hand this to the peer over the same optical session. */
      readonly ownProof: Uint8Array;
      /** The exact transcript both sides sign (public). */
      readonly transcript: Uint8Array;
    }
  | { readonly ok: false; readonly reason: string };

export function newPairingNonce(): Uint8Array {
  return randomBytes(PAIR_NONCE_LEN);
}

/** The exact order-independent transcript both sides sign for proof-of-possession. */
export function pairingTranscript(
  ownSignedCardBytes: Uint8Array,
  ownNonce: Uint8Array,
  peerSignedCardBytes: Uint8Array,
  peerNonce: Uint8Array,
): Uint8Array {
  if (ownNonce.length !== PAIR_NONCE_LEN || peerNonce.length !== PAIR_NONCE_LEN) {
    throw new Error('pairing: bad nonce length');
  }
  const [cardLo, cardHi] = sortPair(ownSignedCardBytes, peerSignedCardBytes);
  const [nonceLo, nonceHi] = sortPair(ownNonce, peerNonce);
  return concatBytes(CTX_PAIR, cardLo, cardHi, nonceLo, nonceHi);
}

/**
 * Phase 1: compute OUR proof-of-possession for this session (both sides run this and
 * exchange the resulting proofs optically before finalizing).
 */
export async function pairingProof(
  km: KeyManager,
  ownSignedCardBytes: Uint8Array,
  ownNonce: Uint8Array,
  peerSignedCardBytes: Uint8Array,
  peerNonce: Uint8Array,
): Promise<{ transcript: Uint8Array; ownProof: Uint8Array }> {
  const transcript = pairingTranscript(ownSignedCardBytes, ownNonce, peerSignedCardBytes, peerNonce);
  return { transcript, ownProof: await km.sign(transcript) };
}

/**
 * Phase 2 (finalize): strictly validate the peer card, REQUIRE a valid peer
 * proof-of-possession, and only then derive the displayed safety number. A forged or
 * self card throws; a valid card with a bad/absent proof returns `{ ok: false }`.
 */
export async function runPairing(
  km: KeyManager,
  ownSignedCardBytes: Uint8Array,
  ownNonce: Uint8Array,
  peerSignedCardBytes: Uint8Array,
  peerNonce: Uint8Array,
  peerProof: Uint8Array,
): Promise<PairingOutcome> {
  const ownIdentityPub = km.identityPublicKey();
  const ownEncryptionPub = km.encryptionPublicKey();

  // Strictly validate the peer card; rejects self-pairing and all forgeries (throws).
  const peerCard = importCard(peerSignedCardBytes, {
    ownIdentityPub,
    ownEncryptionPub,
  });

  const transcript = pairingTranscript(ownSignedCardBytes, ownNonce, peerSignedCardBytes, peerNonce);

  // MANDATORY proof-of-possession: no safety number without a verified peer proof.
  if (!verifyEd25519(peerProof, transcript, peerCard.identityPub)) {
    return { ok: false, reason: 'peer proof-of-possession failed' };
  }

  const ownProof = await km.sign(transcript);
  const safetyNumber = deriveSafetyNumber(
    ownIdentityPub,
    peerCard.identityPub,
    ownEncryptionPub,
    peerCard.encryptionPub,
    await km.dh(peerCard.encryptionPub),
  );

  return { ok: true, peerCard, safetyNumber, ownProof, transcript };
}

export function deriveSafetyNumber(
  ownIdentityPub: Uint8Array,
  peerIdentityPub: Uint8Array,
  ownEncryptionPub: Uint8Array,
  peerEncryptionPub: Uint8Array,
  dh: Uint8Array,
): SafetyNumber {
  const [idLo, idHi] = sortPair(ownIdentityPub, peerIdentityPub);
  const [xLo, xHi] = sortPair(ownEncryptionPub, peerEncryptionPub);
  const digest = sha512(concatBytes(CTX_SAS, idLo, idHi, xLo, xHi, dh));
  return { words: bitsToWords(digest), hex: toHexBits(digest, SAS_BITS) };
}

// Read SAS_WORD_COUNT big-endian 11-bit chunks from the leading bits of `digest`.
// 6 words * 11 bits = 66 bits, drawn from the first 9 bytes.
function bitsToWords(digest: Uint8Array): string[] {
  const words: string[] = [];
  let acc = 0;
  let bits = 0;
  let byteIdx = 0;
  for (let w = 0; w < SAS_WORD_COUNT; w++) {
    while (bits < 11) {
      acc = (acc << 8) | digest[byteIdx++]!;
      bits += 8;
    }
    bits -= 11;
    const idx = (acc >>> bits) & 0x7ff; // top 11 unconsumed bits
    words.push(BIP39_ENGLISH[idx]!);
  }
  return words;
}

function toHexBits(digest: Uint8Array, totalBits: number): string {
  const nBytes = Math.ceil(totalBits / 8);
  let s = '';
  for (let i = 0; i < nBytes; i++) s += digest[i]!.toString(16).padStart(2, '0');
  return s;
}
