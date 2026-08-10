// ContactCard: the identity artifact exchanged optically at pairing.
//
// Deterministic CBOR (dCBOR), integer-keyed, versioned, with a monotonic card_serial
// (must-fix #4 supersession). SignedCard = { card_bytes(bstr), sig(64) } where sig is
// over CTX_CARD || card_bytes and is verified over the TRANSPORTED bytes, never a
// re-encode. STRICT IMPORT VALIDATION is must-fix #1: without it a signed card is
// forgeable (see validate.ts).

import {
  CARD_VERSION,
  CARD_VERSION_ALLOWLIST,
  CTX_CARD,
  ED25519_PUB_LEN,
  ED25519_SIG_LEN,
  X25519_PUB_LEN,
} from './constants.js';
import { concatBytes, bytesEqual, assertLength } from './bytes.js';
import { decodeMapExact, encodeDeterministic, getBytes, getUint } from './cbor.js';
import { validateEd25519Pub, validateX25519Pub, verifyEd25519 } from './validate.js';
import type { KeyManager } from './keys.js';

// Card map keys.
const K_VERSION = 0;
const K_IDENTITY_PUB = 1;
const K_ENCRYPTION_PUB = 2;
const K_SERIAL = 3;

// SignedCard map keys.
const SK_CARD = 0;
const SK_SIG = 1;

const MAX_SERIAL = Number.MAX_SAFE_INTEGER;

export interface ContactCard {
  readonly version: number;
  readonly identityPub: Uint8Array; // Ed25519, validated
  readonly encryptionPub: Uint8Array; // X25519, validated
  readonly serial: number;
  /** The exact transported card bytes the signature covers. */
  readonly cardBytes: Uint8Array;
  /** The full SignedCard wire bytes. */
  readonly signedCardBytes: Uint8Array;
}

function buildCardBytes(identityPub: Uint8Array, encryptionPub: Uint8Array, serial: number): Uint8Array {
  const card = new Map<number, unknown>([
    [K_VERSION, CARD_VERSION],
    [K_IDENTITY_PUB, identityPub],
    [K_ENCRYPTION_PUB, encryptionPub],
    [K_SERIAL, serial],
  ]);
  return encodeDeterministic(card);
}

/** Create our own SignedCard (wire bytes) at a given monotonic serial. */
export async function createSignedCard(km: KeyManager, serial: number): Promise<Uint8Array> {
  if (!Number.isInteger(serial) || serial < 0 || serial > MAX_SERIAL) {
    throw new Error('createSignedCard: serial out of range');
  }
  const identityPub = km.identityPublicKey();
  const encryptionPub = km.encryptionPublicKey();
  const cardBytes = buildCardBytes(identityPub, encryptionPub, serial);
  const sig = await km.sign(concatBytes(CTX_CARD, cardBytes));
  assertLength(sig, ED25519_SIG_LEN, 'card sig');
  const signed = new Map<number, unknown>([
    [SK_CARD, cardBytes],
    [SK_SIG, sig],
  ]);
  return encodeDeterministic(signed);
}

export interface ImportOptions {
  ownIdentityPub?: Uint8Array;
  ownEncryptionPub?: Uint8Array;
}

/**
 * Strictly parse + validate a SignedCard from untrusted bytes. Throws on any
 * deviation. On success the card is cryptographically authentic and its keys are
 * canonical, non-small-order, and (if own* provided) not our own.
 */
export function importCard(signedCardBytes: Uint8Array, opts: ImportOptions = {}): ContactCard {
  // 1. Strict decode of the SignedCard envelope.
  const outer = decodeMapExact(signedCardBytes, {
    [SK_CARD]: { type: 'bytes' },
    [SK_SIG]: { type: 'bytes', len: ED25519_SIG_LEN },
  });
  const cardBytes = getBytes(outer, SK_CARD);
  const sig = getBytes(outer, SK_SIG);

  // 2. Strict decode of the inner card.
  const card = decodeMapExact(cardBytes, {
    [K_VERSION]: { type: 'uint', max: 255 },
    [K_IDENTITY_PUB]: { type: 'bytes', len: ED25519_PUB_LEN },
    [K_ENCRYPTION_PUB]: { type: 'bytes', len: X25519_PUB_LEN },
    [K_SERIAL]: { type: 'uint', max: MAX_SERIAL },
  });

  // 3. Version allowlist (before trusting anything else).
  const version = getUint(card, K_VERSION);
  if (!CARD_VERSION_ALLOWLIST.includes(version)) {
    throw new Error(`card: unsupported version ${version}`);
  }

  const identityPub = getBytes(card, K_IDENTITY_PUB);
  const encryptionPub = getBytes(card, K_ENCRYPTION_PUB);
  const serial = getUint(card, K_SERIAL);

  // 4. Validate BOTH public keys (the critical forgery defense).
  validateEd25519Pub(identityPub, opts.ownIdentityPub);
  validateX25519Pub(encryptionPub, opts.ownEncryptionPub);

  // 5. Canonical re-encode equality of the whole card map (deterministic form).
  if (!bytesEqual(encodeDeterministic(card), cardBytes)) {
    throw new Error('card: non-canonical card encoding');
  }

  // 6. Verify the signature over the TRANSPORTED bytes with strict RFC 8032.
  if (!verifyEd25519(sig, concatBytes(CTX_CARD, cardBytes), identityPub)) {
    throw new Error('card: signature verification failed');
  }

  // Copy retained bytes out of the (aliased) source buffer so the card is self-contained.
  return {
    version,
    identityPub: Uint8Array.from(identityPub),
    encryptionPub: Uint8Array.from(encryptionPub),
    serial,
    cardBytes: Uint8Array.from(cardBytes),
    signedCardBytes: Uint8Array.from(signedCardBytes),
  };
}

/** Convenience: the low-level verify some callers want without a full import. */
export function cardSignatureValid(cardBytes: Uint8Array, sig: Uint8Array, identityPub: Uint8Array): boolean {
  return verifyEd25519(sig, concatBytes(CTX_CARD, cardBytes), identityPub);
}
