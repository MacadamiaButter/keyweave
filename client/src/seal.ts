// Message seal: SIGN-THEN-ENCRYPT (corrected decision; encrypt-then-sign leaked the
// social graph). The wire envelope carries ONLY { version, nonce, ciphertext } - zero
// identity-key material (anchor `leastpriv`: the relay must not be able to build a
// social graph from what it stores).
//
//   inner        = dCBOR{ sender_id, recipient_id, timestamp_ms, body }
//   InnerSigned  = dCBOR{ inner_bytes(bstr), sig(64) }   // Ed25519 over inner_bytes
//   K            = HKDF-SHA512(X25519(dh), info = CTX_MSG || both_ids || both_x_pubs)
//   ciphertext   = XChaCha20-Poly1305(K, random 24B nonce, AAD=[version]).encrypt(dCBOR(InnerSigned))
//   envelope     = dCBOR{ version, nonce, ciphertext }
//
// open() enforces, in order: version allowlist BEFORE any KDF; AEAD (tamper /
// wrong-recipient / wrong-sender all fail here); strict inner decode; sender_id ==
// the sender we derived K for (surreptitious-forward defense); recipient_id == us
// (not-for-me); strict RFC 8032 signature (KCI defense - the attacker who only holds
// the recipient's X25519 secret can derive K but cannot forge the identity signature).

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import {
  CLOCK_SKEW_MS,
  CTX_MSG,
  CTX_MSGID,
  CTX_MSG_HKDF_SALT,
  CTX_MSG_SIG,
  ED25519_PUB_LEN,
  ED25519_SIG_LEN,
  MESSAGE_VERSION,
  MESSAGE_VERSION_ALLOWLIST,
  X25519_PUB_LEN,
  XCHACHA_KEY_LEN,
  XCHACHA_NONCE_LEN,
} from './constants.js';
import { assertLength, bytesEqual, compareBytes, concatBytes, zeroize } from './bytes.js';
import { decodeMapExact, encodeDeterministic, getBytes, getUint } from './cbor.js';
import { verifyEd25519 } from './validate.js';
import type { KeyManager } from './keys.js';
import type { ContactCard } from './card.js';

// inner keys
const I_SENDER = 0;
const I_RECIPIENT = 1;
const I_TIMESTAMP = 2;
const I_BODY = 3;
// InnerSigned keys
const S_INNER = 0;
const S_SIG = 1;
// envelope keys
const E_VERSION = 0;
const E_NONCE = 1;
const E_CIPHERTEXT = 2;

export interface SealOptions {
  timestampMs?: number;
  /** Test-only nonce override; production uses a fresh random 24-byte nonce. */
  nonce?: Uint8Array;
}

export interface OpenOptions {
  /** Local time used for the future-timestamp clamp; defaults to Date.now(). */
  nowMs?: number;
}

export interface OpenedMessage {
  readonly senderId: Uint8Array; // Ed25519 identity pub
  readonly recipientId: Uint8Array;
  readonly timestampMs: number;
  readonly body: Uint8Array;
  /** Dedupe id over AUTHENTICATED bytes: SHA-512(CTX_MSGID || inner_bytes || sig). */
  readonly msgId: Uint8Array;
  readonly innerBytes: Uint8Array;
  readonly sig: Uint8Array;
}

// Party-ordered HKDF info: bind each identity to its encryption key, symmetric so both
// sides derive the same K. Party 0 is the one with the lexicographically smaller id.
// Exported for adversarial tests that must reconstruct K from raw parts.
export function messageKeyInfo(
  ownId: Uint8Array,
  ownX: Uint8Array,
  peerId: Uint8Array,
  peerX: Uint8Array,
): Uint8Array {
  const ownFirst = compareBytes(ownId, peerId) <= 0;
  const id0 = ownFirst ? ownId : peerId;
  const id1 = ownFirst ? peerId : ownId;
  const x0 = ownFirst ? ownX : peerX;
  const x1 = ownFirst ? peerX : ownX;
  return concatBytes(CTX_MSG, id0, id1, x0, x1);
}

export async function deriveMessageKey(km: KeyManager, peer: ContactCard): Promise<Uint8Array> {
  const dh = await km.dh(peer.encryptionPub);
  const info = messageKeyInfo(
    km.identityPublicKey(),
    km.encryptionPublicKey(),
    peer.identityPub,
    peer.encryptionPub,
  );
  const k = hkdf(sha512, dh, CTX_MSG_HKDF_SALT, info, XCHACHA_KEY_LEN);
  zeroize(dh);
  return k;
}

export function computeMsgId(innerBytes: Uint8Array, sig: Uint8Array): Uint8Array {
  return sha512(concatBytes(CTX_MSGID, innerBytes, sig));
}

/** Seal `body` from us (km) to `recipient`. Returns the wire envelope bytes. */
export async function seal(
  km: KeyManager,
  recipient: ContactCard,
  body: Uint8Array,
  opts: SealOptions = {},
): Promise<Uint8Array> {
  const senderId = km.identityPublicKey();
  const recipientId = recipient.identityPub;
  const timestampMs = opts.timestampMs ?? Date.now();
  if (!Number.isInteger(timestampMs) || timestampMs < 0) {
    throw new Error('seal: bad timestamp');
  }

  const inner = new Map<number, unknown>([
    [I_SENDER, senderId],
    [I_RECIPIENT, recipientId],
    [I_TIMESTAMP, timestampMs],
    [I_BODY, body],
  ]);
  const innerBytes = encodeDeterministic(inner);
  // Domain-separated signature (must-fix #8): sign CTX_MSG_SIG || inner_bytes so an inner
  // signature can never be replayed into another signing context (card, pairing, ...).
  const sig = await km.sign(concatBytes(CTX_MSG_SIG, innerBytes));

  const innerSigned = new Map<number, unknown>([
    [S_INNER, innerBytes],
    [S_SIG, sig],
  ]);
  const plaintext = encodeDeterministic(innerSigned);

  const version = MESSAGE_VERSION;
  const nonce = opts.nonce ?? randomBytes(XCHACHA_NONCE_LEN);
  assertLength(nonce, XCHACHA_NONCE_LEN, 'nonce');
  const aad = Uint8Array.from([version]);

  const key = await deriveMessageKey(km, recipient);
  const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  zeroize(key);

  const envelope = new Map<number, unknown>([
    [E_VERSION, version],
    [E_NONCE, nonce],
    [E_CIPHERTEXT, ciphertext],
  ]);
  const wire = encodeDeterministic(envelope);

  // Invariant (anchor `leastpriv`): the wire reveals no identity-key material.
  assertNoIdentityMaterial(wire, [
    senderId,
    recipientId,
    km.encryptionPublicKey(),
    recipient.encryptionPub,
  ]);
  return wire;
}

/** Open an envelope claimed to be from `sender`. Throws (never returns partial) on any failure. */
export async function open(
  km: KeyManager,
  sender: ContactCard,
  envelopeBytes: Uint8Array,
  opts: OpenOptions = {},
): Promise<OpenedMessage> {
  // 1. Strict envelope decode.
  const env = decodeMapExact(envelopeBytes, {
    [E_VERSION]: { type: 'uint', max: 255 },
    [E_NONCE]: { type: 'bytes', len: XCHACHA_NONCE_LEN },
    [E_CIPHERTEXT]: { type: 'bytes', len: [XCHACHA_KEY_LEN, 1 << 20] },
  });
  const version = getUint(env, E_VERSION);

  // 2. Version allowlist BEFORE any key derivation.
  if (!MESSAGE_VERSION_ALLOWLIST.includes(version)) {
    throw new Error(`seal: unsupported message version ${version}`);
  }
  const nonce = getBytes(env, E_NONCE);
  const ciphertext = getBytes(env, E_CIPHERTEXT);
  const aad = Uint8Array.from([version]);

  // 3. Derive K for (us, claimed-sender) and AEAD-open.
  const key = await deriveMessageKey(km, sender);
  let plaintext: Uint8Array;
  try {
    plaintext = xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch {
    zeroize(key);
    throw new Error('seal: AEAD open failed (tamper / wrong recipient / wrong sender)');
  }
  zeroize(key);

  // 4. Strict InnerSigned + inner decode.
  const innerSigned = decodeMapExact(plaintext, {
    [S_INNER]: { type: 'bytes' },
    [S_SIG]: { type: 'bytes', len: ED25519_SIG_LEN },
  });
  const innerBytes = getBytes(innerSigned, S_INNER);
  const sig = getBytes(innerSigned, S_SIG);

  const inner = decodeMapExact(innerBytes, {
    [I_SENDER]: { type: 'bytes', len: ED25519_PUB_LEN },
    [I_RECIPIENT]: { type: 'bytes', len: ED25519_PUB_LEN },
    [I_TIMESTAMP]: { type: 'uint', max: Number.MAX_SAFE_INTEGER },
    [I_BODY]: { type: 'bytes' },
  });
  const senderId = getBytes(inner, I_SENDER);
  const recipientId = getBytes(inner, I_RECIPIENT);
  const timestampMs = getUint(inner, I_TIMESTAMP);
  const body = getBytes(inner, I_BODY);

  // 5. sender_id must equal the sender we derived K for (surreptitious-forward defense).
  if (!bytesEqual(senderId, sender.identityPub)) {
    throw new Error('seal: inner sender_id does not match the claimed sender');
  }
  // 6. recipient_id must be us (not-for-me / re-encryption defense).
  if (!bytesEqual(recipientId, km.identityPublicKey())) {
    throw new Error('seal: message is not addressed to us');
  }
  // 7. Clamp future-dated timestamps BEFORE the recipient's replay high-water mark can
  //    see them (must-fix #2): one message dated at MAX_SAFE_INTEGER would otherwise
  //    poison the per-sender mark and permanently brick the channel.
  const now = opts.nowMs ?? Date.now();
  if (timestampMs > now + CLOCK_SKEW_MS) {
    throw new Error('seal: inner timestamp too far in the future (clock-skew clamp)');
  }
  // 8. Strict RFC 8032 signature by the sender over CTX_MSG_SIG || inner bytes
  //    (KCI defense + domain separation).
  if (!verifyEd25519(sig, concatBytes(CTX_MSG_SIG, innerBytes), senderId)) {
    throw new Error('seal: inner signature invalid');
  }

  // Copy user-facing fields out of the aliased plaintext buffer.
  return {
    senderId: Uint8Array.from(senderId),
    recipientId: Uint8Array.from(recipientId),
    timestampMs,
    body: Uint8Array.from(body),
    msgId: computeMsgId(innerBytes, sig),
    innerBytes: Uint8Array.from(innerBytes),
    sig: Uint8Array.from(sig),
  };
}

/** Assert `wire` contains none of the given (non-secret but linkable) key byte-strings. */
export function assertNoIdentityMaterial(wire: Uint8Array, keys: Uint8Array[]): void {
  for (const k of keys) {
    if (k.length >= X25519_PUB_LEN && containsSubsequence(wire, k)) {
      throw new Error('seal: INVARIANT VIOLATION - identity key material present in wire envelope');
    }
  }
}

function containsSubsequence(hay: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || needle.length > hay.length) return false;
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
