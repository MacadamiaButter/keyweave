// Mailbox coordinates: which drop box a paired peer writes to, and how they are exchanged.
//
// THE CHOICE, and why. A mailbox has two capabilities (write_cap, pull_token) and R8 says
// its budgets belong to the mailbox, so every holder of a cap spends the same quota. That
// forces a FRESH MAILBOX PER PAIRING. Carrying the coordinates in the SIGNED CARD cannot
// do that: the card is one artifact per identity, pinned one-per-identity by contacts.ts,
// and minting a new one per pairing would bump the serial, which every already-paired peer
// reads as a supersession and which two different peers holding two different cards at the
// same serial read as a fork (rejected). A long-lived write_cap in a durable public artifact
// is also the wrong lifetime for a per-pairing secret. So the coordinates travel OPTICALLY,
// inside the ceremony, and the card stays exactly what it was.
//
// They ride in the SAME optical payload as the pairing nonce rather than in a fourth stream
// of their own. A separate stream would be optional (a device that could not reach the relay
// has no coordinate to show), and an OPTIONAL stream races the required ones: the scan step
// completes the moment the required set is in, the screen changes, and whichever stream had
// not been read yet is simply lost. Bundling removes the race with no optional-payload
// machinery (anchor `secondsys`).
//
// AUTHENTICITY. The nonce is protected by the ceremony itself: swap it and the proof of
// possession fails, because both sides sign a transcript containing both nonces. A mailbox
// coordinate is NOT in that transcript, so a screen held up in the camera's view could pair
// the two honest devices and still redirect one side's traffic to a mailbox it controls.
// It could not read anything (it holds no key), but it could silently swallow the messages
// and watch the timing. So the coordinate carries its own Ed25519 signature by the sender's
// identity key, verified against the card that same ceremony pinned. An injected coordinate
// is then a refusal, not a redirect.
//
// leastpriv: a coordinate is one mailbox id plus ONE capability. The side that publishes it
// keeps the pull_token and hands out the write_cap, so the peer can write to that mailbox
// and cannot read it, and the publisher can read it and cannot write to it.

import {
  CAP_TOKEN_RE,
  CTX_MAILBOX,
  ED25519_PUB_LEN,
  ED25519_SIG_LEN,
  MAILBOX_ID_LEN,
  PAIR_NONCE_LEN,
} from './constants.js';
import { concatBytes, fromHex, toHex, utf8 } from './bytes.js';
import { decodeMapExact, encodeDeterministic, getBytes } from './cbor.js';
import { verifyEd25519 } from './validate.js';
import type { KeyManager } from './keys.js';

/**
 * Payload tag for the pairing-info optical payload. Four ASCII bytes, and the first of them
 * is not 0xa2, which is the CBOR map header every SignedCard starts with, so a card can
 * never be read as an info payload nor the reverse.
 */
export const PAIRING_INFO_MAGIC = utf8('KWI1');

// Pairing-info map keys.
const P_NONCE = 0;
const P_MAILBOX_ID = 1;
const P_WRITE_CAP = 2;
const P_SIG = 3;

/** Where to write for one peer: the mailbox they read, and the cap that lets us write it. */
export interface MailboxCoordinate {
  readonly id: Uint8Array; // 16 bytes
  readonly writeCap: string;
}

/** What one optical pairing-info payload carries. The mailbox half is optional. */
export interface PairingInfo {
  readonly nonce: Uint8Array;
  readonly mailbox: MailboxCoordinate | undefined;
  /** Present exactly when `mailbox` is. Verified against the peer card, not here. */
  readonly mailboxSig: Uint8Array | undefined;
}

/** The wire form the relay routes on: 32 lowercase hex characters. */
export function toRelayMailboxId(id: Uint8Array): string {
  if (id.length !== MAILBOX_ID_LEN) throw new Error('mailbox: id is not 16 bytes');
  return toHex(id);
}

/** The 16 bytes behind a relay mailbox id. Validated: the relay is not trusted to be right. */
export function fromRelayMailboxId(hex: string): Uint8Array {
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error('mailbox: relay id is not 32 lowercase hex');
  return fromHex(hex);
}

const ascii = new TextDecoder('utf-8', { fatal: true });

function capBytes(writeCap: string): Uint8Array {
  if (!CAP_TOKEN_RE.test(writeCap)) throw new Error('mailbox: write cap is not a capability token');
  return utf8(writeCap);
}

function capString(bytes: Uint8Array): string {
  let text: string;
  try {
    text = ascii.decode(bytes);
  } catch {
    throw new Error('mailbox: write cap is not text');
  }
  if (!CAP_TOKEN_RE.test(text)) throw new Error('mailbox: write cap is not a capability token');
  return text;
}

/** The bytes a mailbox coordinate's signature covers. Domain-separated from every other sig. */
export function mailboxSigningBytes(coordinate: MailboxCoordinate): Uint8Array {
  if (coordinate.id.length !== MAILBOX_ID_LEN) throw new Error('mailbox: id is not 16 bytes');
  return concatBytes(CTX_MAILBOX, coordinate.id, capBytes(coordinate.writeCap));
}

/** Sign our own coordinate so the peer can refuse one that did not come from us. */
export async function signMailboxCoordinate(
  km: KeyManager,
  coordinate: MailboxCoordinate,
): Promise<Uint8Array> {
  return km.sign(mailboxSigningBytes(coordinate));
}

/** Strict RFC 8032 verify of a coordinate against the identity key the ceremony pinned. */
export function mailboxSignatureValid(
  coordinate: MailboxCoordinate,
  sig: Uint8Array,
  identityPub: Uint8Array,
): boolean {
  if (identityPub.length !== ED25519_PUB_LEN) return false;
  if (sig.length !== ED25519_SIG_LEN) return false;
  return verifyEd25519(sig, mailboxSigningBytes(coordinate), identityPub);
}

/**
 * Serialize one pairing-info payload. Plaintext, like every other optical payload: nothing
 * on this path is encrypted (the patent limitation lives in optical.ts, and this payload is
 * handed to the same encoder as public bytes).
 */
export function encodePairingInfo(
  nonce: Uint8Array,
  mailbox?: MailboxCoordinate,
  mailboxSig?: Uint8Array,
): Uint8Array {
  if (nonce.length !== PAIR_NONCE_LEN) throw new Error('mailbox: nonce is not 32 bytes');
  const map = new Map<number, unknown>([[P_NONCE, nonce]]);
  if (mailbox !== undefined) {
    if (mailboxSig === undefined || mailboxSig.length !== ED25519_SIG_LEN) {
      throw new Error('mailbox: a coordinate must be signed');
    }
    if (mailbox.id.length !== MAILBOX_ID_LEN) throw new Error('mailbox: id is not 16 bytes');
    map.set(P_MAILBOX_ID, mailbox.id);
    map.set(P_WRITE_CAP, capBytes(mailbox.writeCap));
    map.set(P_SIG, mailboxSig);
  }
  return concatBytes(PAIRING_INFO_MAGIC, encodeDeterministic(map));
}

/** True when `payload` carries the pairing-info tag. Length is never the discriminator here. */
export function looksLikePairingInfo(payload: Uint8Array): boolean {
  if (payload.length <= PAIRING_INFO_MAGIC.length) return false;
  for (let i = 0; i < PAIRING_INFO_MAGIC.length; i++) {
    if (payload[i] !== PAIRING_INFO_MAGIC[i]) return false;
  }
  return true;
}

/**
 * Strictly parse one pairing-info payload. Throws on any deviation, including a coordinate
 * that is half present: three optional keys that must arrive together are three ways to be
 * wrong, so the decoder collapses them to one.
 */
export function decodePairingInfo(payload: Uint8Array): PairingInfo {
  if (!looksLikePairingInfo(payload)) throw new Error('mailbox: not a pairing-info payload');
  const body = payload.subarray(PAIRING_INFO_MAGIC.length);
  const m = decodeMapExact(body, {
    [P_NONCE]: { type: 'bytes', len: PAIR_NONCE_LEN },
    [P_MAILBOX_ID]: { type: 'bytes', len: MAILBOX_ID_LEN, optional: true },
    [P_WRITE_CAP]: { type: 'bytes', len: [16, 128], optional: true },
    [P_SIG]: { type: 'bytes', len: ED25519_SIG_LEN, optional: true },
  });
  const nonce = Uint8Array.from(getBytes(m, P_NONCE));
  const present = [P_MAILBOX_ID, P_WRITE_CAP, P_SIG].filter((k) => m.has(k)).length;
  if (present === 0) return { nonce, mailbox: undefined, mailboxSig: undefined };
  if (present !== 3) throw new Error('mailbox: a coordinate must carry id, cap and signature');
  return {
    nonce,
    mailbox: {
      id: Uint8Array.from(getBytes(m, P_MAILBOX_ID)),
      writeCap: capString(getBytes(m, P_WRITE_CAP)),
    },
    mailboxSig: Uint8Array.from(getBytes(m, P_SIG)),
  };
}
