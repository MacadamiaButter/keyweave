// The pairing ceremony's real entry point: the object the browser UI drives, and the one
// place in src/ that hands bytes to the optical encoder.
//
// R14 CLOSURE. The patent firewall's call-site arm is a text rule over source and is
// evadable by construction (mutate the blessed buffer, pass the encoder as a value). It is
// closed here where the question is decidable: startCardBroadcast() returns the card bytes
// ALONGSIDE the frame stream, so a test can execute this exact function, size the stream to
// k=1, and compare frame(0)'s body with the card byte for byte. Executing the real caller
// ends the whole class of textual evasions - a cipher placed anywhere between
// createSignedCard and the encoder changes the wire, and the wire is what is asserted.
// See client/test/optical-patent-invariant.test.ts, "real-caller arm".
//
// CHOREOGRAPHY. Proof-of-possession is mandatory in pairing.ts's TYPE, so a safety number
// is unreachable without the peer's signature over a transcript containing BOTH fresh
// nonces. Each side therefore has to learn the peer's nonce before it can sign, which is
// three moves, not two:
//
//   turn 1  A shows  [card_A, info_A]                     B scans both
//   turn 2  B shows  [card_B, info_B, proof_B]            A scans all three, finalizes
//   turn 3  A shows  [proof_A]                            B scans it, finalizes
//
// `info` is the per-session nonce plus, when this device reserved one, the mailbox
// coordinate the peer will write to. One payload rather than two: see startInfoBroadcast.
//
// Every frame is self-describing (session id, k, blockLen, totalLen, payloadFnv), so a
// "playlist" is just several independent streams played in turn: the receiver locks onto
// whichever is on screen, completes it, and re-locks when the identity changes. That is
// why no acknowledgement channel is needed between the devices. The humans are the
// acknowledgement channel, which is the point of the product.
//
// A notes the asymmetry honestly: B emits proof_B before it has verified proof_A. A proof
// is a signature over a PUBLIC transcript and proves only that B holds its own identity
// key, so there is nothing for B to lose by going first; A, by contrast, verifies before
// it emits, because it can.
//
// leastpriv: this module holds public bytes and one KeyManager reference. It never sees a
// passphrase, a vault blob, or a contact store.

import { ED25519_SIG_LEN, PAIR_NONCE_LEN } from './constants.js';
import { createSignedCard, importCard, type ContactCard } from './card.js';
import {
  encodeCardFrames,
  encodePairingFrames,
  type CardFrameStream,
  type EncodeCardOptions,
} from './optical.js';
import { newPairingNonce, pairingProof, runPairing, type PairingOutcome } from './pairing.js';
import {
  decodePairingInfo,
  encodePairingInfo,
  looksLikePairingInfo,
  mailboxSignatureValid,
  signMailboxCoordinate,
  type MailboxCoordinate,
} from './mailbox.js';
import type { KeyManager } from './keys.js';

/**
 * v0 has no key rotation, so our own card never advances past its first serial. A future
 * rotation bumps this and the peer sees `supersede`, which forces a fresh in-person
 * ceremony (contacts.ts). v0 has no revocation at all (residual R6).
 */
export const OWN_CARD_SERIAL = 1;

export interface CardBroadcast {
  /** The exact SignedCard wire bytes the frames carry, byte for byte. */
  readonly cardBytes: Uint8Array;
  readonly frames: CardFrameStream;
}

/**
 * Serialize our signed card and start its frame stream. THE entry point the R14 test
 * executes: the returned `cardBytes` is what `frames` puts on the wire, so the two are
 * directly comparable by a caller that holds no keys.
 */
export async function startCardBroadcast(
  km: KeyManager,
  serial: number,
  opts: EncodeCardOptions = {},
): Promise<CardBroadcast> {
  const cardBytes = await createSignedCard(km, serial);
  return { cardBytes, frames: encodeCardFrames(cardBytes, opts) };
}

/**
 * Frame stream for the pairing-info payload: this session's nonce, plus the mailbox
 * coordinate when this device has one. Plaintext like every other optical payload.
 *
 * The mailbox rides WITH the nonce rather than in a stream of its own because a stream of
 * its own would be optional (a device that could not reach the relay has nothing to show)
 * and an optional stream races the required ones: the scan step completes on the required
 * set, the screen changes, and whatever had not been read yet is lost. See src/mailbox.ts.
 */
export function startInfoBroadcast(
  info: Uint8Array,
  opts: EncodeCardOptions = {},
): CardFrameStream {
  return encodePairingFrames(info, opts);
}

/** Frame stream for an Ed25519 proof-of-possession (64 bytes over the public transcript). */
export function startProofBroadcast(
  proof: Uint8Array,
  opts: EncodeCardOptions = {},
): CardFrameStream {
  if (proof.length !== ED25519_SIG_LEN) {
    throw new Error(`pairing-session: a proof is ${ED25519_SIG_LEN} bytes, got ${proof.length}`);
  }
  return encodePairingFrames(proof, opts);
}

export type PairingPayloadKind = 'card' | 'nonce' | 'proof' | 'info';

/**
 * Which of the three ceremony payloads a completed optical reassembly is, by length.
 *
 * Length is the whole discriminator and that is deliberate: a type tag byte would have to
 * be prepended to the card too, and then frame(0) would no longer BE the card, which is
 * the patent limitation this transport exists to keep. The three populations cannot
 * collide: a nonce is exactly 32, a proof exactly 64, and a SignedCard carries a 64-byte
 * signature plus two 32-byte keys plus CBOR framing, so it can be neither. That floor is
 * asserted in the suite rather than assumed here.
 *
 * A `card` answer is a CANDIDATE only. importCard() decides, and it is the caller's job to
 * call it: this function reads a length and nothing else.
 *
 * `info` is the one kind that is NOT decided by length, because its length varies with the
 * capability token inside it. It is decided by a four-byte tag whose first byte is not the
 * CBOR map header a SignedCard starts with, and it is checked AFTER the two fixed lengths so
 * the three original populations classify exactly as they did before it existed.
 *
 * `nonce` is now a NOISE class rather than a payload the ceremony expects: the nonce travels
 * inside `info`. The rule stays because a stray 32-byte symbol in the camera's view has to
 * land somewhere, and the alternative is `card`, which would push it at importCard and turn
 * an ordinary QR code on a poster into a refused ceremony.
 */
export function classifyPairingPayload(payload: Uint8Array): PairingPayloadKind {
  if (payload.length === PAIR_NONCE_LEN) return 'nonce';
  if (payload.length === ED25519_SIG_LEN) return 'proof';
  if (looksLikePairingInfo(payload)) return 'info';
  return 'card';
}

export interface PeerParts {
  card?: ContactCard;
  nonce?: Uint8Array;
  proof?: Uint8Array;
  /** Verified against the peer card, so it is only ever set once that card is in hand. */
  mailbox?: MailboxCoordinate;
}

/**
 * One in-person pairing attempt. Holds our card and nonce, accumulates the peer's three
 * public parts, and gates the safety number behind pairing.ts's mandatory PoP.
 */
export class PairingSession {
  readonly cardBytes: Uint8Array;
  readonly nonce: Uint8Array;
  readonly cardFrames: CardFrameStream;
  /** Our nonce and, when this device reserved one, our mailbox coordinate. */
  readonly infoFrames: CardFrameStream;
  /** The mailbox WE published in this ceremony, so the caller can keep its pull token. */
  readonly ownMailbox: MailboxCoordinate | undefined;

  private readonly km: KeyManager;
  private readonly peer: PeerParts = {};
  // The peer's coordinate arrives with their nonce, which can be read BEFORE their card.
  // Verification needs the card, so the raw parts wait here until there is one.
  private pendingMailbox: { coordinate: MailboxCoordinate; sig: Uint8Array } | undefined;
  private ownProof: Uint8Array | undefined;
  private ownProofFrames: CardFrameStream | undefined;

  private constructor(
    km: KeyManager,
    cardBytes: Uint8Array,
    cardFrames: CardFrameStream,
    nonce: Uint8Array,
    infoBytes: Uint8Array,
    ownMailbox: MailboxCoordinate | undefined,
  ) {
    this.km = km;
    this.cardBytes = cardBytes;
    this.cardFrames = cardFrames;
    this.nonce = nonce;
    this.infoFrames = startInfoBroadcast(infoBytes);
    this.ownMailbox = ownMailbox;
  }

  static async begin(
    km: KeyManager,
    serial: number = OWN_CARD_SERIAL,
    opts: EncodeCardOptions = {},
    ownMailbox?: MailboxCoordinate,
  ): Promise<PairingSession> {
    const broadcast = await startCardBroadcast(km, serial, opts);
    const nonce = newPairingNonce();
    const sig = ownMailbox ? await signMailboxCoordinate(km, ownMailbox) : undefined;
    const infoBytes = encodePairingInfo(nonce, ownMailbox, sig);
    return new PairingSession(
      km,
      broadcast.cardBytes,
      broadcast.frames,
      nonce,
      infoBytes,
      ownMailbox,
    );
  }

  peerParts(): Readonly<PeerParts> {
    return this.peer;
  }

  /**
   * Strictly validate and retain the peer's card. THROWS on a forgery, a non-canonical
   * key, a small-order key, or our own card presented back at us; the caller turns that
   * into a refusal, never a retry loop.
   */
  acceptPeerCard(signedCardBytes: Uint8Array): ContactCard {
    const card = importCard(signedCardBytes, {
      ownIdentityPub: this.km.identityPublicKey(),
      ownEncryptionPub: this.km.encryptionPublicKey(),
    });
    this.peer.card = card;
    // A coordinate that arrived before the card has been waiting for exactly this.
    this.settlePendingMailbox();
    return card;
  }

  acceptPeerNonce(nonce: Uint8Array): void {
    if (nonce.length !== PAIR_NONCE_LEN) {
      throw new Error(`pairing-session: peer nonce is ${nonce.length} bytes`);
    }
    this.peer.nonce = Uint8Array.from(nonce);
  }

  /**
   * Strictly parse the peer's pairing-info payload: their nonce, and their mailbox
   * coordinate when they published one. THROWS on a malformed payload or on a coordinate
   * whose signature does not check out against their card, which the caller turns into a
   * refusal. A wrong coordinate is a REDIRECT, not noise, so it is refused rather than
   * ignored (src/mailbox.ts explains the screen-in-the-room case this closes).
   */
  acceptPeerInfo(payload: Uint8Array): void {
    const info = decodePairingInfo(payload);
    this.acceptPeerNonce(info.nonce);
    if (info.mailbox === undefined || info.mailboxSig === undefined) {
      this.pendingMailbox = undefined;
      return;
    }
    this.pendingMailbox = { coordinate: info.mailbox, sig: info.mailboxSig };
    this.settlePendingMailbox();
  }

  private settlePendingMailbox(): void {
    const pending = this.pendingMailbox;
    const card = this.peer.card;
    if (!pending || !card) return;
    if (!mailboxSignatureValid(pending.coordinate, pending.sig, card.identityPub)) {
      throw new Error('pairing-session: the mailbox coordinate is not signed by that card');
    }
    this.peer.mailbox = pending.coordinate;
    this.pendingMailbox = undefined;
  }

  acceptPeerProof(proof: Uint8Array): void {
    if (proof.length !== ED25519_SIG_LEN) {
      throw new Error(`pairing-session: peer proof is ${proof.length} bytes`);
    }
    this.peer.proof = Uint8Array.from(proof);
  }

  /**
   * Sign the transcript so the peer can verify us. Needs the peer's card and nonce, so it
   * is only callable once both have been scanned.
   */
  async prove(): Promise<CardFrameStream> {
    const { card, nonce } = this.requirePeer(false);
    const { ownProof } = await pairingProof(
      this.km,
      this.cardBytes,
      this.nonce,
      card.signedCardBytes,
      nonce,
    );
    this.ownProof = ownProof;
    this.ownProofFrames = startProofBroadcast(ownProof);
    return this.ownProofFrames;
  }

  /** The proof stream, once prove() or finalize() has produced one. */
  proofFrames(): CardFrameStream {
    if (!this.ownProofFrames) throw new Error('pairing-session: no proof to broadcast yet');
    return this.ownProofFrames;
  }

  /**
   * Verify the peer's proof and derive the safety number. Returns pairing.ts's
   * discriminated union unchanged: `ok: false` is a REFUSAL, never a retry.
   */
  async finalize(): Promise<PairingOutcome> {
    const { card, nonce, proof } = this.requirePeer(true);
    const outcome = await runPairing(
      this.km,
      this.cardBytes,
      this.nonce,
      card.signedCardBytes,
      nonce,
      proof!,
    );
    if (outcome.ok) {
      this.ownProof = outcome.ownProof;
      this.ownProofFrames = startProofBroadcast(outcome.ownProof);
    }
    return outcome;
  }

  private requirePeer(withProof: boolean): {
    card: ContactCard;
    nonce: Uint8Array;
    proof?: Uint8Array;
  } {
    const { card, nonce, proof } = this.peer;
    if (!card) throw new Error('pairing-session: peer card not scanned yet');
    if (!nonce) throw new Error('pairing-session: peer nonce not scanned yet');
    if (withProof && !proof) throw new Error('pairing-session: peer proof not scanned yet');
    return { card, nonce, proof };
  }
}
