// Optical pairing transport: the animated-QR hop that carries a SignedCard from one
// device's screen to the other's camera. Wrap-before-encode - the card is serialized
// and signed by card.ts, and only then handed to the fountain codec as opaque bytes.
//
// DESIGN INVARIANT (enforced by test/optical-patent-invariant.test.ts, which `npm test`
// runs; there is no CI runner in this repo yet): the optical payload is the PLAINTEXT
// signed public card. Nothing encrypts between card serialization and the encoder, so a
// raw camera decode of pairing frames yields a parseable public card. That test reads the
// FRAME BODY on the wire, not only the reassembled output, because any symmetric
// transform undone on decode would round-trip byte-exact; it also refuses a call site
// that hands this function anything but a createSignedCard result. This module and
// everything under vendor/decimen/ import nothing from seal.ts or keys.ts. Two reasons,
// both load-bearing:
//   - leastpriv: the optical layer only ever sees public bytes, so a defect in a
//     vendored third-party codec cannot reach key material.
//   - the encrypted-QR prior art (US 11455616 / US 11720879) claims displaying and
//     DECRYPTING an encrypted code; a plaintext-readable payload is a required
//     non-infringement limitation, not an implementation detail. Posture, not a
//     clearance (docs/keyweave-v0-hardened-spec.md).
//
// INTEGRITY BOUNDARY: the frame header's `payloadFnv` is a 32-bit non-cryptographic
// checksum and is trivially forgeable by anyone who can put a QR in front of the
// camera. It is reported as a CORRUPTION HINT ONLY. The Ed25519 signature over the
// CBOR card is the integrity boundary, and the CALLER verifies it with
// importCard(assembled) before the bytes are used for anything. This module returns
// raw payload bytes and verifies no signatures.
//
// defdepth: the header caps live in TWO independently written places, here and in
// vendor/decimen/frame.ts parseFrame(). Both must pass before a decoder exists. Both
// walls are on THIS path only, so the same ceilings are asserted a third time in the
// LTDecoder constructor for callers that build a decoder without a frame.

import {
  HEADER_LEN,
  MAX_BLOCK_LEN,
  MAX_K,
  MAX_TOTAL_LEN,
  fnv1a,
  packFrame,
  looksLikeFrame,
  parseFrame,
  streamIdentity,
} from '../vendor/decimen/frame.js';
import type { FrameHeader } from '../vendor/decimen/frame.js';
import { blockLength } from '../vendor/decimen/frame-capacity.js';
import { LTDecoder, LTEncoder } from '../vendor/decimen/fountain.js';

export { MAX_BLOCK_LEN, MAX_K, MAX_TOTAL_LEN };

/**
 * Source blocks the default frame size aims for. k = 1 degenerates the fountain to
 * plain repetition (the receiver completes on the first decoded frame and a single
 * unlucky symbol is the whole transfer), and a card is small enough that the naive
 * default would land there. Small frames also mean a low-density QR, which is what
 * decodes across a room rather than at phone-to-phone range.
 */
export const TARGET_SOURCE_BLOCKS = 5;

/** Floor on the default block size; below this the header dominates the frame. */
export const MIN_BLOCK_LEN = 16;

export interface EncodeCardOptions {
  /**
   * Bytes per wire frame, header included. Omit to size the frame so k lands near
   * TARGET_SOURCE_BLOCKS for this card.
   */
  frameBytes?: number;
  /** Fixed session id, 1..0xffff. Test seam; production draws one. */
  sessionId?: number;
}

export interface CardFrameStream {
  readonly sessionId: number;
  readonly k: number;
  readonly blockLen: number;
  readonly frameBytes: number;
  readonly totalLen: number;
  /**
   * Wire bytes for frame `seq`. The stream is endless by design: the display loop
   * increments seq forever and the receiver stops it by completing.
   */
  frame(seq: number): Uint8Array;
}

/**
 * Session ids are 16 bits and MUST NOT be 0: the fountain seeds on sessionId + 1, and
 * 0 collides with the encoder's own draw. Math.random() < 1, so floor(r * 0xffff) is
 * at most 0xfffe and the +1 can neither produce 0 nor overflow the u16.
 */
function drawSessionId(): number {
  return Math.floor(Math.random() * 0xffff) + 1;
}

function defaultBlockLen(payloadLen: number): number {
  const aim = Math.ceil(payloadLen / TARGET_SOURCE_BLOCKS);
  return Math.min(MAX_BLOCK_LEN, Math.max(MIN_BLOCK_LEN, aim));
}

/**
 * Encode signed card bytes into the animated-QR frame stream.
 *
 * `cardBytes` is whatever card.ts produced. This layer never inspects it beyond its
 * length, and never transforms it: the receiver reassembles these exact bytes.
 */
export function encodeCardFrames(
  cardBytes: Uint8Array,
  opts: EncodeCardOptions = {},
): CardFrameStream {
  return buildFrameStream(cardBytes, opts);
}

/**
 * The same frame stream for the ceremony's OTHER public payloads: the fresh per-session
 * nonce and the Ed25519 proof-of-possession over the public pairing transcript. Both are
 * plaintext on the wire exactly like the card.
 *
 * It is a separate export rather than a second caller of encodeCardFrames on purpose. The
 * patent firewall's call-site rule says every `encodeCardFrames(` in src/ hands the
 * encoder a createSignedCard result; a nonce is not one, so routing nonces through the
 * card function would force that rule to be relaxed, and the rule is worth more than the
 * saved line. Length is bounded by the caller (src/pairing-session.ts), which is the only
 * place that knows what a legitimate pairing payload looks like.
 */
export function encodePairingFrames(
  payload: Uint8Array,
  opts: EncodeCardOptions = {},
): CardFrameStream {
  return buildFrameStream(payload, opts);
}

// The frame layer is payload-agnostic; the two exports above are the only entries. Refusal
// text says "card" for every payload because the card is the only thing this transport
// carries at length, and rewording per payload would only make two error strings to grep.
function buildFrameStream(cardBytes: Uint8Array, opts: EncodeCardOptions): CardFrameStream {
  const totalLen = cardBytes.length;
  if (totalLen === 0) throw new Error('optical: refusing to encode an empty card');
  if (totalLen > MAX_TOTAL_LEN) {
    throw new Error(`optical: card is ${totalLen} bytes, over the ${MAX_TOTAL_LEN} byte cap`);
  }

  const blockLen =
    opts.frameBytes === undefined ? defaultBlockLen(totalLen) : blockLength(opts.frameBytes);
  if (!Number.isInteger(blockLen) || blockLen < 1 || blockLen > MAX_BLOCK_LEN) {
    throw new Error(
      `optical: frameBytes must leave 1..${MAX_BLOCK_LEN} payload bytes after the ` +
        `${HEADER_LEN} byte header, got ${blockLen}`,
    );
  }

  const sessionId = opts.sessionId ?? drawSessionId();
  if (!Number.isInteger(sessionId) || sessionId < 1 || sessionId > 0xffff) {
    throw new Error(`optical: sessionId must be 1..65535, got ${sessionId}`);
  }

  // Checked before the encoder exists, so an out-of-range frame size cannot allocate
  // first and be refused after.
  if (Math.ceil(totalLen / blockLen) > MAX_K) {
    throw new Error(
      `optical: ${Math.ceil(totalLen / blockLen)} source blocks exceeds the ${MAX_K} block cap`,
    );
  }
  const encoder = new LTEncoder(cardBytes, blockLen, sessionId);

  const base: Omit<FrameHeader, 'seq'> = {
    sessionId,
    k: encoder.k,
    blockLen,
    totalLen,
    payloadFnv: fnv1a(cardBytes),
  };

  return {
    sessionId,
    k: encoder.k,
    blockLen,
    frameBytes: HEADER_LEN + blockLen,
    totalLen,
    frame(seq: number): Uint8Array {
      // seq is a u32 on the wire; DataView would wrap a larger value silently and the
      // receiver would derive different block indices than the encoder used.
      if (!Number.isInteger(seq) || seq < 0 || seq > 0xffffffff) {
        throw new Error(`optical: seq must be a u32, got ${seq}`);
      }
      return packFrame({ ...base, seq }, encoder.encode(seq));
    },
  };
}

/**
 * The receiver-side header wall. Written out here rather than reused from frame.ts so
 * that a parser that stops rejecting cannot silently disarm the decoder guard too
 * (defdepth). The shared thing is the three numbers, which is deliberate: a cap edit
 * should move both walls.
 *
 * Returns a refusal reason, or null when the header is one a real encoder could emit.
 */
export function headerRefusal(h: FrameHeader): string | null {
  if (!Number.isInteger(h.k) || h.k < 1 || h.k > MAX_K) {
    return `k out of range: ${h.k}`;
  }
  if (!Number.isInteger(h.blockLen) || h.blockLen < 1 || h.blockLen > MAX_BLOCK_LEN) {
    return `blockLen out of range: ${h.blockLen}`;
  }
  if (!Number.isInteger(h.totalLen) || h.totalLen < 1 || h.totalLen > MAX_TOTAL_LEN) {
    return `totalLen out of range: ${h.totalLen}`;
  }
  if (h.totalLen > h.k * h.blockLen) {
    return `totalLen ${h.totalLen} exceeds ${h.k} blocks of ${h.blockLen}`;
  }
  if (h.totalLen <= (h.k - 1) * h.blockLen) {
    return `totalLen ${h.totalLen} leaves a whole block of ${h.blockLen} unused`;
  }
  return null;
}

export type OpticalFeed =
  | { readonly kind: 'refused'; readonly reason: string }
  | {
      readonly kind: 'progress';
      readonly k: number;
      readonly solved: number;
      readonly framesNew: number;
      readonly framesDup: number;
    }
  | {
      readonly kind: 'complete';
      /** The reassembled payload, byte-exact. NOT yet verified: importCard() it. */
      readonly payload: Uint8Array;
      /** Non-cryptographic corruption hint. Never an authenticity signal. */
      readonly checksumOk: boolean;
    };

/**
 * Accumulates scanned frames into one card. Constructed with no arguments and holding
 * no key material by design: it decodes public bytes and hands them back.
 */
export class OpticalReceiver {
  private identity: string | null = null;
  private decoder: LTDecoder | null = null;
  private payload: Uint8Array | null = null;
  private checksumOk = false;

  // Two counters, not one. These populations are different in kind and a UI that merges
  // them cries wolf: a camera pointed at the world decodes ordinary QR codes (a poster, a
  // URL) that are simply not ours, which is noise, while an in-bounds-looking frame that
  // fails the caps is the attack signal the caps exist for.
  /** Decoded symbols that were not a well-formed Keyweave frame at all. */
  malformedCount = 0;
  /** Well-formed frames whose header was refused by the caps. */
  cappedCount = 0;

  /** Frames refused for any reason, since the last reset. */
  get refusedCount(): number {
    return this.malformedCount + this.cappedCount;
  }

  /** Drop all stream state. The next frame starts a fresh decoder. */
  reset(): void {
    this.identity = null;
    this.decoder = null;
    this.payload = null;
    this.checksumOk = false;
    this.malformedCount = 0;
    this.cappedCount = 0;
  }

  feed(frameBytes: Uint8Array): OpticalFeed {
    const parsed = parseFrame(frameBytes);
    if (!parsed) {
      // parseFrame folds the caps into its own refusal, so the two populations arrive on
      // the same branch. looksLikeFrame re-runs only the STRUCTURAL checks to tell them
      // apart: structurally ours means the caps did the refusing.
      if (looksLikeFrame(frameBytes)) {
        this.cappedCount++;
        return { kind: 'refused', reason: 'frame header is out of bounds' };
      }
      this.malformedCount++;
      return { kind: 'refused', reason: 'not a well-formed Keyweave frame' };
    }
    const { header, block } = parsed;

    // Second wall: no decoder is constructed until this passes.
    const refusal = headerRefusal(header);
    if (refusal) {
      this.cappedCount++;
      return { kind: 'refused', reason: refusal };
    }

    // Any drift in the five identity fields is a different stream. Reusing a decoder
    // across that boundary corrupts it silently.
    const identity = streamIdentity(header);
    if (this.identity !== identity) {
      this.identity = identity;
      this.decoder = new LTDecoder(header.k, header.blockLen, header.sessionId, header.totalLen);
      this.payload = null;
      this.checksumOk = false;
    }
    const decoder = this.decoder!;

    if (this.payload) {
      return { kind: 'complete', payload: this.payload, checksumOk: this.checksumOk };
    }

    decoder.addFrame(header.seq, block);
    if (!decoder.isComplete) {
      return {
        kind: 'progress',
        k: decoder.k,
        solved: decoder.solvedCount,
        framesNew: decoder.framesNew,
        framesDup: decoder.framesDup,
      };
    }

    const payload = decoder.assemble();
    if (!payload) {
      return {
        kind: 'progress',
        k: decoder.k,
        solved: decoder.solvedCount,
        framesNew: decoder.framesNew,
        framesDup: decoder.framesDup,
      };
    }
    this.payload = payload;
    this.checksumOk = fnv1a(payload) === header.payloadFnv;
    return { kind: 'complete', payload, checksumOk: this.checksumOk };
  }
}
