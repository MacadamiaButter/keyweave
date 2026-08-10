// KEYWEAVE VENDOR SPLIT of decimen `shared/protocol.ts` @ f0c49e92d50366c6867759800dd962b70d840a1a.
// Upstream fuses two unrelated layers into one module: the frame layer (kept here) and
// the "DCF2" file container (upstream lines 33-270: gzip/gunzip, SHA-256, filename, media
// type). The container is EXCLUDED BY CONSTRUCTION, so no CompressionStream reaches this
// build and there is no decompression surface on the scan path at all. See PROVENANCE.md
// for the exact line ranges and every local modification.
//
// Text below carrying em dashes is upstream's, kept verbatim (vendor/decimen/** is exempt
// from the Keyweave public-text gate). Keyweave-authored text uses no em dash.

// Frame protocol: every QR frame is fully self-describing, so there is NO
// handshake — the receiver locks onto a stream mid-flight, and a new session
// id on any frame simply starts a fresh transfer.
//
// Layout (little-endian), 20 bytes, followed by `blockLen` payload bytes:
//   0  u8   magic 0xD1
//   1  u8   magic 0x0C
//   2  u16  sessionId   random per sender start
//   4  u32  seq         drives the fountain PRNG (see fountain.ts)
//   8  u16  k           source block count
//  10  u16  blockLen    payload bytes per frame
//  12  u32  totalLen    protected file-container length in bytes
//  16  u32  payloadFnv  FNV-1a of the whole container — verified on completion

export const HEADER_LEN = 20;
const MAGIC0 = 0xd1;
const MAGIC1 = 0x0c;

// ---------------------------------------------------------------------------
// KEYWEAVE HARDENING (not upstream). Upstream issue #1 is open at our pin: the
// only checks in parseFrame() are magic, non-zero fields and self-consistent
// frame length, so `k` (u16) and `totalLen` (u32) are attacker-chosen. A single
// 28-byte frame declaring k=1, blockLen=8, totalLen=256MB drives a 256 MB
// allocation in LTDecoder.assemble(), plus a full-length fnv1a pass over it; the
// u32 ceiling is 4 GB. Upstream's own 64 MB ceiling lived in unpackFile(), i.e.
// in the container we deleted, so vendoring the frame layer WITHOUT these caps
// would be strictly worse than upstream.
//
// The numbers are Keyweave's, not upstream's and not PR #27's: the only thing
// this transport ever carries is one signed contact card (~150 bytes today).
//
// These caps are one of two independent walls against a hostile FRAME. The other
// lives in the receiver (src/optical.ts), which re-checks the same invariants
// before it constructs any decoder, so a parser regression cannot silently disarm
// the decoder guard, nor the reverse. Neither wall substitutes for the other.
//
// Say what they do NOT cover: both only run on the path through
// OpticalReceiver.feed(). Neither is reachable from a caller that constructs
// LTDecoder itself, and this directory is importable, so the same three ceilings
// are asserted once more in the LTDecoder constructor (fountain.ts). That third
// assertion bounds the CLASS; it is not a third check on a frame.
// ---------------------------------------------------------------------------

/** Absolute ceiling on a declared payload length. Generous headroom over a card. */
export const MAX_TOTAL_LEN = 16384;
/** Ceiling on the declared source-block count (bounds solitonCdf() work and the wait). */
export const MAX_K = 32;
/** QR V40 / ECC-L byte capacity. A larger block cannot have arrived in one symbol. */
export const MAX_BLOCK_LEN = 2953;

export interface FrameHeader {
  sessionId: number;
  seq: number;
  k: number;
  blockLen: number;
  totalLen: number;
  payloadFnv: number;
}

export function packFrame(h: FrameHeader, block: Uint8Array): Uint8Array {
  const out = new Uint8Array(HEADER_LEN + block.length);
  const dv = new DataView(out.buffer);
  dv.setUint8(0, MAGIC0);
  dv.setUint8(1, MAGIC1);
  dv.setUint16(2, h.sessionId, true);
  dv.setUint32(4, h.seq, true);
  dv.setUint16(8, h.k, true);
  dv.setUint16(10, h.blockLen, true);
  dv.setUint32(12, h.totalLen, true);
  dv.setUint32(16, h.payloadFnv, true);
  out.set(block, HEADER_LEN);
  return out;
}

export function parseFrame(
  bytes: Uint8Array,
): { header: FrameHeader; block: Uint8Array } | null {
  if (bytes.length <= HEADER_LEN) return null;
  if (bytes[0] !== MAGIC0 || bytes[1] !== MAGIC1) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const header: FrameHeader = {
    sessionId: dv.getUint16(2, true),
    seq: dv.getUint32(4, true),
    k: dv.getUint16(8, true),
    blockLen: dv.getUint16(10, true),
    totalLen: dv.getUint32(12, true),
    payloadFnv: dv.getUint32(16, true),
  };
  if (header.k === 0 || header.blockLen === 0 || header.totalLen === 0) return null;
  if (bytes.length !== HEADER_LEN + header.blockLen) return null;

  // KEYWEAVE HARDENING: absolute ceilings first, then the arithmetic invariant.
  // `(k-1)*blockLen < totalLen <= k*blockLen` is the only relation a real encoder
  // can produce (k = ceil(totalLen / blockLen)); everything else is a header that
  // no sender would emit. Ceilings are checked before the products so the products
  // stay far inside the safe-integer range.
  if (header.k > MAX_K) return null;
  if (header.blockLen > MAX_BLOCK_LEN) return null;
  if (header.totalLen > MAX_TOTAL_LEN) return null;
  if (header.totalLen > header.k * header.blockLen) return null;
  if (header.totalLen <= (header.k - 1) * header.blockLen) return null;

  return { header, block: bytes.subarray(HEADER_LEN) };
}

/**
 * KEYWEAVE ADDITION (not upstream). True when `bytes` passes the STRUCTURAL checks a
 * Keyweave frame must pass (length, magic, non-zero fields, self-consistent length) and
 * so is one of ours, independent of whether the caps then refuse its declared geometry.
 *
 * This is what separates the two refusal populations a receiver sees. A camera pointed at
 * the world decodes ordinary QR codes constantly: posters, URLs, partially occluded
 * symbols. Those fail here and are noise. A symbol that passes here but is still refused
 * by parseFrame was refused BY THE CAPS, which is the attack signal the caps exist for.
 * Merging the two makes a hostile-frame counter that fires on a poster.
 */
export function looksLikeFrame(bytes: Uint8Array): boolean {
  if (bytes.length <= HEADER_LEN) return false;
  if (bytes[0] !== MAGIC0 || bytes[1] !== MAGIC1) return false;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const k = dv.getUint16(8, true);
  const blockLen = dv.getUint16(10, true);
  const totalLen = dv.getUint32(12, true);
  if (k === 0 || blockLen === 0 || totalLen === 0) return false;
  return bytes.length === HEADER_LEN + blockLen;
}

/**
 * Everything about a frame that has to hold constant for a decoder to keep
 * accepting frames into it. `seq` is deliberately absent — it is the one field
 * that varies within a stream.
 *
 * The receiver resets on ANY disagreement, not just a new session id: session
 * ids are 16 bits drawn at random on every sender restart, so a collision
 * across a restart is rare but real, and a mismatched frame fed into the old
 * decoder corrupts it silently — surfacing only as a checksum failure after the
 * whole transfer has run. Including `payloadFnv` also means a sender restarted
 * on the SAME file resumes into the same decoder, which is correct: identical
 * k, sessionId and seq produce an identical frame.
 */
export function streamIdentity(h: FrameHeader): string {
  return `${h.sessionId}:${h.k}:${h.blockLen}:${h.totalLen}:${h.payloadFnv}`;
}

export function fnv1a(bytes: Uint8Array): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i]!;
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** splitmix32 — deterministic across JS engines (integer ops only). */
export function splitmix32(seed: number): () => number {
  let s = seed | 0;
  return () => {
    s = (s + 0x9e3779b9) | 0;
    let t = s ^ (s >>> 16);
    t = Math.imul(t, 0x21f0aaad);
    t ^= t >>> 15;
    t = Math.imul(t, 0x735a2d97);
    t ^= t >>> 15;
    return t >>> 0;
  };
}
