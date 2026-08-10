// Byte helpers. No secret-dependent branching in the compare/zeroize paths.

const HEX = '0123456789abcdef';

export function toHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) {
    const v = b[i]!;
    s += HEX[v >> 4]! + HEX[v & 15]!;
  }
  return s;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('fromHex: odd length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const v = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(v)) throw new Error('fromHex: non-hex');
    out[i] = v;
  }
  return out;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** Constant-time equality for two equal-length (or not) byte strings. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Length itself is not secret here, but avoid an early return that leaks it via timing.
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/** Plain (non-constant-time) equality, fine for non-secret comparisons. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Lexicographic (unsigned, big-endian byte order) comparison.
 * Returns <0 if a<b, 0 if equal, >0 if a>b.
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const d = a[i]! - b[i]!;
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/** Return [min, max] of two byte strings by lexicographic order (order-independent pairing). */
export function sortPair(a: Uint8Array, b: Uint8Array): [Uint8Array, Uint8Array] {
  return compareBytes(a, b) <= 0 ? [a, b] : [b, a];
}

/** Best-effort in-place zeroization. See NAMED-RESIDUALS R5: JS cannot guarantee this. */
export function zeroize(...arrays: (Uint8Array | undefined)[]): void {
  for (const a of arrays) if (a) a.fill(0);
}

export function assertLength(b: Uint8Array, len: number, label: string): void {
  if (!(b instanceof Uint8Array)) throw new Error(`${label}: not a byte string`);
  if (b.length !== len) throw new Error(`${label}: expected ${len} bytes, got ${b.length}`);
}

const enc = new TextEncoder();
export function utf8(s: string): Uint8Array {
  return enc.encode(s);
}
