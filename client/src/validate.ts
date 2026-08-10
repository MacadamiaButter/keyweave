// Strict public-key validation. Must-fix #1 (CRITICAL): an unvalidated import is a
// UNIVERSAL FORGERY - a card carrying the neutral point as identity_pub with
// sig = pk||0x00*32 VERIFIES under noble's permissive default (zip215:true).
// Anchor `kerckhoffs`: we never assume the peer/relay hands us a well-formed key.
//
// For Ed25519 identity keys:
//   (a) canonical re-encode equality: Point.fromBytes(pk).toBytes() === pk
//   (b) isSmallOrder() === false  (isTorsionFree() ALONE PASSES the neutral element
//       0x01||0x00*31 - it has order 1, is in the prime subgroup, so torsion-free is
//       true; only the small-order test rejects it)
//   (c) != our own key
//   and every signature is verified with { zip215:false } (strict RFC 8032).
//
// For X25519 encryption keys we do NOT inherit low-order rejection from a library
// version: canonical (bit 255 clear, value < p) + explicit small-order blocklist.

import { ed25519 } from '@noble/curves/ed25519.js';
import { X25519_PUB_LEN } from './constants.js';
import { assertLength, bytesEqual } from './bytes.js';

const Point = ed25519.Point;

export function validateEd25519Pub(pk: Uint8Array, ownPub?: Uint8Array): void {
  assertLength(pk, 32, 'ed25519 pub');
  let pt: ReturnType<typeof Point.fromBytes>;
  try {
    pt = Point.fromBytes(pk, false); // strict: throws on non-canonical / off-curve
  } catch (e) {
    throw new Error(`ed25519 pub invalid: not a canonical point (${(e as Error).message})`);
  }
  if (!bytesEqual(pt.toBytes(), pk)) {
    throw new Error('ed25519 pub invalid: non-canonical encoding (re-encode mismatch)');
  }
  if (pt.isSmallOrder()) {
    throw new Error('ed25519 pub invalid: small-order point (includes the neutral element)');
  }
  if (ownPub && bytesEqual(pk, ownPub)) {
    throw new Error('ed25519 pub invalid: equals our own identity key');
  }
}

/** Strict RFC 8032 verification (rejects the small-order/non-canonical forgeries). */
export function verifyEd25519(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, msg, pub, { zip215: false });
  } catch {
    return false;
  }
}

// ---- X25519 canonical + small-order validation ----

// p = 2^255 - 19, little-endian.
const P_LE = (() => {
  const p = new Uint8Array(32).fill(0xff);
  p[0] = 0xed;
  p[31] = 0x7f;
  return p;
})();

// Little-endian unsigned compare: true iff a < b.
function leLessThan(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 31; i >= 0; i--) {
    if (a[i]! < b[i]!) return true;
    if (a[i]! > b[i]!) return false;
  }
  return false; // equal
}

// Curve25519 small-order u-coordinate blocklist (libsodium `has_small_order`),
// canonical little-endian, top bit already clear. Covers points of order 1,2,4,8 on
// the curve and its twist.
const SMALL_ORDER_X25519: readonly Uint8Array[] = [
  // 0 (order 4)
  new Uint8Array(32),
  // 1 (order 1)
  (() => {
    const b = new Uint8Array(32);
    b[0] = 1;
    return b;
  })(),
  // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
  Uint8Array.from([
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
  ]),
  // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
  Uint8Array.from([
    0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
    0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
  ]),
  // p-1 (order 2)
  (() => {
    const b = new Uint8Array(32).fill(0xff);
    b[0] = 0xec;
    b[31] = 0x7f;
    return b;
  })(),
  // p (=0, order 4)
  (() => {
    const b = new Uint8Array(32).fill(0xff);
    b[0] = 0xed;
    b[31] = 0x7f;
    return b;
  })(),
  // p+1 (=1, order 1)
  (() => {
    const b = new Uint8Array(32).fill(0xff);
    b[0] = 0xee;
    b[31] = 0x7f;
    return b;
  })(),
];

export function x25519IsSmallOrder(u: Uint8Array): boolean {
  const masked = Uint8Array.from(u);
  masked[31] = masked[31]! & 0x7f; // ignore the sign/high bit like RFC 7748 decode
  let hit = 0;
  for (const bad of SMALL_ORDER_X25519) {
    let diff = 0;
    for (let i = 0; i < 32; i++) diff |= masked[i]! ^ bad[i]!;
    hit |= diff === 0 ? 1 : 0;
  }
  return hit === 1;
}

export function validateX25519Pub(pk: Uint8Array, ownPub?: Uint8Array): void {
  assertLength(pk, X25519_PUB_LEN, 'x25519 pub');
  // Canonical: high bit clear AND value < p (reject p, p+1, and any high-bit-set form).
  if ((pk[31]! & 0x80) !== 0) {
    throw new Error('x25519 pub invalid: non-canonical (high bit set)');
  }
  if (!leLessThan(pk, P_LE)) {
    throw new Error('x25519 pub invalid: non-canonical (value >= p)');
  }
  if (x25519IsSmallOrder(pk)) {
    throw new Error('x25519 pub invalid: small-order point');
  }
  if (ownPub && bytesEqual(pk, ownPub)) {
    throw new Error('x25519 pub invalid: equals our own encryption key');
  }
}
