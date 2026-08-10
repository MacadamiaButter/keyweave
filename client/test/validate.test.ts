import { describe, it, expect } from 'vitest';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import {
  validateEd25519Pub,
  validateX25519Pub,
  verifyEd25519,
  x25519IsSmallOrder,
} from '../src/validate.js';

describe('Ed25519 public-key validation', () => {
  it('accepts an honest public key', () => {
    const pub = ed25519.getPublicKey(new Uint8Array(32).fill(3));
    expect(() => validateEd25519Pub(pub)).not.toThrow();
  });

  it('rejects the neutral element (torsion-free is TRUE, small-order is the check that catches it)', () => {
    const neutral = new Uint8Array(32);
    neutral[0] = 1; // y=1, canonical
    const pt = ed25519.Point.fromBytes(neutral, false);
    // Demonstrate the trap the spec warns about:
    expect(pt.isTorsionFree()).toBe(true);
    expect(pt.isSmallOrder()).toBe(true);
    expect(() => validateEd25519Pub(neutral)).toThrow(/small-order/);
  });

  it('rejects a non-canonical encoding (value >= p)', () => {
    const nonCanonical = new Uint8Array(32).fill(0xff);
    nonCanonical[0] = 0xee;
    nonCanonical[31] = 0x7f;
    expect(() => validateEd25519Pub(nonCanonical)).toThrow(/ed25519 pub invalid/);
  });

  it('rejects a wrong length', () => {
    expect(() => validateEd25519Pub(new Uint8Array(31))).toThrow();
  });
});

describe('strict RFC 8032 verify (zip215:false) as an independent defense layer', () => {
  it('rejects the neutral/small-order-key forgery that zip215:true ACCEPTS', () => {
    // Bypass the card key-validation layer entirely and hit verifyEd25519 directly: the
    // {zip215:false} strict-verify must reject the neutral-element forgery on its own, so
    // it is pinned even if the small-order key check were ever removed (defense in depth).
    const neutral = new Uint8Array(32);
    neutral[0] = 1; // Edwards neutral element, y=1
    const forgedSig = new Uint8Array(64);
    forgedSig.set(neutral, 0); // sig = pk || 0x00*32
    const msg = new TextEncoder().encode('universal-forgery target');

    // The attack is REAL under noble's permissive default: zip215:true accepts it.
    expect(ed25519.verify(forgedSig, msg, neutral, { zip215: true })).toBe(true);
    // Our strict wrapper (zip215:false) rejects it, independent of key validation.
    expect(verifyEd25519(forgedSig, msg, neutral)).toBe(false);
  });
});

describe('X25519 public-key validation', () => {
  it('accepts an honest public key', () => {
    const pub = x25519.getPublicKey(new Uint8Array(32).fill(7));
    expect(x25519IsSmallOrder(pub)).toBe(false);
    expect(() => validateX25519Pub(pub)).not.toThrow();
  });

  it('rejects every known small-order u-coordinate', () => {
    const u0 = new Uint8Array(32); // 0
    const u1 = new Uint8Array(32);
    u1[0] = 1; // 1
    const order8a = Uint8Array.from([
      0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
      0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
      0xb8, 0x00,
    ]);
    const order8b = Uint8Array.from([
      0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
      0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
      0x11, 0x57,
    ]);
    const pMinus1 = new Uint8Array(32).fill(0xff);
    pMinus1[0] = 0xec;
    pMinus1[31] = 0x7f;
    for (const bad of [u0, u1, order8a, order8b, pMinus1]) {
      expect(x25519IsSmallOrder(bad)).toBe(true);
      expect(() => validateX25519Pub(bad)).toThrow(/x25519 pub invalid/);
    }
  });

  it('rejects a non-canonical value (high bit set / >= p)', () => {
    const highBit = x25519.getPublicKey(new Uint8Array(32).fill(4));
    highBit[31] |= 0x80;
    expect(() => validateX25519Pub(highBit)).toThrow(/non-canonical/);
    const pPlus1 = new Uint8Array(32).fill(0xff);
    pPlus1[0] = 0xee;
    pPlus1[31] = 0x7f;
    expect(() => validateX25519Pub(pPlus1)).toThrow(/x25519 pub invalid/);
  });
});
