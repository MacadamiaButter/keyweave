import { describe, it, expect } from 'vitest';
import { encode as cborEncode } from 'cbor2';
import { decodeMapExact, decodeStrict, encodeDeterministic } from '../src/cbor.js';

describe('strict dCBOR decode', () => {
  it('round-trips an integer-keyed map as a Map, canonically', () => {
    const m = new Map<number, unknown>([
      [0, 1],
      [1, new Uint8Array([1, 2, 3])],
      [2, 7],
    ]);
    const enc = encodeDeterministic(m);
    const dec = decodeStrict<Map<number, unknown>>(enc);
    expect(dec).toBeInstanceOf(Map);
    expect([...dec.keys()]).toEqual([0, 1, 2]);
    // Canonical re-encode equality.
    expect(Buffer.from(encodeDeterministic(dec)).equals(Buffer.from(enc))).toBe(true);
  });

  it('rejects out-of-order / duplicate map keys', () => {
    // a2 (map of 2) with keys 1 then 0 (out of order)
    const badOrder = Buffer.concat([
      Buffer.from([0xa2, 0x01]),
      Buffer.from(cborEncode(1)),
      Buffer.from([0x00]),
      Buffer.from(cborEncode(2)),
    ]);
    expect(() => decodeStrict(badOrder)).toThrow();
    const dup = Buffer.concat([
      Buffer.from([0xa2, 0x00]),
      Buffer.from(cborEncode(1)),
      Buffer.from([0x00]),
      Buffer.from(cborEncode(2)),
    ]);
    expect(() => decodeStrict(dup)).toThrow();
  });

  it('rejects non-minimal integer encodings and trailing data', () => {
    expect(() => decodeStrict(new Uint8Array([0x18, 0x00]))).toThrow(); // uint 0 in a long form
    expect(() => decodeStrict(new Uint8Array([0x00, 0x00]))).toThrow(); // trailing byte
  });
});

describe('decodeMapExact schema enforcement', () => {
  const schema = {
    0: { type: 'uint' as const, max: 255 },
    1: { type: 'bytes' as const, len: 4 },
  };

  it('accepts a well-formed map', () => {
    const bytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, 3],
        [1, new Uint8Array([1, 2, 3, 4])],
      ]),
    );
    const m = decodeMapExact(bytes, schema);
    expect(m.get(0)).toBe(3);
  });

  it('rejects an unknown map key', () => {
    const bytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, 3],
        [1, new Uint8Array([1, 2, 3, 4])],
        [2, 9],
      ]),
    );
    expect(() => decodeMapExact(bytes, schema)).toThrow(/unknown map key 2/);
  });

  it('rejects a missing required key', () => {
    const bytes = encodeDeterministic(new Map<number, unknown>([[0, 3]]));
    expect(() => decodeMapExact(bytes, schema)).toThrow(/missing required key 1/);
  });

  it('rejects wrong value type', () => {
    const bytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, new Uint8Array([1])], // should be uint
        [1, new Uint8Array([1, 2, 3, 4])],
      ]),
    );
    expect(() => decodeMapExact(bytes, schema)).toThrow(/non-negative integer/);
  });

  it('rejects an out-of-range byte length', () => {
    const bytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, 3],
        [1, new Uint8Array([1, 2, 3])], // len 3, schema wants 4
      ]),
    );
    expect(() => decodeMapExact(bytes, schema)).toThrow(/must be 4 bytes/);
  });

  it('rejects a uint above its max', () => {
    const bytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, 300],
        [1, new Uint8Array([1, 2, 3, 4])],
      ]),
    );
    expect(() => decodeMapExact(bytes, schema)).toThrow(/exceeds max 255/);
  });
});
