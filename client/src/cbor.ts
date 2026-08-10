// Strict, deterministic CBOR (dCBOR) encode/decode with schema validation.
//
// Must-fix #5 (replay/malleability): every piece of UNTRUSTED CBOR is decoded
// with dcbor canonical enforcement AND validated against an exact schema -
// unknown map keys, wrong types, and out-of-range lengths are all rejected, at
// BOTH the envelope and the attacker-controlled inner layers. The relay cannot
// re-encode an authenticated blob into a new accepted wire form.

import { encode as cborEncode, decode as cborDecode } from 'cbor2';

// dCBOR canonical encode. Deterministic key ordering + minimal integer forms.
export function encodeDeterministic(value: unknown): Uint8Array {
  return cborEncode(value, { dcbor: true });
}

// Strict decode: canonical form enforced (rejects non-minimal ints, out-of-order
// or duplicate keys, trailing data, non-canonical floats, indefinite-length
// streaming). Integer-keyed maps come back as `Map`.
export function decodeStrict<T = unknown>(bytes: Uint8Array): T {
  return cborDecode<T>(bytes, {
    dcbor: true,
    preferMap: true,
    rejectDuplicateKeys: true,
    rejectStreaming: true,
  });
}

/**
 * Decode to a Map with an EXACT integer-key schema. Throws on any deviation:
 * not a map, unknown key present, required key missing, wrong value type, or a
 * byte-string length outside the allowed range.
 */
export interface FieldSpec {
  type: 'uint' | 'bytes' | 'array';
  /** For 'bytes': exact length, or [min,max] inclusive. */
  len?: number | [number, number];
  /** For 'uint': inclusive max (min is always 0). */
  max?: number;
  /**
   * If true, a MISSING key is allowed (it is simply absent from the result). A key
   * that IS present is still fully validated. Used for versioned formats where a
   * newer field is absent in an older-format blob (e.g. vault v1 has no seen-set).
   * Strictness is otherwise unchanged: unknown keys and required-missing keys throw.
   */
  optional?: boolean;
}

export function decodeMapExact(
  bytes: Uint8Array,
  schema: Record<number, FieldSpec>,
): Map<number, unknown> {
  const decoded = decodeStrict<unknown>(bytes);
  if (!(decoded instanceof Map)) throw new Error('cbor: expected a map');
  const m = decoded as Map<unknown, unknown>;

  // Reject any key that is not an allowed integer key.
  const allowed = new Set(Object.keys(schema).map((k) => Number(k)));
  for (const key of m.keys()) {
    if (typeof key !== 'number' || !Number.isInteger(key)) {
      throw new Error(`cbor: non-integer map key ${String(key)}`);
    }
    if (!allowed.has(key)) throw new Error(`cbor: unknown map key ${key}`);
  }

  const out = new Map<number, unknown>();
  for (const [rawKey, spec] of Object.entries(schema)) {
    const key = Number(rawKey);
    if (!m.has(key)) {
      if (spec.optional) continue;
      throw new Error(`cbor: missing required key ${key}`);
    }
    const val = m.get(key);
    validateField(key, val, spec);
    out.set(key, val);
  }
  return out;
}

function validateField(key: number, val: unknown, spec: FieldSpec): void {
  switch (spec.type) {
    case 'uint': {
      if (typeof val !== 'number' || !Number.isInteger(val) || val < 0) {
        throw new Error(`cbor: key ${key} must be a non-negative integer`);
      }
      if (!Number.isSafeInteger(val)) throw new Error(`cbor: key ${key} integer out of safe range`);
      if (spec.max !== undefined && val > spec.max) {
        throw new Error(`cbor: key ${key} integer ${val} exceeds max ${spec.max}`);
      }
      return;
    }
    case 'bytes': {
      if (!(val instanceof Uint8Array)) throw new Error(`cbor: key ${key} must be a byte string`);
      if (spec.len !== undefined) {
        if (typeof spec.len === 'number') {
          if (val.length !== spec.len) {
            throw new Error(`cbor: key ${key} must be ${spec.len} bytes, got ${val.length}`);
          }
        } else {
          const [min, max] = spec.len;
          if (val.length < min || val.length > max) {
            throw new Error(`cbor: key ${key} length ${val.length} outside [${min},${max}]`);
          }
        }
      }
      return;
    }
    case 'array': {
      if (!Array.isArray(val)) throw new Error(`cbor: key ${key} must be an array`);
      return;
    }
  }
}

export function getBytes(m: Map<number, unknown>, key: number): Uint8Array {
  const v = m.get(key);
  if (!(v instanceof Uint8Array)) throw new Error(`cbor: key ${key} is not bytes`);
  return v;
}

export function getUint(m: Map<number, unknown>, key: number): number {
  const v = m.get(key);
  if (typeof v !== 'number') throw new Error(`cbor: key ${key} is not a number`);
  return v;
}
