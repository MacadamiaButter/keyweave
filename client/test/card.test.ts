import { describe, it, expect } from 'vitest';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard, importCard } from '../src/card.js';
import { encodeDeterministic } from '../src/cbor.js';
import { CTX_CARD } from '../src/constants.js';
import { concatBytes } from '../src/bytes.js';

// Assemble a raw SignedCard from explicit parts (used to build forgeries).
function packSignedCard(
  version: number,
  identityPub: Uint8Array,
  encryptionPub: Uint8Array,
  serial: number,
  sig: Uint8Array,
): Uint8Array {
  const cardBytes = encodeDeterministic(
    new Map<number, unknown>([
      [0, version],
      [1, identityPub],
      [2, encryptionPub],
      [3, serial],
    ]),
  );
  return encodeDeterministic(
    new Map<number, unknown>([
      [0, cardBytes],
      [1, sig],
    ]),
  );
}

const validX25519 = () => x25519.getPublicKey(new Uint8Array(32).fill(5));
// The Edwards neutral element: y = 1, encoded 0x01 || 0x00*31. Canonical, torsion-free,
// but small order - the exact point that a torsion-only check misses.
const NEUTRAL = (() => {
  const b = new Uint8Array(32);
  b[0] = 1;
  return b;
})();

describe('contact card import validation', () => {
  it('an honest signed card imports and is authentic', async () => {
    const A = await generateKeyManager('noble');
    const signed = await createSignedCard(A.manager, 1);
    const card = importCard(signed);
    expect(card.version).toBe(1);
    expect(card.serial).toBe(1);
    expect(Buffer.from(card.identityPub).equals(Buffer.from(A.manager.identityPublicKey()))).toBe(true);
    expect(Buffer.from(card.encryptionPub).equals(Buffer.from(A.manager.encryptionPublicKey()))).toBe(true);
  });

  it('[CRITICAL] rejects a small-order (neutral) identity_pub forgery that VERIFIES under zip215:true', () => {
    // The forgery from the spec: identity_pub = neutral, sig = pk || 0x00*32.
    const forgedSig = new Uint8Array(64);
    forgedSig.set(NEUTRAL, 0);
    const signed = packSignedCard(1, NEUTRAL, validX25519(), 1, forgedSig);

    // Prove the attack is REAL: permissive (ZIP-215) verification accepts the forged sig.
    // Recompute the exact signed message the card layer uses.
    const cardBytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1],
        [1, NEUTRAL],
        [2, validX25519()],
        [3, 1],
      ]),
    );
    expect(ed25519.verify(forgedSig, concatBytes(CTX_CARD, cardBytes), NEUTRAL, { zip215: true })).toBe(
      true,
    );

    // Our import REJECTS it at key validation (small-order), before ever trusting the sig.
    expect(() => importCard(signed)).toThrow(/small-order/);
  });

  it('rejects a non-canonical identity_pub encoding (p+1 form of the neutral)', () => {
    const nonCanonical = new Uint8Array(32).fill(0xff);
    nonCanonical[0] = 0xee; // p+1, top bit clear -> non-canonical encoding of y=1
    nonCanonical[31] = 0x7f;
    const sig = new Uint8Array(64);
    const signed = packSignedCard(1, nonCanonical, validX25519(), 1, sig);
    expect(() => importCard(signed)).toThrow(/ed25519 pub invalid/);
  });

  it('rejects a small-order encryption_pub (all-zero X25519)', async () => {
    const A = await generateKeyManager('noble');
    const idPub = A.manager.identityPublicKey();
    const smallOrderX = new Uint8Array(32); // u = 0
    const cardBytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1],
        [1, idPub],
        [2, smallOrderX],
        [3, 1],
      ]),
    );
    const sig = await A.manager.sign(concatBytes(CTX_CARD, cardBytes));
    const signed = packSignedCard(1, idPub, smallOrderX, 1, sig);
    expect(() => importCard(signed)).toThrow(/x25519 pub invalid: small-order/);
  });

  it('rejects a card that equals our own identity key (self-import guard)', async () => {
    const A = await generateKeyManager('noble');
    const signed = await createSignedCard(A.manager, 1);
    expect(() =>
      importCard(signed, {
        ownIdentityPub: A.manager.identityPublicKey(),
        ownEncryptionPub: A.manager.encryptionPublicKey(),
      }),
    ).toThrow(/equals our own/);
  });

  it('self-guard fires on OUR identity_pub even with a DIFFERENT encryption_pub', async () => {
    // Pins the identity self-guard independently: a card carrying our identity key but some
    // OTHER (valid) encryption key must still be rejected as ours. (Fails if the identity
    // != own-key check is removed, since the different encryption key would pass its guard.)
    const A = await generateKeyManager('noble');
    const idPub = A.manager.identityPublicKey();
    const otherX = x25519.getPublicKey(new Uint8Array(32).fill(6)); // != A's encryption key
    const cardBytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1],
        [1, idPub],
        [2, otherX],
        [3, 1],
      ]),
    );
    const sig = await A.manager.sign(concatBytes(CTX_CARD, cardBytes));
    const signed = packSignedCard(1, idPub, otherX, 1, sig);
    expect(() =>
      importCard(signed, {
        ownIdentityPub: idPub,
        ownEncryptionPub: A.manager.encryptionPublicKey(),
      }),
    ).toThrow(/equals our own identity/);
  });

  it('self-guard fires on OUR encryption_pub even under a DIFFERENT identity_pub', async () => {
    // Pins the encryption self-guard independently: a card signed by a DIFFERENT identity
    // but advertising OUR encryption key must be rejected (a transplant of our x-key).
    const A = await generateKeyManager('noble');
    const B = await generateKeyManager('noble');
    const bId = B.manager.identityPublicKey();
    const ourX = A.manager.encryptionPublicKey();
    const cardBytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1],
        [1, bId],
        [2, ourX],
        [3, 1],
      ]),
    );
    const sig = await B.manager.sign(concatBytes(CTX_CARD, cardBytes));
    const signed = packSignedCard(1, bId, ourX, 1, sig);
    expect(() =>
      importCard(signed, {
        ownIdentityPub: A.manager.identityPublicKey(),
        ownEncryptionPub: ourX,
      }),
    ).toThrow(/equals our own encryption/);
  });

  it('rejects a valid-key card whose signature does not verify (strict RFC 8032)', async () => {
    const A = await generateKeyManager('noble');
    const idPub = A.manager.identityPublicKey();
    const xPub = A.manager.encryptionPublicKey();
    const bogusSig = new Uint8Array(64).fill(7); // not a real signature
    const signed = packSignedCard(1, idPub, xPub, 1, bogusSig);
    expect(() => importCard(signed)).toThrow(/signature verification failed/);
  });

  it('rejects unknown map keys / wrong types in the card', async () => {
    const A = await generateKeyManager('noble');
    const idPub = A.manager.identityPublicKey();
    const xPub = A.manager.encryptionPublicKey();
    const cardBytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1],
        [1, idPub],
        [2, xPub],
        [3, 1],
        [9, 42], // unknown key
      ]),
    );
    const sig = await A.manager.sign(concatBytes(CTX_CARD, cardBytes));
    const signed = encodeDeterministic(
      new Map<number, unknown>([
        [0, cardBytes],
        [1, sig],
      ]),
    );
    expect(() => importCard(signed)).toThrow(/unknown map key 9/);
  });

  it('rejects an unsupported card version', async () => {
    const A = await generateKeyManager('noble');
    const idPub = A.manager.identityPublicKey();
    const xPub = A.manager.encryptionPublicKey();
    const cardBytes = encodeDeterministic(
      new Map<number, unknown>([
        [0, 2], // unsupported
        [1, idPub],
        [2, xPub],
        [3, 1],
      ]),
    );
    const sig = await A.manager.sign(concatBytes(CTX_CARD, cardBytes));
    const signed = encodeDeterministic(
      new Map<number, unknown>([
        [0, cardBytes],
        [1, sig],
      ]),
    );
    expect(() => importCard(signed)).toThrow(/unsupported version 2/);
  });
});
