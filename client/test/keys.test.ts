import { describe, it, expect } from 'vitest';
import {
  detectWebCryptoSupport,
  generateKeyManager,
  keyManagerFromSeeds,
} from '../src/keys.js';
import { verifyEd25519 } from '../src/validate.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { bytesEqual } from '../src/bytes.js';

const BACKENDS = ['noble', 'webcrypto'] as const;

describe('key manager (both backends)', () => {
  it('detects WebCrypto Secure Curves support in this runtime (Node 22)', async () => {
    expect(await detectWebCryptoSupport()).toBe(true);
  });

  for (const backend of BACKENDS) {
    it(`[${backend}] derives two INDEPENDENT keypairs from two separate seeds`, async () => {
      const idSeed = new Uint8Array(32).fill(1);
      const xSeed = new Uint8Array(32).fill(2);
      const km = await keyManagerFromSeeds(idSeed, xSeed, backend);
      expect(km.backend).toBe(backend);
      const idPub = km.identityPublicKey();
      const xPub = km.encryptionPublicKey();
      expect(idPub.length).toBe(32);
      expect(xPub.length).toBe(32);
      // Public keys match the standard derivation for the same seeds.
      expect(bytesEqual(idPub, ed25519.getPublicKey(idSeed))).toBe(true);
      expect(bytesEqual(xPub, x25519.getPublicKey(xSeed))).toBe(true);
      // The two keys are independent: identity pub != encryption pub.
      expect(bytesEqual(idPub, xPub)).toBe(false);
    });

    it(`[${backend}] signs verifiably (strict RFC 8032) and does DH symmetrically`, async () => {
      const A = await generateKeyManager(backend);
      const B = await generateKeyManager(backend);
      const msg = new TextEncoder().encode('attack at dawn');
      const sig = await A.manager.sign(msg);
      expect(sig.length).toBe(64);
      expect(verifyEd25519(sig, msg, A.manager.identityPublicKey())).toBe(true);
      // A tampered message fails.
      const bad = Uint8Array.from(msg);
      bad[0] ^= 1;
      expect(verifyEd25519(sig, bad, A.manager.identityPublicKey())).toBe(false);
      // DH is symmetric across managers.
      const ab = await A.manager.dh(B.manager.encryptionPublicKey());
      const ba = await B.manager.dh(A.manager.encryptionPublicKey());
      expect(bytesEqual(ab, ba)).toBe(true);
    });

    it(`[${backend}] destroy() disables signing AND dh, identically on both backends`, async () => {
      // This test used to encode a divergence: noble threw, webcrypto kept working because
      // a non-extractable CryptoKey has no bytes to wipe. But destroy() is called by
      // Vault.lock(), and a caller holding a cached manager across a lock would then keep
      // signing on the backend `auto` actually selects in a browser. Wiping and revoking
      // are different jobs; the platform only lets us do the second one here, and it is
      // the one lock() depends on. Both backends now mean the same thing by destroy().
      const A = await generateKeyManager(backend);
      const peer = await generateKeyManager(backend);
      const peerPub = peer.manager.encryptionPublicKey();

      // Positive control: usable before destroy, so the rejection below is not a manager
      // that never worked.
      await expect(A.manager.sign(new Uint8Array([1]))).resolves.toBeInstanceOf(Uint8Array);
      await expect(A.manager.dh(peerPub)).resolves.toBeInstanceOf(Uint8Array);

      A.manager.destroy();

      await expect(A.manager.sign(new Uint8Array([1]))).rejects.toThrow(/destroyed/);
      await expect(A.manager.dh(peerPub)).rejects.toThrow(/destroyed/);

      // Public keys stay readable: they are public, and a locked contact list still needs
      // to render who you paired with.
      expect(A.manager.identityPublicKey()).toBeInstanceOf(Uint8Array);
    });
  }

  it('a WebCrypto-signed message verifies with the noble public key (cross-backend)', async () => {
    const seedId = new Uint8Array(32).fill(9);
    const seedX = new Uint8Array(32).fill(8);
    const wc = await keyManagerFromSeeds(seedId, seedX, 'webcrypto');
    const nb = await keyManagerFromSeeds(seedId, seedX, 'noble');
    expect(bytesEqual(wc.identityPublicKey(), nb.identityPublicKey())).toBe(true);
    const msg = new TextEncoder().encode('cross-backend');
    const sig = await wc.sign(msg);
    expect(verifyEd25519(sig, msg, nb.identityPublicKey())).toBe(true);
  });
});
