// Key management: two INDEPENDENT keypairs from two separate 32-byte seeds -
// Ed25519 identity (RFC 8032) and X25519 encryption (RFC 7748).
//
// Defense-in-depth (must-fix #9 / anchor `defdepth`): long-term private keys are
// held as NON-EXTRACTABLE WebCrypto CryptoKeys where the runtime supports Secure
// Curves, so a later-served malicious bundle can only *oracle* while resident, it
// cannot exfiltrate raw key bytes and decrypt forever offline. @noble is a LABELED
// degraded fallback (still correct, just extractable in JS memory). Both paths are
// exercised by the test suite.
//
// Seeds are the only serialized secret; they live encrypted in the vault. The live
// private KEY (WebCrypto path) is never extractable.

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/hashes/utils.js';
import {
  ED25519_PUB_LEN,
  ED25519_SIG_LEN,
  SEED_LEN,
  X25519_PUB_LEN,
  type KeyBackend,
} from './constants.js';
import { assertLength, zeroize } from './bytes.js';

// RFC 8410 PKCS#8 prefixes for a raw 32-byte private key (OneAsymmetricKey, v1).
// SEQ, INTEGER 0, SEQ{ OID }, OCTET STRING{ OCTET STRING{ seed } }
const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const PKCS8_X25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function pkcs8(prefix: Uint8Array, seed: Uint8Array): Uint8Array {
  const out = new Uint8Array(prefix.length + seed.length);
  out.set(prefix);
  out.set(seed, prefix.length);
  return out;
}

function subtle(): SubtleCrypto | undefined {
  return globalThis.crypto?.subtle;
}

// WebCrypto wants an ArrayBuffer-backed BufferSource; hand it a fresh copy so we never
// pass a possibly-SharedArrayBuffer-backed view (also keeps the type checker happy).
function ab(u: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(u.length);
  out.set(u);
  return out.buffer;
}

/** Attempt a real non-extractable Ed25519 + X25519 import; true only if it works. */
export async function detectWebCryptoSupport(): Promise<boolean> {
  const s = subtle();
  if (!s) return false;
  try {
    const seed = new Uint8Array(SEED_LEN); // all-zero probe seed, discarded
    const idKey = await s.importKey('pkcs8', ab(pkcs8(PKCS8_ED25519_PREFIX, seed)), 'Ed25519', false, [
      'sign',
    ]);
    await s.sign('Ed25519', idKey, ab(new Uint8Array([0])));
    const xKey = await s.importKey('pkcs8', ab(pkcs8(PKCS8_X25519_PREFIX, seed)), 'X25519', false, [
      'deriveBits',
    ]);
    const peer = x25519.getPublicKey(new Uint8Array(SEED_LEN).fill(1));
    const peerKey = await s.importKey('raw', ab(peer), 'X25519', false, []);
    await s.deriveBits({ name: 'X25519', public: peerKey }, xKey, 256);
    return true;
  } catch {
    return false;
  }
}

export interface KeyManager {
  readonly backend: KeyBackend;
  /** Ed25519 identity public key (32 bytes). This IS the identity id. */
  identityPublicKey(): Uint8Array;
  /** X25519 encryption public key (32 bytes). */
  encryptionPublicKey(): Uint8Array;
  /** Ed25519 signature (64 bytes) over `message`. */
  sign(message: Uint8Array): Promise<Uint8Array>;
  /** Raw X25519 shared secret (32 bytes) with a validated peer public key. */
  dh(peerEncryptionPub: Uint8Array): Promise<Uint8Array>;
  /** Best-effort wipe of any retained secret material (noble backend only). */
  destroy(): void;
}

type BackendChoice = 'auto' | KeyBackend;

/**
 * Build a KeyManager from two independent 32-byte seeds. Inputs are COPIED; the
 * caller keeps ownership of (and should zeroize) the passed-in seeds.
 */
export async function keyManagerFromSeeds(
  identitySeed: Uint8Array,
  encryptionSeed: Uint8Array,
  choice: BackendChoice = 'auto',
): Promise<KeyManager> {
  assertLength(identitySeed, SEED_LEN, 'identitySeed');
  assertLength(encryptionSeed, SEED_LEN, 'encryptionSeed');

  const idPub = ed25519.getPublicKey(identitySeed);
  const xPub = x25519.getPublicKey(encryptionSeed);
  assertLength(idPub, ED25519_PUB_LEN, 'identityPub');
  assertLength(xPub, X25519_PUB_LEN, 'encryptionPub');

  let useWebCrypto: boolean;
  if (choice === 'webcrypto') {
    if (!(await detectWebCryptoSupport())) {
      throw new Error('keys: WebCrypto Secure Curves not available in this runtime');
    }
    useWebCrypto = true;
  } else if (choice === 'noble') {
    useWebCrypto = false;
  } else {
    useWebCrypto = await detectWebCryptoSupport();
  }

  if (useWebCrypto) return webCryptoManager(identitySeed, encryptionSeed, idPub, xPub);
  return nobleManager(identitySeed, encryptionSeed, idPub, xPub);
}

/** Generate two fresh independent seeds and a KeyManager. Caller must persist + zeroize the seeds. */
export async function generateKeyManager(
  choice: BackendChoice = 'auto',
): Promise<{ manager: KeyManager; identitySeed: Uint8Array; encryptionSeed: Uint8Array }> {
  const identitySeed = randomBytes(SEED_LEN);
  const encryptionSeed = randomBytes(SEED_LEN);
  const manager = await keyManagerFromSeeds(identitySeed, encryptionSeed, choice);
  return { manager, identitySeed, encryptionSeed };
}

async function webCryptoManager(
  identitySeed: Uint8Array,
  encryptionSeed: Uint8Array,
  idPub: Uint8Array,
  xPub: Uint8Array,
): Promise<KeyManager> {
  const s = subtle();
  if (!s) throw new Error('keys: WebCrypto unavailable');
  const idPkcs8 = pkcs8(PKCS8_ED25519_PREFIX, identitySeed);
  const xPkcs8 = pkcs8(PKCS8_X25519_PREFIX, encryptionSeed);
  const idKey = await s.importKey('pkcs8', ab(idPkcs8), 'Ed25519', false, ['sign']);
  const xKey = await s.importKey('pkcs8', ab(xPkcs8), 'X25519', false, ['deriveBits']);
  // The PKCS8 buffers held plaintext seeds; wipe them (the CryptoKeys are non-extractable now).
  zeroize(idPkcs8, xPkcs8);

  const idPubCopy = Uint8Array.from(idPub);
  const xPubCopy = Uint8Array.from(xPub);
  let destroyed = false;

  return {
    backend: 'webcrypto',
    identityPublicKey: () => Uint8Array.from(idPubCopy),
    encryptionPublicKey: () => Uint8Array.from(xPubCopy),
    async sign(message: Uint8Array): Promise<Uint8Array> {
      if (destroyed) throw new Error('keys: manager destroyed');
      const sig = new Uint8Array(await s.sign('Ed25519', idKey, ab(message)));
      assertLength(sig, ED25519_SIG_LEN, 'signature');
      return sig;
    },
    async dh(peerEncryptionPub: Uint8Array): Promise<Uint8Array> {
      if (destroyed) throw new Error('keys: manager destroyed');
      assertLength(peerEncryptionPub, X25519_PUB_LEN, 'peerEncryptionPub');
      const peerKey = await s.importKey('raw', ab(peerEncryptionPub), 'X25519', false, []);
      const shared = new Uint8Array(await s.deriveBits({ name: 'X25519', public: peerKey }, xKey, 256));
      assertLength(shared, X25519_PUB_LEN, 'sharedSecret');
      return shared;
    },
    destroy(): void {
      // There are no JS-visible key bytes to wipe: the CryptoKeys are non-extractable, and
      // dropping the handles is all the platform allows. The flag is the part that matters.
      // Without it this backend and the noble one disagree about what destroy() MEANS: a
      // caller holding a cached manager across Vault.lock() would keep signing and deriving
      // here while the same code throws on the fallback. `auto` picks this backend in every
      // current browser, so the divergence would land on exactly the path that ships.
      // Same class as the ReplayGuard cached-reference defect, and the same remedy.
      destroyed = true;
    },
  };
}

async function nobleManager(
  identitySeed: Uint8Array,
  encryptionSeed: Uint8Array,
  idPub: Uint8Array,
  xPub: Uint8Array,
): Promise<KeyManager> {
  // LABELED degraded fallback: the private seeds are retained in JS memory.
  const idSeed = Uint8Array.from(identitySeed);
  const xSeed = Uint8Array.from(encryptionSeed);
  const idPubCopy = Uint8Array.from(idPub);
  const xPubCopy = Uint8Array.from(xPub);
  let destroyed = false;

  return {
    backend: 'noble',
    identityPublicKey: () => Uint8Array.from(idPubCopy),
    encryptionPublicKey: () => Uint8Array.from(xPubCopy),
    async sign(message: Uint8Array): Promise<Uint8Array> {
      if (destroyed) throw new Error('keys: manager destroyed');
      const sig = ed25519.sign(message, idSeed);
      assertLength(sig, ED25519_SIG_LEN, 'signature');
      return sig;
    },
    async dh(peerEncryptionPub: Uint8Array): Promise<Uint8Array> {
      if (destroyed) throw new Error('keys: manager destroyed');
      assertLength(peerEncryptionPub, X25519_PUB_LEN, 'peerEncryptionPub');
      const shared = x25519.getSharedSecret(xSeed, peerEncryptionPub);
      assertLength(shared, X25519_PUB_LEN, 'sharedSecret');
      return shared;
    },
    destroy(): void {
      destroyed = true;
      zeroize(idSeed, xSeed);
    },
  };
}
