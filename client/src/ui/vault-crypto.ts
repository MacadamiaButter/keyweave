// Where the Argon2id pass happens.
//
// ARGON2_DEFAULT is 256 MiB over 3 passes, tuned for offline device-theft cracking rather
// than a server login. Measured on the reference box: 3.2 seconds, synchronous. On the UI
// thread that is a frozen page during unlock and again during every save, so the browser
// runs it in a worker (vault-worker.ts) and this file is the seam.
//
// LocalVaultCrypto is the same operations inline. It is what the suite drives, and it is
// the fallback when Worker is not available at all. It is honest about what it costs.
//
// The passphrase is held HERE and nowhere else: unlock hands it in once, saves reuse it,
// and forget() drops it. In the worker deployment that means the string never exists on
// the UI thread after the input is cleared. That is a leastpriv boundary, not a defense
// against a compromised bundle (R1): a bundle that is already lying can read the keystroke.

import {
  ARGON2_DEFAULT,
  createVaultBlob,
  decryptVaultBlob,
  type Argon2Params,
  type VaultData,
} from '../vault.js';
import { SEED_LEN } from '../constants.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { zeroize } from '../bytes.js';

export interface VaultCrypto {
  /** Fresh identity: two independent seeds, an empty vault, sealed and opened in one pass. */
  createIdentity(passphrase: string): Promise<{ blob: Uint8Array; data: VaultData }>;
  unlock(blob: Uint8Array, passphrase: string): Promise<VaultData>;
  /** Re-seal with the passphrase this crypto is already holding. */
  seal(data: VaultData): Promise<Uint8Array>;
  forget(): void;
}

function emptyVaultData(identitySeed: Uint8Array, encryptionSeed: Uint8Array): VaultData {
  return {
    identitySeed,
    encryptionSeed,
    contacts: [],
    highWater: [],
    seen: [],
    messages: [],
    mailboxes: [],
  };
}

export class LocalVaultCrypto implements VaultCrypto {
  private passphrase: string | undefined;

  constructor(private readonly params: Argon2Params = ARGON2_DEFAULT) {}

  async createIdentity(passphrase: string): Promise<{ blob: Uint8Array; data: VaultData }> {
    // Two independent seeds, never one seed derived twice: coupling signature and DH
    // failure modes was rejected at design time and stays rejected here.
    const identitySeed = randomBytes(SEED_LEN);
    const encryptionSeed = randomBytes(SEED_LEN);
    const data = emptyVaultData(identitySeed, encryptionSeed);
    const blob = createVaultBlob(passphrase, data, this.params);
    this.passphrase = passphrase;
    // The caller opens the session from `data`; the seeds in it are the live copies.
    return { blob, data };
  }

  async unlock(blob: Uint8Array, passphrase: string): Promise<VaultData> {
    const data = decryptVaultBlob(blob, passphrase);
    this.passphrase = passphrase;
    return data;
  }

  async seal(data: VaultData): Promise<Uint8Array> {
    if (this.passphrase === undefined) throw new Error('vault-crypto: locked');
    return createVaultBlob(this.passphrase, data, this.params);
  }

  forget(): void {
    this.passphrase = undefined;
  }
}

/**
 * Best-effort wipe of the seed copies a transport (postMessage, or a test) left behind.
 * Named residual R5 applies unchanged: JavaScript cannot guarantee zeroization.
 */
export function wipeVaultData(data: VaultData): void {
  zeroize(data.identitySeed, data.encryptionSeed);
}
