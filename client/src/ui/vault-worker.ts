// The Argon2id worker. A thin message loop around LocalVaultCrypto: no policy here, so
// there is only one implementation of the vault operations to review.
//
// The passphrase arrives once per unlock and stays in this worker. Decrypted seeds cross
// back to the UI thread because that is where the KeyManager has to live (the ceremony
// signs, and the frame stream is a closure that cannot be structured-cloned). Both sides
// of that trade are inside one origin and one bundle, so it is a least-privilege
// boundary, not a security boundary against R1.

import { LocalVaultCrypto, wipeVaultData } from './vault-crypto.js';
import type { VaultData } from '../vault.js';

type Request =
  | { id: number; op: 'createIdentity'; passphrase: string }
  | { id: number; op: 'unlock'; blob: Uint8Array; passphrase: string }
  | { id: number; op: 'seal'; data: VaultData }
  | { id: number; op: 'forget' };

const crypto = new LocalVaultCrypto();

const ctx = self as unknown as {
  onmessage: ((event: MessageEvent) => void) | null;
  postMessage(message: unknown): void;
};

ctx.onmessage = async (event: MessageEvent) => {
  const request = event.data as Request;
  try {
    switch (request.op) {
      case 'createIdentity': {
        const result = await crypto.createIdentity(request.passphrase);
        ctx.postMessage({ id: request.id, ok: true, value: result });
        // postMessage clones synchronously, so by here the UI thread has its own copy and
        // this one is only a seed sitting in worker memory. Best effort (residual R5).
        wipeVaultData(result.data);
        break;
      }
      case 'unlock': {
        const data = await crypto.unlock(request.blob, request.passphrase);
        ctx.postMessage({ id: request.id, ok: true, value: data });
        wipeVaultData(data);
        break;
      }
      case 'seal': {
        const blob = await crypto.seal(request.data);
        ctx.postMessage({ id: request.id, ok: true, value: blob });
        break;
      }
      case 'forget': {
        crypto.forget();
        ctx.postMessage({ id: request.id, ok: true, value: null });
        break;
      }
    }
  } catch (error) {
    // The message text is the vault layer's own (wrong passphrase, KDF floor, format
    // allowlist). Passing it through unchanged keeps one source of truth for the reason.
    ctx.postMessage({
      id: request.id,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
};
