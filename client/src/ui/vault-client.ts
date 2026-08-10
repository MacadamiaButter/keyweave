// Main-thread proxy for vault-worker.ts. Same interface as LocalVaultCrypto, so the
// ceremony and the session layer cannot tell which one they were handed and the suite can
// drive the local one.

import type { VaultData } from '../vault.js';
import { LocalVaultCrypto, type VaultCrypto } from './vault-crypto.js';

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
}

export class WorkerVaultCrypto implements VaultCrypto {
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;

  constructor(private readonly worker: Worker) {
    worker.onmessage = (event: MessageEvent) => {
      const { id, ok, value, error } = event.data as {
        id: number;
        ok: boolean;
        value?: unknown;
        error?: string;
      };
      const entry = this.pending.get(id);
      if (!entry) return;
      this.pending.delete(id);
      if (ok) entry.resolve(value);
      else entry.reject(new Error(error ?? 'vault worker failed'));
    };
    // A worker that dies mid-derivation must not leave a promise hanging forever, which in
    // this UI is an unlock button that spins for the rest of the session.
    worker.onerror = () => this.failAll('vault worker stopped');
    worker.onmessageerror = () => this.failAll('vault worker sent an unreadable message');
  }

  private failAll(reason: string): void {
    for (const entry of this.pending.values()) entry.reject(new Error(reason));
    this.pending.clear();
  }

  private call<T>(request: Record<string, unknown>): Promise<T> {
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (value: unknown) => void, reject });
      this.worker.postMessage({ id, ...request });
    });
  }

  createIdentity(passphrase: string): Promise<{ blob: Uint8Array; data: VaultData }> {
    return this.call({ op: 'createIdentity', passphrase });
  }

  unlock(blob: Uint8Array, passphrase: string): Promise<VaultData> {
    return this.call({ op: 'unlock', blob, passphrase });
  }

  seal(data: VaultData): Promise<Uint8Array> {
    return this.call({ op: 'seal', data });
  }

  forget(): void {
    void this.call({ op: 'forget' }).catch(() => undefined);
  }
}

/**
 * A worker if the runtime has one, otherwise the inline implementation. The fallback is
 * correct and slow, not degraded: it runs the identical code, on the UI thread.
 */
export function createVaultCrypto(): VaultCrypto {
  if (typeof Worker === 'undefined') return new LocalVaultCrypto();
  const worker = new Worker(new URL('./vault-worker.ts', import.meta.url), { type: 'module' });
  return new WorkerVaultCrypto(worker);
}
