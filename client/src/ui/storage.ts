// Where the encrypted vault blob lives between visits.
//
// IndexedDB rather than localStorage: the blob is binary and localStorage would force a
// base64 round trip through an immutable string, which is both larger and one more copy of
// ciphertext the runtime will not let anyone wipe. Only the SEALED blob is stored; nothing
// here ever sees a seed, a passphrase or a contact.
//
// A browser can throw the store away at any time (private windows, storage pressure,
// "clear site data"). That is data loss with no recovery, since there is no account and no
// server copy, and the UI says so rather than implying durability it cannot provide.

export interface BlobStore {
  load(): Promise<Uint8Array | null>;
  save(blob: Uint8Array): Promise<void>;
  clear(): Promise<void>;
}

const DB_NAME = 'keyweave';
const DB_VERSION = 1;
const STORE = 'vault';
const KEY = 'blob';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('indexeddb: open failed'));
    request.onblocked = () => reject(new Error('indexeddb: blocked by another tab'));
  });
}

function run<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('indexeddb: request failed'));
  });
}

export class IndexedDbBlobStore implements BlobStore {
  async load(): Promise<Uint8Array | null> {
    const db = await openDb();
    try {
      const store = db.transaction(STORE, 'readonly').objectStore(STORE);
      const value = await run(store.get(KEY));
      if (value instanceof Uint8Array) return value;
      if (value instanceof ArrayBuffer) return new Uint8Array(value);
      return null;
    } finally {
      db.close();
    }
  }

  async save(blob: Uint8Array): Promise<void> {
    const db = await openDb();
    try {
      const tx = db.transaction(STORE, 'readwrite');
      await run(tx.objectStore(STORE).put(blob, KEY));
      // Resolve on the TRANSACTION, not the request: a put that has succeeded is not yet
      // a write that survives a crash, and "the contact is saved" has to mean durable.
      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onabort = () => reject(tx.error ?? new Error('indexeddb: write aborted'));
        tx.onerror = () => reject(tx.error ?? new Error('indexeddb: write failed'));
      });
    } finally {
      db.close();
    }
  }

  async clear(): Promise<void> {
    const db = await openDb();
    try {
      const tx = db.transaction(STORE, 'readwrite');
      await run(tx.objectStore(STORE).delete(KEY));
      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onabort = () => reject(tx.error ?? new Error('indexeddb: clear aborted'));
      });
    } finally {
      db.close();
    }
  }
}

/** In-memory store for tests and for a runtime with no IndexedDB. */
export class MemoryBlobStore implements BlobStore {
  private blob: Uint8Array | null = null;
  /** Writes since construction. The suite uses it to prove a pin was persisted. */
  saveCount = 0;

  async load(): Promise<Uint8Array | null> {
    return this.blob ? Uint8Array.from(this.blob) : null;
  }

  async save(blob: Uint8Array): Promise<void> {
    this.blob = Uint8Array.from(blob);
    this.saveCount++;
  }

  async clear(): Promise<void> {
    this.blob = null;
  }
}

export function createBlobStore(): BlobStore {
  return typeof indexedDB === 'undefined' ? new MemoryBlobStore() : new IndexedDbBlobStore();
}
