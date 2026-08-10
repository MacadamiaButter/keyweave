import { describe, it, expect } from 'vitest';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard, importCard } from '../src/card.js';
import { ContactStore } from '../src/contacts.js';

async function cardAt(km: Awaited<ReturnType<typeof generateKeyManager>>['manager'], serial: number) {
  return importCard(await createSignedCard(km, serial));
}

describe('one-card-per-identity pinning + supersession', () => {
  it('pins a new identity and treats an identical card as idempotent', async () => {
    const A = await generateKeyManager('noble');
    const card = await cardAt(A.manager, 1);
    const store = new ContactStore();
    expect(store.classify(card).status).toBe('new');
    store.pin(card);
    expect(store.isPinned(card.identityPub)).toBe(true);
    expect(store.classify(card).status).toBe('same');
  });

  it('flags a higher-serial card as supersede (forces re-pair), never auto-accepts', async () => {
    const A = await generateKeyManager('noble');
    const store = new ContactStore();
    store.pin(await cardAt(A.manager, 1));
    const newer = await cardAt(A.manager, 5);
    expect(store.classify(newer).status).toBe('supersede');
    // Only an explicit re-pair confirmation moves the pin.
    store.confirmSupersede(newer);
    expect(store.get(newer.identityPub)?.serial).toBe(5);
  });

  it('rejects a serial rollback', async () => {
    const A = await generateKeyManager('noble');
    const store = new ContactStore();
    store.pin(await cardAt(A.manager, 5));
    const older = await cardAt(A.manager, 2);
    expect(store.classify(older).status).toBe('rejected');
    expect(() => store.confirmSupersede(older)).toThrow(/rollback/);
  });

  it('round-trips through vault export/import (re-validating each card)', async () => {
    const A = await generateKeyManager('noble');
    const B = await generateKeyManager('noble');
    const store = new ContactStore();
    store.pin(await cardAt(A.manager, 1));
    store.pin(await cardAt(B.manager, 3));
    const exported = store.export();
    const restored = ContactStore.import(exported);
    expect(restored.size()).toBe(2);
    expect(restored.isPinned(A.manager.identityPublicKey())).toBe(true);
    expect(restored.isPinned(B.manager.identityPublicKey())).toBe(true);
  });
});
