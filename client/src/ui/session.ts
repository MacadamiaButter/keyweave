// An unlocked Keyweave session: one Vault, one ContactStore, one own card serial.
//
// THE VAULT CALLER OBLIGATION (WP1). Vault state is only durable once it has been sealed
// and written. `commit()` therefore does classify -> pin -> snapshot -> seal -> store.save
// in one await, and does not resolve until the write has landed. Nothing in this file
// mutates the vault and returns without persisting, because an unsaved mutation is silently
// gone at lock, and for the replay seen-set that is not just a lost contact, it is a
// re-acceptable in-window replay after reopen.
//
// leastpriv: the ceremony gets a ContactPinner, which can classify and commit a card and
// do nothing else. It never receives the Vault, the KeyManager or the blob store.

import { Vault, type MailboxPairing, type MessageRecord, type VaultData } from '../vault.js';
import { ContactStore, type AcceptResult, type AcceptStatus } from '../contacts.js';
import { importCard, type ContactCard } from '../card.js';
import type { KeyManager } from '../keys.js';
import type { ReplayGuard } from '../replay.js';
import type { MessagingHost } from '../messaging.js';
import type { ContactPinner } from './ceremony.js';
import type { BlobStore } from './storage.js';
import type { VaultCrypto } from './vault-crypto.js';

/** Idle re-lock. Long enough for a ceremony with a stranger, short enough to matter. */
export const IDLE_LOCK_MS = 5 * 60_000;

export interface SessionOptions {
  idleMs?: number;
  onLock?: () => void;
}

export class KeyweaveSession implements ContactPinner, MessagingHost {
  private constructor(
    readonly vault: Vault,
    readonly contacts: ContactStore,
    private readonly crypto: VaultCrypto,
    private readonly store: BlobStore,
  ) {}

  private static async fromData(
    data: VaultData,
    crypto: VaultCrypto,
    store: BlobStore,
    opts: SessionOptions,
  ): Promise<KeyweaveSession> {
    const vault = await Vault.fromData(data, {
      idleMs: opts.idleMs ?? IDLE_LOCK_MS,
      // The passphrase lives in the crypto seam, not in the vault, so a lock that only
      // wipes the vault leaves the KDF worker still able to seal. Hanging forget() on the
      // vault's OWN lock path is what makes "locked" mean the same thing in both places,
      // including when the idle timer fired it and no UI code ran at all. It is also the
      // only way an unattended lock can reach forget(): nothing calls session.lock().
      onLock: () => {
        crypto.forget();
        opts.onLock?.();
      },
    });
    // Every stored card is re-imported through the strict validator on the way back in, so
    // a vault edited outside the app cannot smuggle a key past the checks it failed once.
    const contacts = ContactStore.import(vault.data_().contacts);
    return new KeyweaveSession(vault, contacts, crypto, store);
  }

  /** First run: generate the identity, seal it, write it, and open the session. */
  static async createIdentity(
    crypto: VaultCrypto,
    store: BlobStore,
    passphrase: string,
    opts: SessionOptions = {},
  ): Promise<KeyweaveSession> {
    const { blob, data } = await crypto.createIdentity(passphrase);
    // Persisted BEFORE the session exists: a generated identity that was never written is
    // a key the user believes they have.
    await store.save(blob);
    return KeyweaveSession.fromData(data, crypto, store, opts);
  }

  static async unlock(
    crypto: VaultCrypto,
    store: BlobStore,
    passphrase: string,
    opts: SessionOptions = {},
  ): Promise<KeyweaveSession> {
    const blob = await store.load();
    if (!blob) throw new Error('session: no vault on this device');
    const data = await crypto.unlock(blob, passphrase);
    return KeyweaveSession.fromData(data, crypto, store, opts);
  }

  keys(): KeyManager {
    return this.vault.keys();
  }

  identityPublicKey(): Uint8Array {
    return this.vault.keys().identityPublicKey();
  }

  classify(card: ContactCard): AcceptResult {
    return this.contacts.classify(card);
  }

  /**
   * Pin (or supersede) and PERSIST. Resolves only once the sealed blob has been written,
   * so a caller that awaits this has a durable contact, not an in-memory one.
   *
   * ALL OR NOTHING, and that is a claim the product makes out loud. A write that fails
   * lands on a screen whose advice is "Treat this as not paired", and whose only button
   * goes to the ready screen, which lists peers out of the in-memory store this method
   * mutates. Pinning first and awaiting afterwards therefore made the app contradict
   * itself: it said not paired and then offered the contact, on the one product whose
   * premise is that a screen never names the wrong outcome. So the mutations are undone
   * when the write rejects, and the original error is rethrown unchanged so the caller can
   * still name the cause.
   *
   * ROLLBACK RATHER THAN STAGING, chosen deliberately. Staging would mean deciding the pin
   * against a candidate copy and applying it after the write, which is a second
   * implementation of classify/pin/supersede, the part of this codebase where the rules
   * about serials are security-relevant and where two implementations is how one of them
   * drifts. Undoing reuses the single mutation path and adds one inverse to each store.
   */
  async commit(card: ContactCard, status: AcceptStatus, mailbox?: MailboxPairing): Promise<void> {
    // Taken BEFORE anything moves, and exported rather than referenced: export() copies the
    // bytes, so this image cannot be edited from underneath by the mutations below.
    const contactsBefore = this.contacts.export();
    const mailboxesBefore = [...this.vault.data_().mailboxes];
    switch (status) {
      case 'new':
        this.contacts.pin(card);
        break;
      case 'supersede':
        // Reached only after a fresh face-to-face ceremony on the higher-serial card, which
        // is exactly what contacts.ts requires before a pin may move.
        this.contacts.confirmSupersede(card);
        break;
      case 'same':
        // Already pinned, identical card. Nothing to change, and still saved: a save is
        // also how any replay state admitted this session reaches the blob.
        break;
      case 'rejected':
        throw new Error('session: refusing to commit a rejected card');
    }
    // Same write as the pin, so there is no window where one landed and the other did not.
    if (mailbox) this.vault.putMailbox(mailbox);
    try {
      await this.persist();
    } catch (error) {
      this.contacts.restore(contactsBefore);
      // ONLY WHILE THE VAULT IS STILL OPEN. The other way for this write to fail is the idle
      // lock firing during it, and a locked vault has no mailbox table to put anything back
      // into: restoreMailboxes would throw 'vault: locked' and replace the caller's real
      // error with a worse one. app.ts treats that case as a lock rather than a write
      // failure and drops the whole session, so there is nothing left to be wrong about.
      if (!this.vault.isLocked()) this.vault.restoreMailboxes(mailboxesBefore);
      throw error;
    }
  }

  /**
   * Snapshot, seal, write. The single place vault state becomes durable, so every caller
   * that mutates the vault (a pin, a mailbox, a queued message, a replay admit) ends here.
   */
  async persist(): Promise<void> {
    const data = this.vault.snapshot();
    data.contacts = this.contacts.export();
    const blob = await this.crypto.seal(data);
    await this.store.save(blob);
  }

  /** The live replay guard. Admits through it are durable only once persist() has run. */
  replay(): ReplayGuard {
    return this.vault.replay();
  }

  /**
   * The pinned card for a peer. Re-imported from the stored bytes through the strict
   * validator every time rather than cached, for the same reason the store re-imports at
   * unlock: the bytes are the record, and the validator is what makes them a card.
   */
  cardFor(peerId: Uint8Array): ContactCard | undefined {
    const pin = this.contacts.get(peerId);
    return pin ? importCard(pin.signedCardBytes) : undefined;
  }

  mailboxFor(peerId: Uint8Array): MailboxPairing | undefined {
    return this.vault.mailboxFor(peerId);
  }

  /** The live record array. Mutating it is only durable once persist() resolves. */
  messages(): MessageRecord[] {
    return this.vault.data_().messages;
  }

  /** Every pinned identity, for the screen that has to offer a conversation to open. */
  peers(): Uint8Array[] {
    return this.contacts.identities();
  }

  /** Explicit lock. forget() rides the vault's onLock, so idle and explicit locks agree. */
  lock(): void {
    this.vault.lock();
  }

  /** True once the idle timer (or an explicit lock) has emptied the vault. */
  isLocked(): boolean {
    return this.vault.isLocked();
  }
}
