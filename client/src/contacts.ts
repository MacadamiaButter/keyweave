// One-card-per-identity pinning + monotonic supersession (must-fix #4).
//
// A pinned identity accepts EXACTLY ONE card. A card with a higher serial is a
// supersession that FORCES a fresh re-pair ceremony (never silently accepted); a
// card with an equal-or-lower serial that differs is a rollback and is REJECTED.
// v0 has NO revocation (residual R6).

import type { ContactCard } from './card.js';
import { importCard } from './card.js';
import { bytesEqual, toHex } from './bytes.js';

export type AcceptStatus =
  | 'new' // first card for this identity - pinned
  | 'same' // identical to the pinned card - idempotent
  | 'supersede' // higher serial - caller MUST re-pair before pinning
  | 'rejected'; // rollback / fork at same-or-lower serial - refused

export interface AcceptResult {
  status: AcceptStatus;
  reason?: string;
}

interface Pin {
  identityPub: Uint8Array;
  encryptionPub: Uint8Array;
  serial: number;
  signedCardBytes: Uint8Array;
}

export class ContactStore {
  private readonly pins = new Map<string, Pin>();

  /** Classify an incoming (already-imported, authentic) card without mutating. */
  classify(card: ContactCard): AcceptResult {
    const key = toHex(card.identityPub);
    const existing = this.pins.get(key);
    if (!existing) return { status: 'new' };
    if (
      card.serial === existing.serial &&
      bytesEqual(card.encryptionPub, existing.encryptionPub)
    ) {
      return { status: 'same' };
    }
    if (card.serial <= existing.serial) {
      return { status: 'rejected', reason: 'serial rollback or fork at same serial' };
    }
    return { status: 'supersede', reason: 'higher serial requires a fresh re-pair' };
  }

  /** Pin a brand-new identity. Throws if already pinned (use confirmSupersede). */
  pin(card: ContactCard): void {
    const key = toHex(card.identityPub);
    if (this.pins.has(key)) throw new Error('contacts: identity already pinned');
    this.pins.set(key, toPin(card));
  }

  /**
   * After a face-to-face re-pair ceremony has verified a higher-serial card, replace
   * the pin. Refuses to move backward.
   */
  confirmSupersede(card: ContactCard): void {
    const key = toHex(card.identityPub);
    const existing = this.pins.get(key);
    if (!existing) throw new Error('contacts: no existing pin to supersede');
    if (card.serial <= existing.serial) throw new Error('contacts: refusing serial rollback');
    this.pins.set(key, toPin(card));
  }

  get(identityPub: Uint8Array): Pin | undefined {
    return this.pins.get(toHex(identityPub));
  }

  isPinned(identityPub: Uint8Array): boolean {
    return this.pins.has(toHex(identityPub));
  }

  size(): number {
    return this.pins.size;
  }

  /** Every pinned identity key, in pin order. Copies, so a caller cannot edit a pin. */
  identities(): Uint8Array[] {
    return [...this.pins.values()].map((p) => Uint8Array.from(p.identityPub));
  }

  /** Serialize to plain records for the vault (signed card bytes are re-validated on load). */
  export(): Uint8Array[] {
    return [...this.pins.values()].map((p) => Uint8Array.from(p.signedCardBytes));
  }

  /**
   * Put this store back to the state an earlier export() described. The INVERSE of a pin,
   * and the only way to remove one.
   *
   * It exists for exactly one caller: ui/session.ts commit(), which mutates this store and
   * then awaits a write that can fail. A pin that survives a failed write is a contact the
   * app has told the person is NOT saved and then lists on the next screen, so the refusal
   * screen's own sentence has to be made true, and the honest way to do that is to undo the
   * mutation rather than to reimplement classify/pin against a candidate copy.
   *
   * WHY IT TAKES AN IMAGE RATHER THAN AN IDENTITY TO DROP: the mutation being undone is
   * either a fresh pin or a supersede, and only the second has a previous value to put back.
   * One inverse that restores a whole image is correct for both, and its correctness does
   * not depend on the caller remembering which of the two it did.
   *
   * Every card goes back through importCard, so a restore validates exactly as strictly as
   * a load does: this can only reach a state the store would have accepted anyway.
   */
  restore(signedCards: Uint8Array[]): void {
    this.pins.clear();
    for (const bytes of signedCards) this.pin(importCard(bytes));
  }

  /** Rebuild from vault records, re-importing (strictly validating) each signed card. */
  static import(signedCards: Uint8Array[]): ContactStore {
    const store = new ContactStore();
    store.restore(signedCards);
    return store;
  }
}

function toPin(card: ContactCard): Pin {
  return {
    identityPub: Uint8Array.from(card.identityPub),
    encryptionPub: Uint8Array.from(card.encryptionPub),
    serial: card.serial,
    signedCardBytes: Uint8Array.from(card.signedCardBytes),
  };
}
