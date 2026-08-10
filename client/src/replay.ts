// Replay defense (must-fix #5 + must-fix #1 hardening). Two independent mechanisms:
//   1. Dedupe on the msg-id computed over AUTHENTICATED bytes
//      (SHA-512(CTX_MSGID || inner_bytes || sig)) - NOT the malleable wire envelope.
//      The relay can re-encode the wire form all it likes; the msg-id is invariant,
//      so no re-encoding mints a new accepted message.
//   2. A per-sender BOUNDED ACCEPTANCE WINDOW around the high-water mark (recipient-side
//      state only, degrades safely). We accept anything with ts > hwm - WINDOW_MS, and
//      hard-reject only BELOW that window. A hard monotone gate (reject anything below
//      hwm) silently DROPS legitimate messages whenever the untrusted relay returns a
//      batch out of timestamp order; the window fixes that data-loss bug while still
//      bounding how far back a replay can be resurrected.
//
// Within the window, dedupe is by the seen-set. The seen-set is PRUNED to the window
// (entries below hwm - WINDOW_MS are dropped because they are hard-rejected anyway) and
// is PERSISTED in the vault alongside the high-water marks, so eviction/restart cannot
// resurrect a message that still falls inside the window.
//
// fix-round-2 (regression #3): the seen-set is INDEXED BY SENDER (Map<senderHex,
// Map<idHex,ts>>) so pruning and capping are per-sender, never a full-corpus scan on
// every admit. Below-window entries are reclaimed for ALL senders on a bounded schedule
// (every SEEN_PRUNE_EVERY admits, and on export/save), so a silent sender's aged entries
// no longer leak until that sender next speaks. Hard per-sender + total caps bound worst
// -case memory: at the caps the OLDEST entries are dropped first (they are closest to the
// stale floor). See NAMED RESIDUAL R-replay-cap below.
//
// NAMED RESIDUAL (R-replay-cap): under a flood of more than the cap of DISTINCT in-window
// messages from one sender, the oldest in-window seen-entries are evicted, so a replay of
// one of those specific evicted ids could be re-accepted within the window. This is a
// bounded-memory (DoS-resistance) tradeoff; the primary replay defenses (authenticated
// msg-id + the time-bounded window) are unchanged. Caps are sized so normal use never
// reaches them.

import { toHex } from './bytes.js';
import { CLOCK_SKEW_MS } from './constants.js';

// Bounded acceptance window: accept ts > hwm - WINDOW_MS, hard-reject at/below it.
export const WINDOW_MS = 14 * 24 * 60 * 60 * 1000; // 14 days

// Bounded-schedule prune cadence and hard memory caps (fix-round-2, regression #3).
export const SEEN_PRUNE_EVERY = 512; // run the cross-sender window prune every N admits
export const MAX_SEEN_PER_SENDER = 4096; // hard per-sender seen-entry cap
export const MAX_SEEN_TOTAL = 65_536; // hard global seen-entry cap

export type ReplayVerdict =
  | { accepted: true }
  | { accepted: false; reason: 'duplicate' | 'stale' };

export interface HighWaterEntry {
  senderId: Uint8Array;
  highWaterMs: number;
}

/** A single persisted seen-set entry (durable dedupe state, bounded to the window). */
export interface SeenEntry {
  msgId: Uint8Array;
  senderId: Uint8Array;
  timestampMs: number;
}

export class ReplayGuard {
  // sender -> (msgId -> ts). Indexing by sender keeps prune/cap per-sender O(1)-amortized
  // instead of scanning the whole corpus on every admit.
  private readonly seen = new Map<string, Map<string, number>>();
  private readonly highWater = new Map<string, number>(); // senderHex -> hwm
  private readonly windowMs: number;
  private admitsSincePrune = 0;
  private totalSeen = 0;
  private destroyed = false;

  constructor(windowMs: number = WINDOW_MS) {
    this.windowMs = windowMs;
  }

  private assertLive(): void {
    if (this.destroyed) throw new Error('replay: guard destroyed');
  }

  /**
   * Deactivate the guard and drop its state (mirrors KeyManager.destroy()). The vault
   * calls this at lock(): a caller-cached guard must not keep admitting after lock -
   * post-lock admits can never become durable (save() throws 'vault: locked'), and the
   * seen-set is keyed by sender identity (social-graph metadata) that must not outlive
   * the unlocked session even through a cached reference.
   */
  destroy(): void {
    this.destroyed = true;
    this.seen.clear();
    this.highWater.clear();
    this.totalSeen = 0;
  }

  /**
   * Check-and-record. On accept, updates the seen-set and (if advanced) the high-water
   * mark. `nowMs` clamps the STORED high-water mark at now + CLOCK_SKEW_MS so a
   * future-dated timestamp that slips past open()'s gate still cannot poison the mark
   * beyond the skew allowance (must-fix #2 defense-in-depth).
   */
  admit(
    senderId: Uint8Array,
    timestampMs: number,
    msgId: Uint8Array,
    nowMs: number = Date.now(),
  ): ReplayVerdict {
    this.assertLive();
    const senderKey = toHex(senderId);
    const idKey = toHex(msgId);

    const hwm = this.highWater.get(senderKey);
    // Hard reject only BELOW the window; everything inside it is eligible.
    if (hwm !== undefined && timestampMs <= hwm - this.windowMs) {
      return { accepted: false, reason: 'stale' };
    }

    let senderSeen = this.seen.get(senderKey);
    if (senderSeen?.has(idKey)) return { accepted: false, reason: 'duplicate' };

    if (senderSeen === undefined) {
      senderSeen = new Map<string, number>();
      this.seen.set(senderKey, senderSeen);
    }
    senderSeen.set(idKey, timestampMs);
    this.totalSeen++;

    if (hwm === undefined || timestampMs > hwm) {
      const capped = Math.min(timestampMs, nowMs + CLOCK_SKEW_MS);
      const newHwm = hwm === undefined ? capped : Math.max(hwm, capped);
      this.highWater.set(senderKey, newHwm);
    }

    // Hard per-sender cap: drop the oldest-inserted entries beyond the cap. O(1) amortized.
    this.enforcePerSenderCap(senderSeen);

    // Cross-sender window prune on a bounded schedule (NOT every admit - that was the
    // O(n^2) full scan). Reclaims aged entries for silent senders too.
    if (++this.admitsSincePrune >= SEEN_PRUNE_EVERY) this.pruneAll();

    return { accepted: true };
  }

  /** Drop oldest-inserted entries for one sender once it exceeds the hard per-sender cap. */
  private enforcePerSenderCap(senderSeen: Map<string, number>): void {
    while (senderSeen.size > MAX_SEEN_PER_SENDER) {
      const oldest = senderSeen.keys().next().value as string; // Map preserves insertion order
      senderSeen.delete(oldest);
      this.totalSeen--;
    }
  }

  /**
   * Prune EVERY sender's below-window entries (safe: anything at/below hwm - windowMs is
   * hard-rejected by admit anyway), drop now-empty senders, then enforce the global cap.
   */
  private pruneAll(): void {
    this.admitsSincePrune = 0;
    for (const [senderKey, senderSeen] of this.seen) {
      const hwm = this.highWater.get(senderKey);
      if (hwm !== undefined) {
        const floor = hwm - this.windowMs;
        for (const [id, ts] of senderSeen) {
          if (ts <= floor) {
            senderSeen.delete(id);
            this.totalSeen--;
          }
        }
      }
      if (senderSeen.size === 0) this.seen.delete(senderKey);
    }
    if (this.totalSeen > MAX_SEEN_TOTAL) this.enforceTotalCap();
  }

  /** Hard global cap: drop oldest-inserted entries per sender until back under the cap. */
  private enforceTotalCap(): void {
    for (const [senderKey, senderSeen] of this.seen) {
      while (this.totalSeen > MAX_SEEN_TOTAL && senderSeen.size > 0) {
        const oldest = senderSeen.keys().next().value as string;
        senderSeen.delete(oldest);
        this.totalSeen--;
      }
      if (senderSeen.size === 0) this.seen.delete(senderKey);
      if (this.totalSeen <= MAX_SEEN_TOTAL) break;
    }
  }

  highWaterFor(senderId: Uint8Array): number | undefined {
    this.assertLive();
    return this.highWater.get(toHex(senderId));
  }

  /** Current count of retained seen-entries (observability; does not prune). */
  seenCount(): number {
    this.assertLive();
    return this.totalSeen;
  }

  /** Durable state for the vault: the per-sender high-water marks. */
  exportHighWater(): HighWaterEntry[] {
    this.assertLive();
    const out: HighWaterEntry[] = [];
    for (const [hex, hwm] of this.highWater) {
      out.push({ senderId: hexToBytes(hex), highWaterMs: hwm });
    }
    return out;
  }

  /**
   * Durable state for the vault: the in-window seen-set (so eviction can't resurrect).
   * Prunes on the way out ("on save" arm of the bounded schedule) so persisted state
   * stays bounded to the window instead of re-Argon2'ing an unbounded set every save.
   */
  exportSeen(): SeenEntry[] {
    this.assertLive();
    this.pruneAll();
    const out: SeenEntry[] = [];
    for (const [senderHex, senderSeen] of this.seen) {
      for (const [idHex, ts] of senderSeen) {
        out.push({ msgId: hexToBytes(idHex), senderId: hexToBytes(senderHex), timestampMs: ts });
      }
    }
    return out;
  }

  /**
   * Rebuild from persisted state: BOTH the high-water marks AND the in-window seen-set.
   * The seen-set is REQUIRED (regression #1): there is no high-water-only construction
   * path, because a guard with marks but no seen-set would ACCEPT a captured in-window
   * replay. A caller wanting a fresh guard uses `new ReplayGuard()`.
   */
  static restore(
    highWater: HighWaterEntry[],
    seen: SeenEntry[],
    windowMs: number = WINDOW_MS,
  ): ReplayGuard {
    const g = new ReplayGuard(windowMs);
    for (const e of highWater) g.highWater.set(toHex(e.senderId), e.highWaterMs);
    for (const s of seen) {
      const senderKey = toHex(s.senderId);
      let senderSeen = g.seen.get(senderKey);
      if (senderSeen === undefined) {
        senderSeen = new Map<string, number>();
        g.seen.set(senderKey, senderSeen);
      }
      const idKey = toHex(s.msgId);
      if (!senderSeen.has(idKey)) {
        senderSeen.set(idKey, s.timestampMs);
        g.totalSeen++;
      }
    }
    return g;
  }
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
