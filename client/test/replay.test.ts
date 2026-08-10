import { describe, it, expect } from 'vitest';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard, importCard } from '../src/card.js';
import { seal, open } from '../src/seal.js';
import { decodeStrict, encodeDeterministic } from '../src/cbor.js';
import {
  ReplayGuard,
  WINDOW_MS,
  SEEN_PRUNE_EVERY,
  MAX_SEEN_PER_SENDER,
} from '../src/replay.js';
import { bytesEqual } from '../src/bytes.js';
import { CLOCK_SKEW_MS } from '../src/constants.js';

const te = (s: string) => new TextEncoder().encode(s);
const DAY = 24 * 60 * 60 * 1000;

async function pair() {
  const A = (await generateKeyManager('noble')).manager;
  const B = (await generateKeyManager('noble')).manager;
  const aViewOfB = importCard(await createSignedCard(B, 1));
  const bViewOfA = importCard(await createSignedCard(A, 1));
  return { A, B, aViewOfB, bViewOfA };
}

describe('replay guard', () => {
  it('admits a message once, then dedupes an exact replay', async () => {
    const { A, aViewOfB, B, bViewOfA } = await pair();
    const env = await seal(A, aViewOfB, te('hi'), { timestampMs: 100 });
    const opened = await open(B, bViewOfA, env);
    const guard = new ReplayGuard();
    expect(guard.admit(opened.senderId, opened.timestampMs, opened.msgId)).toEqual({ accepted: true });
    // Re-pull + re-open the SAME wire bytes: identical authenticated msg-id -> duplicate.
    const opened2 = await open(B, bViewOfA, env);
    expect(guard.admit(opened2.senderId, opened2.timestampMs, opened2.msgId)).toEqual({
      accepted: false,
      reason: 'duplicate',
    });
  });

  it('[data-loss] a reversed / out-of-order batch delivers ALL messages exactly once', async () => {
    // Regression for must-fix #1: a HARD monotone gate drops everything after the newest
    // when the untrusted relay returns a batch out of timestamp order. The bounded
    // acceptance window must deliver every legitimate message exactly once.
    const { A, aViewOfB, B, bViewOfA } = await pair();
    const base = Date.now() - 60_000; // recent + strictly in the past (open()'s future clamp)
    const envs: Uint8Array[] = [];
    for (let i = 0; i < 5; i++) {
      envs.push(await seal(A, aViewOfB, te(`m${i}`), { timestampMs: base + i * 1000 }));
    }
    const guard = new ReplayGuard();
    // Relay hands them back NEWEST-FIRST (fully reversed timestamp order).
    const opened = [];
    for (const env of [...envs].reverse()) opened.push(await open(B, bViewOfA, env));

    const verdicts = opened.map((o) => guard.admit(o.senderId, o.timestampMs, o.msgId));
    // Before the fix, 4/5 of these were dropped as 'stale'. Now ALL are accepted.
    expect(verdicts.every((v) => v.accepted)).toBe(true);
    expect(verdicts.filter((v) => v.accepted)).toHaveLength(5);
    // Exactly once: a second pass over the same batch is all duplicates.
    const second = opened.map((o) => guard.admit(o.senderId, o.timestampMs, o.msgId));
    expect(second.every((v) => !v.accepted && v.reason === 'duplicate')).toBe(true);
  });

  it('[malleability] an unknown-map-key re-encoding does NOT mint a new accepted msg-id', async () => {
    const { A, aViewOfB, B, bViewOfA } = await pair();
    const env = await seal(A, aViewOfB, te('canonical'), { timestampMs: 100 });

    // The relay re-encodes the SAME authenticated blob into a different wire form by
    // adding an unknown map key. Strict decode refuses it outright.
    const m = decodeStrict<Map<number, unknown>>(env);
    const malleable = new Map<number, unknown>(m as Map<number, unknown>);
    malleable.set(9, 0);
    const reencoded = encodeDeterministic(malleable);
    expect(Buffer.from(reencoded).equals(Buffer.from(env))).toBe(false); // genuinely different wire
    await expect(open(B, bViewOfA, reencoded)).rejects.toThrow(/unknown map key 9/);

    // The dedupe id is over AUTHENTICATED bytes, INDEPENDENT of the wire nonce: sealing
    // the SAME (sender, recipient, timestamp, body) under two DIFFERENT nonces yields two
    // different wire envelopes but ONE shared msg-id, so the second admit is a duplicate.
    // (This assertion FAILS if the id ever moves onto the malleable wire nonce.)
    const w1 = await seal(A, aViewOfB, te('canonical'), { timestampMs: 100, nonce: new Uint8Array(24).fill(1) });
    const w2 = await seal(A, aViewOfB, te('canonical'), { timestampMs: 100, nonce: new Uint8Array(24).fill(2) });
    expect(Buffer.from(w1).equals(Buffer.from(w2))).toBe(false); // different wire (nonce differs)
    const o1 = await open(B, bViewOfA, w1);
    const o2 = await open(B, bViewOfA, w2);
    expect(Buffer.from(o1.msgId).equals(Buffer.from(o2.msgId))).toBe(true); // one shared authenticated id
    const guard = new ReplayGuard();
    expect(guard.admit(o1.senderId, o1.timestampMs, o1.msgId).accepted).toBe(true);
    expect(guard.admit(o2.senderId, o2.timestampMs, o2.msgId)).toEqual({
      accepted: false,
      reason: 'duplicate',
    });
  });

  it('per-sender window: accepts in-window (even below hwm), hard-rejects only below the window', () => {
    const sender = new Uint8Array(32).fill(1);
    const guard = new ReplayGuard();
    const now = 1_700_000_000_000; // fixed clock for the hwm cap
    const id = (n: number) => {
      const b = new Uint8Array(64);
      b[0] = n;
      return b;
    };
    // Establish the high-water mark at `now`.
    expect(guard.admit(sender, now, id(1), now).accepted).toBe(true);
    expect(guard.highWaterFor(sender)).toBe(now);
    // An out-of-order OLDER message that is still IN-WINDOW is accepted (not dropped).
    expect(guard.admit(sender, now - DAY, id(2), now).accepted).toBe(true);
    expect(guard.highWaterFor(sender)).toBe(now); // hwm does not move backward
    // A message BELOW the window is hard-rejected as stale...
    expect(guard.admit(sender, now - WINDOW_MS - 1, id(3), now)).toEqual({
      accepted: false,
      reason: 'stale',
    });
    // ...and the window boundary itself (hwm - WINDOW_MS) is inclusive-reject.
    expect(guard.admit(sender, now - WINDOW_MS, id(4), now)).toEqual({
      accepted: false,
      reason: 'stale',
    });
  });

  it('high-water marks + seen-set are per-sender and survive export/restore (no resurrection)', () => {
    const s1 = new Uint8Array(32).fill(1);
    const s2 = new Uint8Array(32).fill(2);
    const now = 1_700_000_000_000;
    const m1 = new Uint8Array(64).fill(1);
    const m2 = new Uint8Array(64).fill(2);
    const guard = new ReplayGuard();
    guard.admit(s1, now, m1, now);
    guard.admit(s2, now, m2, now);
    // Persist BOTH the marks AND the in-window seen-set, then rebuild (restart / eviction).
    const restored = ReplayGuard.restore(guard.exportHighWater(), guard.exportSeen());
    expect(restored.highWaterFor(s1)).toBe(now);
    expect(restored.highWaterFor(s2)).toBe(now);
    // The in-window message is STILL deduped after restore -> eviction cannot resurrect it.
    expect(restored.admit(s1, now, m1, now)).toEqual({ accepted: false, reason: 'duplicate' });
    // A below-window message is still hard-rejected after restore.
    expect(restored.admit(s1, now - WINDOW_MS - 1, new Uint8Array(64).fill(9), now)).toEqual({
      accepted: false,
      reason: 'stale',
    });
  });

  it('[regression #1] restore REQUIRES the seen-set; withHighWater() is gone; the seen-set is load-bearing', () => {
    // The bounded acceptance window makes the seen-set the sole in-window replay defense.
    // A guard rebuilt from high-water marks ALONE would re-admit a captured in-window
    // message; the deleted withHighWater() was exactly that path (and the first one an
    // integrator would reach). restore() now forces the seen-set to be supplied.
    const s1 = new Uint8Array(32).fill(1);
    const now = 1_700_000_000_000;
    const m1 = new Uint8Array(64).fill(1);
    const guard = new ReplayGuard();
    expect(guard.admit(s1, now, m1, now).accepted).toBe(true);

    // The weak high-water-only construction path is DELETED.
    expect((ReplayGuard as unknown as { withHighWater?: unknown }).withHighWater).toBeUndefined();

    // The ONLY restore path carries the seen-set, and it still dedupes the in-window replay.
    const restored = ReplayGuard.restore(guard.exportHighWater(), guard.exportSeen());
    expect(restored.admit(s1, now, m1, now)).toEqual({ accepted: false, reason: 'duplicate' });

    // Contrast proving the seen-set is what stops the replay (i.e. why a marks-only guard
    // was unsafe): hand restore() the marks but an EMPTY seen-set and the very same
    // in-window message is re-admitted. There is no longer a helper that does this
    // implicitly - the real save path (exportSeen, above) always carries the true set.
    const marksOnly = ReplayGuard.restore(guard.exportHighWater(), []);
    expect(marksOnly.admit(s1, now, m1, now).accepted).toBe(true);
  });

  it('[regression #3] 20k in-order admits stay fast (was O(n^2) ~2.3s) and bounded to O(window)', () => {
    const sender = new Uint8Array(32).fill(4);
    const guard = new ReplayGuard();
    const base = 1_700_000_000_000;
    const now = base + 60_000; // every admit is in-window and not future
    const buf = new Uint8Array(64);
    const dv = new DataView(buf.buffer);

    const t0 = performance.now();
    for (let i = 0; i < 20_000; i++) {
      dv.setUint32(0, i); // unique msg-id per admit (rest of buf stays zero)
      const v = guard.admit(sender, base + i, buf, now);
      if (!v.accepted) throw new Error(`unexpected non-accept at ${i}`);
    }
    const elapsed = performance.now() - t0;

    // Prior full-scan-per-admit implementation was ~2.3s; O(1)-amortized must be far under.
    expect(elapsed).toBeLessThan(1500);
    // Retained entries are bounded by the hard per-sender cap, NOT the 20000 admitted.
    expect(guard.seenCount()).toBeLessThanOrEqual(MAX_SEEN_PER_SENDER);
    expect(guard.seenCount()).toBeLessThan(20_000);
  });

  it('[regression #3] a silent sender’s aged entry is reclaimed by the scheduled cross-sender prune', () => {
    const A = new Uint8Array(32).fill(5);
    const B = new Uint8Array(32).fill(6);
    const now = 1_700_000_000_000;
    const guard = new ReplayGuard();
    const m0 = new Uint8Array(64).fill(10);
    const m1 = new Uint8Array(64).fill(11);

    // A speaks twice; the second admit advances A's hwm so far that m0 drops BELOW the window.
    expect(guard.admit(A, now - 2 * WINDOW_MS, m0, now).accepted).toBe(true); // first: any ts ok
    expect(guard.admit(A, now, m1, now).accepted).toBe(true); // hwm(A) -> now; m0 now stale-floored

    // admit() does NOT scan/prune every call (that was the O(n^2) bug): m0 still lingers.
    expect(guard.seenCount()).toBe(2);

    // A goes silent. B's activity drives the bounded schedule; the (SEEN_PRUNE_EVERY)th admit
    // overall runs the cross-sender prune, which reclaims A's below-window m0.
    const buf = new Uint8Array(64);
    buf[0] = 0xbb;
    const dv = new DataView(buf.buffer);
    for (let i = 0; i < SEEN_PRUNE_EVERY - 2; i++) {
      dv.setUint32(4, i); // unique id for B; byte 0 kept != A's ids
      expect(guard.admit(B, now, buf, now).accepted).toBe(true);
    }

    // Exactly one entry (A's m0) was reclaimed: B's (SEEN_PRUNE_EVERY-2) + A's surviving m1.
    expect(guard.seenCount()).toBe(SEEN_PRUNE_EVERY - 1);
    // And a replay of m0 is hard-rejected by the window gate regardless (defense unchanged).
    expect(guard.admit(A, now - 2 * WINDOW_MS, m0, now)).toEqual({ accepted: false, reason: 'stale' });
  });

  it('[regression #3] exportSeen() prunes below-window entries on save (bounds the persisted set)', () => {
    const A = new Uint8Array(32).fill(7);
    const now = 1_700_000_000_000;
    const guard = new ReplayGuard();
    const m0 = new Uint8Array(64).fill(20);
    const m1 = new Uint8Array(64).fill(21);
    expect(guard.admit(A, now - 2 * WINDOW_MS, m0, now).accepted).toBe(true);
    expect(guard.admit(A, now, m1, now).accepted).toBe(true); // m0 now below the window
    expect(guard.seenCount()).toBe(2); // lingers until the scheduled/on-save prune

    const exported = guard.exportSeen(); // "on save" arm of the bounded schedule
    expect(exported).toHaveLength(1);
    expect(bytesEqual(exported[0]!.msgId, m1)).toBe(true);
    expect(guard.seenCount()).toBe(1);
  });

  it('[regression #4] a far-future admit clamps the stored high-water to now + CLOCK_SKEW_MS', () => {
    const sender = new Uint8Array(32).fill(8);
    const now = 1_700_000_000_000;
    const farFuture = now + 999 * DAY; // way past the skew allowance
    const id = new Uint8Array(64).fill(1);
    const guard = new ReplayGuard();
    expect(guard.admit(sender, farFuture, id, now).accepted).toBe(true);
    // The high-water mark is clamped, NOT set to the future ts - so it cannot brick the channel.
    expect(guard.highWaterFor(sender)).toBe(now + CLOCK_SKEW_MS);
    expect(guard.highWaterFor(sender)).not.toBe(farFuture);
  });
});
