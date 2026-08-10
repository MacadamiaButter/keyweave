import { describe, it, expect } from 'vitest';
import {
  MAX_BLOCK_LEN,
  MAX_K,
  MAX_TOTAL_LEN,
  OpticalReceiver,
  encodeCardFrames,
  headerRefusal,
} from '../src/optical.js';
import { HEADER_LEN, packFrame, parseFrame } from '../vendor/decimen/frame.js';
import type { FrameHeader } from '../vendor/decimen/frame.js';
import { LTDecoder } from '../vendor/decimen/fountain.js';

// Deterministic filler so a failure is reproducible (the fountain is deterministic in
// sessionId + seq, so every test here is too).
function filler(len: number, seed: number): Uint8Array {
  const out = new Uint8Array(len);
  let s = seed >>> 0;
  for (let i = 0; i < len; i++) {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    out[i] = (s >>> 24) & 0xff;
  }
  return out;
}

function header(over: Partial<FrameHeader>): FrameHeader {
  return { sessionId: 1, seq: 0, k: 1, blockLen: 100, totalLen: 100, payloadFnv: 0, ...over };
}

/** A frame whose body length matches its declared blockLen, so only the caps can reject it. */
function frameFor(h: FrameHeader): Uint8Array {
  return packFrame(h, new Uint8Array(h.blockLen).fill(0x41));
}

describe('optical round trip under frame loss', () => {
  // 33% loss, at the three k values the pre-vendor harness verified. Dropping every
  // third seq is a worst case the fountain must absorb without a back-channel.
  for (const [k, payloadLen] of [
    [4, 400],
    [6, 600],
    [9, 900],
  ] as const) {
    it(`recovers byte-exact at k=${k} with every third frame dropped`, () => {
      const payload = filler(payloadLen, 0x5eed + k);
      const stream = encodeCardFrames(payload, { frameBytes: HEADER_LEN + 100, sessionId: 7 });
      expect(stream.k).toBe(k);
      expect(stream.blockLen).toBe(100);
      expect(stream.totalLen).toBe(payloadLen);

      const rx = new OpticalReceiver();
      let dropped = 0;
      let done: Uint8Array | null = null;
      let checksumOk = false;
      for (let seq = 0; seq < 300 && !done; seq++) {
        if (seq % 3 === 2) {
          dropped++;
          continue;
        }
        const status = rx.feed(stream.frame(seq));
        expect(status.kind).not.toBe('refused');
        if (status.kind === 'complete') {
          done = status.payload;
          checksumOk = status.checksumOk;
        }
      }
      expect(dropped).toBeGreaterThan(0);
      expect(done).not.toBeNull();
      expect(checksumOk).toBe(true);
      expect(Buffer.from(done!).equals(Buffer.from(payload))).toBe(true);
    });
  }

  it('honest frames from the encoder are never refused by the caps', () => {
    // The caps must reject only headers no encoder can produce. Sweep the whole legal
    // payload range, default sizing and explicit sizing.
    for (const len of [1, 15, 16, 17, 146, 154, 1000, 2953, 2954, 8192, MAX_TOTAL_LEN]) {
      const payload = filler(len, len);
      for (const frameBytes of [undefined, HEADER_LEN + 512, HEADER_LEN + MAX_BLOCK_LEN]) {
        const stream = encodeCardFrames(payload, { frameBytes, sessionId: 1234 });
        expect(stream.k).toBeLessThanOrEqual(MAX_K);
        for (const seq of [0, 1, 2, 17, 4242]) {
          const wire = stream.frame(seq);
          const parsed = parseFrame(wire);
          expect(parsed, `len=${len} frameBytes=${String(frameBytes)} seq=${seq}`).not.toBeNull();
          expect(headerRefusal(parsed!.header)).toBeNull();
        }
      }
    }
  });

  it('reports the fnv checksum as a hint, not as authenticity', () => {
    // payloadFnv is 32-bit and non-cryptographic. Anyone who can put a QR in front of
    // the camera can set it. A consistently wrong value still assembles the correct
    // bytes: the signature check in card.ts is what decides whether they mean anything.
    const payload = filler(400, 9);
    const stream = encodeCardFrames(payload, { frameBytes: HEADER_LEN + 100, sessionId: 3 });
    const rx = new OpticalReceiver();
    let done: Uint8Array | null = null;
    let checksumOk = true;
    for (let seq = 0; seq < 100 && !done; seq++) {
      const wire = stream.frame(seq);
      new DataView(wire.buffer, wire.byteOffset, wire.byteLength).setUint32(16, 0xdeadbeef, true);
      const status = rx.feed(wire);
      if (status.kind === 'complete') {
        done = status.payload;
        checksumOk = status.checksumOk;
      }
    }
    expect(done).not.toBeNull();
    expect(checksumOk).toBe(false);
    expect(Buffer.from(done!).equals(Buffer.from(payload))).toBe(true);
  });
});

describe('frame header bounds', () => {
  // Shapes upstream PR #27 enumerates for the invariant
  // (k-1)*blockLen < totalLen <= k*blockLen, plus the Keyweave ceilings.
  const accepted: [string, FrameHeader][] = [
    ['consistent single block', header({ k: 1, blockLen: 100, totalLen: 100 })],
    ['full last block', header({ k: 3, blockLen: 100, totalLen: 300 })],
    ['short last block', header({ k: 3, blockLen: 100, totalLen: 250 })],
    ['exactly one byte in the last block', header({ k: 3, blockLen: 100, totalLen: 201 })],
    ['at the k ceiling', header({ k: MAX_K, blockLen: 512, totalLen: MAX_K * 512 })],
    ['at the totalLen ceiling', header({ k: 6, blockLen: 2953, totalLen: MAX_TOTAL_LEN })],
    ['at the blockLen ceiling', header({ k: 1, blockLen: MAX_BLOCK_LEN, totalLen: MAX_BLOCK_LEN })],
  ];

  const rejected: [string, FrameHeader][] = [
    ['totalLen one over k blocks', header({ k: 3, blockLen: 100, totalLen: 301 })],
    ['totalLen leaves a whole block unused', header({ k: 3, blockLen: 100, totalLen: 200 })],
    ['k=1 with totalLen 0xFFFFFFFF', header({ k: 1, blockLen: 100, totalLen: 0xffffffff })],
    ['k over the cap, otherwise consistent', header({ k: MAX_K + 1, blockLen: 100, totalLen: (MAX_K + 1) * 100 })],
    ['blockLen over the cap, otherwise consistent', header({ k: 1, blockLen: MAX_BLOCK_LEN + 1, totalLen: MAX_BLOCK_LEN + 1 })],
    ['totalLen over the cap, otherwise consistent', header({ k: 7, blockLen: 2953, totalLen: 7 * 2953 })],
  ];

  for (const [name, h] of accepted) {
    it(`accepts: ${name}`, () => {
      expect(headerRefusal(h)).toBeNull();
      expect(parseFrame(frameFor(h))).not.toBeNull();
    });
  }

  for (const [name, h] of rejected) {
    it(`rejects at both walls: ${name}`, () => {
      expect(parseFrame(frameFor(h))).toBeNull();
      expect(headerRefusal(h)).not.toBeNull();
      expect(new OpticalReceiver().feed(frameFor(h)).kind).toBe('refused');
    });
  }

  it('[CRITICAL] refuses the 256 MB single-frame allocation (upstream issue #1)', () => {
    // Converted from the pre-vendor PoC: one 28-byte frame declaring k=1, blockLen=8,
    // totalLen=256MB drove a 256 MB zero-fill in LTDecoder.assemble() upstream, plus a
    // full-length fnv1a pass over it, from a single scanned QR. The u32 ceiling is 4 GB.
    // Upstream's only totalLen ceiling lived in the DCF2 container we deleted, so this
    // must fail at the frame parser and again at the receiver.
    const hostile = header({ k: 1, blockLen: 8, totalLen: 256 * 1024 * 1024 });
    const wire = frameFor(hostile);
    expect(wire.length).toBe(28);

    expect(parseFrame(wire)).toBeNull();
    expect(headerRefusal(hostile)).toMatch(/totalLen out of range/);
    const status = new OpticalReceiver().feed(wire);
    expect(status.kind).toBe('refused');
  });

  it('[CRITICAL] the decoder refuses that geometry when constructed directly', () => {
    // Both walls above sit on the path through OpticalReceiver.feed(): parseFrame() is not
    // on a direct caller's path and headerRefusal() is a free function nobody has to call.
    // A caller that imports the codec and builds its own decoder passes neither, and that
    // is exactly the shape of upstream issue #1's proof of concept. Before the constructor
    // ceilings this line returned a 268435456-byte buffer.
    expect(() => new LTDecoder(1, 8, 1, 256 * 1024 * 1024)).toThrow(/totalLen out of range/);
    expect(() => new LTDecoder(MAX_K + 1, 8, 1, 8)).toThrow(/k out of range/);
    expect(() => new LTDecoder(1, MAX_BLOCK_LEN + 1, 1, 8)).toThrow(/blockLen out of range/);

    // Positive control: geometry a real encoder can produce is still built, so the
    // ceilings are not simply refusing everything.
    expect(() => new LTDecoder(5, 32, 1, 146)).not.toThrow();
    expect(() => new LTDecoder(6, MAX_BLOCK_LEN, 1, MAX_TOTAL_LEN)).not.toThrow();
  });

  it('rejects malformed frames before any header math', () => {
    expect(parseFrame(new Uint8Array(HEADER_LEN))).toBeNull(); // header only, no block
    const wrongMagic = frameFor(header({}));
    wrongMagic[0] = 0x00;
    expect(parseFrame(wrongMagic)).toBeNull();
    const truncated = frameFor(header({})).subarray(0, HEADER_LEN + 50);
    expect(parseFrame(truncated)).toBeNull(); // declares 100 payload bytes, carries 50
    expect(parseFrame(frameFor(header({ k: 0 })))).toBeNull();
    expect(parseFrame(frameFor(header({ totalLen: 0 })))).toBeNull();
  });
});

describe('stream identity drift', () => {
  it('a new session mid-stream starts a fresh decoder', () => {
    const a = filler(400, 1);
    const b = filler(400, 2);
    const sa = encodeCardFrames(a, { frameBytes: HEADER_LEN + 100, sessionId: 11 });
    const sb = encodeCardFrames(b, { frameBytes: HEADER_LEN + 100, sessionId: 22 });

    const rx = new OpticalReceiver();
    for (const seq of [0, 1]) {
      const status = rx.feed(sa.frame(seq));
      expect(status.kind).toBe('progress');
    }
    const first = rx.feed(sb.frame(0));
    expect(first.kind).toBe('progress');
    if (first.kind === 'progress') expect(first.framesNew).toBe(1); // decoder was replaced

    let done: Uint8Array | null = null;
    for (let seq = 1; seq < 100 && !done; seq++) {
      const status = rx.feed(sb.frame(seq));
      if (status.kind === 'complete') done = status.payload;
    }
    expect(done).not.toBeNull();
    expect(Buffer.from(done!).equals(Buffer.from(b))).toBe(true);
  });

  it('same session id but different content is still a different stream', () => {
    // The 16-bit session id collides across restarts. streamIdentity covers all five
    // header fields, so identical k/blockLen/totalLen with different bytes still resets;
    // without that the old decoder would silently produce garbage.
    const a = filler(400, 3);
    const b = filler(400, 4);
    const sa = encodeCardFrames(a, { frameBytes: HEADER_LEN + 100, sessionId: 99 });
    const sb = encodeCardFrames(b, { frameBytes: HEADER_LEN + 100, sessionId: 99 });
    expect(sa.k).toBe(sb.k);
    expect(sa.totalLen).toBe(sb.totalLen);

    const rx = new OpticalReceiver();
    rx.feed(sa.frame(0));
    rx.feed(sa.frame(1));
    rx.feed(sa.frame(2));

    let done: Uint8Array | null = null;
    for (let seq = 0; seq < 100 && !done; seq++) {
      const status = rx.feed(sb.frame(seq));
      if (status.kind === 'complete') done = status.payload;
    }
    expect(done).not.toBeNull();
    expect(Buffer.from(done!).equals(Buffer.from(b))).toBe(true);
  });

  it('reset() drops stream state', () => {
    const a = filler(400, 5);
    const sa = encodeCardFrames(a, { frameBytes: HEADER_LEN + 100, sessionId: 5 });
    const rx = new OpticalReceiver();
    rx.feed(sa.frame(0));
    rx.feed(sa.frame(1));
    rx.reset();
    const status = rx.feed(sa.frame(2));
    expect(status.kind).toBe('progress');
    if (status.kind === 'progress') expect(status.framesNew).toBe(1);
  });
});

describe('encoder input validation', () => {
  it('never draws session id 0 and never exceeds the u16', () => {
    const card = filler(146, 6);
    const seen = new Set<number>();
    for (let i = 0; i < 5000; i++) {
      const id = encodeCardFrames(card).sessionId;
      expect(id).toBeGreaterThanOrEqual(1);
      expect(id).toBeLessThanOrEqual(0xffff);
      seen.add(id);
    }
    expect(seen.has(0)).toBe(false);
    expect(seen.size).toBeGreaterThan(100); // it is actually drawing, not pinned
  });

  it('boundary draws of the session id scheme cannot produce 0 or overflow', () => {
    const real = Math.random;
    try {
      for (const r of [0, 0.5, 1 - Number.EPSILON / 2]) {
        Math.random = () => r;
        const id = encodeCardFrames(filler(146, 7)).sessionId;
        expect(id).toBeGreaterThanOrEqual(1);
        expect(id).toBeLessThanOrEqual(0xffff);
      }
    } finally {
      Math.random = real;
    }
  });

  it('refuses an oversized card', () => {
    expect(() => encodeCardFrames(filler(MAX_TOTAL_LEN + 1, 8))).toThrow(/over the 16384 byte cap/);
  });

  it('refuses an empty card', () => {
    expect(() => encodeCardFrames(new Uint8Array(0))).toThrow(/empty card/);
  });

  it('refuses a frame size outside the block-length range', () => {
    expect(() => encodeCardFrames(filler(100, 9), { frameBytes: HEADER_LEN })).toThrow(/frameBytes/);
    expect(() =>
      encodeCardFrames(filler(100, 9), { frameBytes: HEADER_LEN + MAX_BLOCK_LEN + 1 }),
    ).toThrow(/frameBytes/);
  });

  it('refuses a frame size that would need more than MAX_K source blocks', () => {
    expect(() => encodeCardFrames(filler(4000, 10), { frameBytes: HEADER_LEN + 100 })).toThrow(
      /exceeds the 32 block cap/,
    );
  });

  it('refuses a session id outside 1..65535', () => {
    for (const sessionId of [0, -1, 0x10000, 1.5]) {
      expect(() => encodeCardFrames(filler(100, 11), { sessionId })).toThrow(/sessionId/);
    }
  });

  it('refuses a seq outside the u32 the header can carry', () => {
    const stream = encodeCardFrames(filler(100, 12));
    expect(() => stream.frame(-1)).toThrow(/seq/);
    expect(() => stream.frame(0x100000000)).toThrow(/seq/);
    expect(() => stream.frame(1.5)).toThrow(/seq/);
    expect(stream.frame(0xffffffff).length).toBe(stream.frameBytes);
  });

  it('separates ordinary non-Keyweave symbols from capped frames in its counters', () => {
    // A camera pointed at the world decodes posters and URL QR codes. A UI that shows one
    // "refused" number reads that noise as hostile traffic, and an operator triaging a real
    // optical attack cannot tell the two apart. Pin the split.
    const rx = new OpticalReceiver();

    // Noise: not one of ours (bad magic, wrong length). Not an attack signal.
    expect(rx.feed(new Uint8Array(30)).kind).toBe('refused');
    expect(rx.malformedCount).toBe(1);
    expect(rx.cappedCount).toBe(0);

    // A well-formed frame whose declared geometry the caps refuse. This IS the signal.
    const hostile = packFrame(
      { sessionId: 1, seq: 0, k: 1, blockLen: 8, totalLen: 268435456, payloadFnv: 0 },
      new Uint8Array(8),
    );
    expect(rx.feed(hostile).kind).toBe('refused');
    expect(rx.cappedCount).toBe(1);
    expect(rx.malformedCount).toBe(1); // unchanged by the capped frame
    expect(rx.refusedCount).toBe(2);

    rx.reset();
    expect(rx.malformedCount).toBe(0);
    expect(rx.cappedCount).toBe(0);
    expect(rx.refusedCount).toBe(0);
  });

  it('default frame sizing does not degenerate to k=1 on a real card', () => {
    // A signed card is ~146-154 bytes. At the frame sizes decimen ships (2933 payload
    // bytes) that is k=1, which turns the fountain into plain frame repetition.
    for (const len of [146, 154, 512, 1200]) {
      const stream = encodeCardFrames(filler(len, len), { sessionId: 1 });
      expect(stream.k).toBeGreaterThanOrEqual(4);
      expect(stream.k).toBeLessThanOrEqual(6);
      expect(stream.frameBytes).toBeLessThanOrEqual(HEADER_LEN + MAX_BLOCK_LEN);
    }
  });
});
