// The sender half of the optical hop: an animated QR on a canvas.
//
// PACING. A capture at 30 fps that lands mid-repaint reads a torn symbol, so a frame is
// held for several display refreshes rather than swapped every one. Two refreshes is the
// floor; three is used here, which is 20 fps on a 60 Hz panel and leaves a margin on a
// panel that is not exactly 60. The fountain code makes throughput a non-issue: a card is
// about five source blocks, so a receiver completes in well under a second either way, and
// the scarce resource is clean captures, not frames per second.
//
// DENSITY. Error correction level L, and small frames. A QR carrying 50 bytes is a version
// 3 or 4 symbol with fat modules that decodes across a table; pushing the payload up to
// shrink the frame count buys nothing here and costs exactly the range the ceremony needs.
// Per-symbol error correction is also the wrong place to spend: a symbol the camera misses
// entirely is absorbed by the fountain, which is redundancy at the layer that has it.
//
// PLAYLIST. A ceremony turn shows more than one payload (card, nonce, proof). Every frame
// is self-describing, so the streams simply take turns on screen: the receiver locks onto
// whichever is playing and re-locks when the stream identity changes. No acknowledgement
// channel is needed between the two devices, which is what makes the whole ceremony work
// with a camera and no network.
//
// REDUCED MOTION. The animation is not decoration, it is the payload, so frame advance
// continues. What prefers-reduced-motion drops is in the stylesheet: easing, transitions
// and the spinner.

import { create as createQr } from 'qrcode/lib/core/qrcode.js';
import { rasterizeQr } from '../../vendor/decimen/qr-raster.js';
import type { CardFrameStream } from '../optical.js';

/** Display refreshes each frame is held for. Two is the floor a capture needs. */
export const HOLD_REFRESHES = 3;
/** How long one stream stays on screen before the playlist moves on. */
export const DWELL_MS = 2600;
/** Quiet zone in modules. The specification says 4; below that decoders start guessing. */
export const QUIET_MODULES = 4;

export interface QrPlayerOptions {
  holdRefreshes?: number;
  dwellMs?: number;
}

export class QrPlayer {
  private readonly holdRefreshes: number;
  private readonly dwellMs: number;
  private readonly ctx: CanvasRenderingContext2D;
  private playlist: readonly CardFrameStream[] = [];
  private seqs: number[] = [];
  private index = 0;
  private ticks = 0;
  private streamStartedAt = 0;
  /**
   * Generation counter. Every scheduled callback captures the generation it was created
   * in, so a stopped player cannot be resurrected by a frame that was already in flight.
   * Same reason the camera loop has one.
   */
  private generation = 0;
  private wakeLock: WakeLockSentinel | undefined;

  constructor(
    private readonly canvas: HTMLCanvasElement,
    opts: QrPlayerOptions = {},
  ) {
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('qr-display: no 2d context');
    this.ctx = ctx;
    this.holdRefreshes = Math.max(2, opts.holdRefreshes ?? HOLD_REFRESHES);
    this.dwellMs = opts.dwellMs ?? DWELL_MS;
  }

  play(playlist: readonly CardFrameStream[]): void {
    this.stop();
    if (playlist.length === 0) return;
    this.playlist = playlist;
    this.seqs = playlist.map(() => 0);
    this.index = 0;
    this.ticks = 0;
    this.streamStartedAt = 0;
    const generation = ++this.generation;
    void this.acquireWakeLock();
    this.draw();
    const step = (now: number) => {
      if (generation !== this.generation) return;
      if (this.streamStartedAt === 0) this.streamStartedAt = now;
      if (this.playlist.length > 1 && now - this.streamStartedAt >= this.dwellMs) {
        this.index = (this.index + 1) % this.playlist.length;
        this.streamStartedAt = now;
        this.ticks = 0;
        this.draw();
      } else if (++this.ticks >= this.holdRefreshes) {
        this.ticks = 0;
        // seq is a u32 on the wire; wrapping keeps a long-running display legal rather
        // than throwing at 2^32 frames.
        this.seqs[this.index] = (this.seqs[this.index]! + 1) >>> 0;
        this.draw();
      }
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  stop(): void {
    this.generation++;
    this.playlist = [];
    void this.releaseWakeLock();
  }

  /** Which payload of the playlist is on screen, 1-based. For the status line. */
  currentIndex(): number {
    return this.playlist.length === 0 ? 0 : this.index + 1;
  }

  private draw(): void {
    const stream = this.playlist[this.index];
    if (!stream) return;
    const bytes = stream.frame(this.seqs[this.index]!);
    const qr = createQr([{ data: bytes, mode: 'byte' }], { errorCorrectionLevel: 'L' });
    const raster = rasterizeQr(qr.modules.size, qr.modules.data, QUIET_MODULES);

    // One canvas pixel per QR module. The stylesheet scales it up with
    // image-rendering: pixelated, which is sharper than any smoothing this could do and
    // costs no per-frame work.
    if (this.canvas.width !== raster.size || this.canvas.height !== raster.size) {
      this.canvas.width = raster.size;
      this.canvas.height = raster.size;
    }
    this.ctx.putImageData(
      new ImageData(new Uint8ClampedArray(raster.pixels.buffer), raster.size, raster.size),
      0,
      0,
    );
  }

  private async acquireWakeLock(): Promise<void> {
    // Best effort by design: no browser owes us this, and a ceremony where the screen
    // dims is annoying, not broken.
    if (!('wakeLock' in navigator)) return;
    try {
      this.wakeLock = await navigator.wakeLock.request('screen');
    } catch {
      this.wakeLock = undefined;
    }
  }

  private async releaseWakeLock(): Promise<void> {
    const lock = this.wakeLock;
    this.wakeLock = undefined;
    if (!lock) return;
    try {
      await lock.release();
    } catch {
      // A lock the system already dropped is not an error worth surfacing.
    }
  }
}
