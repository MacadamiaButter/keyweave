// The receiver half of the optical hop: camera in, decoded payloads out.
//
// The quirk handling here is ported from decimen's receive shell, deliberately and not
// re-derived (client/vendor/decimen/PROVENANCE.md lists it as this work package's debt).
// Each item below cost somebody a debugging session:
//
//   - SECURE CONTEXT FIRST. On an insecure origin `navigator.mediaDevices` is undefined
//     entirely: there is no prompt to accept and no permission to grant. Diagnosing that
//     as a denial sends the user to reset a permission that was never asked for.
//   - FRAME RATE. `frameRate: { exact: n }` is what actually pins a camera that would
//     otherwise negotiate 15 fps, and it is also what some cameras reject outright. Try
//     exact, fall back to ideal, fall back to neither. This replaces upstream's iOS branch
//     with an attempt, so there is no user-agent string in this file.
//   - READ THE SETTINGS BACK. A camera that accepted a constraint and then ignored it is
//     ordinary. `track.getSettings()` is the only honest source for what is running, and
//     the delta is surfaced rather than assumed away.
//   - GENERATION COUNTER. `requestVideoFrameCallback` re-arms itself, so a stopped stream
//     with a callback already in flight leaves a capture loop running against a dead
//     track. Every callback checks the generation it was born in.
//   - A LIVE applyConstraints THAT FAILS IS NOT A FAILED SCAN. Some cameras refuse any
//     change once the stream is running. The stream stays up and the UI says so.
//   - PROBE, NEVER SNIFF. focusMode and torch come from getCapabilities.
//   - TORCH IS DELIBERATELY UNUSED. The sender is an emissive screen, so a flashlight adds
//     glare over the thing being read. It is probed and reported, never enabled.
//   - DROP, DO NOT QUEUE. When every decode worker is busy the frame is discarded. The
//     next frame is worth more than a stale one, and the fountain absorbs the miss.
//   - willReadFrequently, because every single frame is read straight back out.

import { DecodeWorkerPool, type PoolWorker } from '../../vendor/decimen/worker-pool.js';
import {
  applyAdvancedConstraint,
  probeCameraCapabilities,
} from '../../vendor/decimen/platform.js';
import { OpticalReceiver } from '../optical.js';
import { toHex } from '../bytes.js';

export type CameraFailureKind =
  | 'insecure-context'
  | 'denied'
  | 'no-camera'
  | 'in-use'
  | 'unknown';

export class CameraFailure extends Error {
  constructor(
    readonly kind: CameraFailureKind,
    message: string,
  ) {
    super(message);
    this.name = 'CameraFailure';
  }
}

export interface CameraNotes {
  readonly requestedFrameRate: number;
  readonly frameRateExact: boolean;
  readonly actualFrameRate: number | undefined;
  readonly width: number | undefined;
  readonly height: number | undefined;
  readonly continuousFocus: boolean;
  /** Probed and reported so the capability is visible. Never switched on; see the header. */
  readonly torchAvailable: boolean;
  readonly refusedLiveChange: boolean;
}

export interface ScanProgress {
  /** Source blocks in the stream currently being decoded, 0 when nothing is locked on. */
  readonly k: number;
  readonly solved: number;
  /** Symbols that were not Keyweave frames at all. Ordinary noise, never an attack signal. */
  readonly malformed: number;
  /** Well-formed frames refused by the header caps. THIS is the signal the caps exist for. */
  readonly capped: number;
  /** Frames discarded because every decode worker was busy. */
  readonly dropped: number;
}

export interface OpticalScannerOptions {
  video: HTMLVideoElement;
  onPayload: (payload: Uint8Array) => void;
  onProgress?: (progress: ScanProgress) => void;
  createWorker?: () => PoolWorker;
  poolSize?: number;
  frameRate?: number;
  maxCaptureEdge?: number;
}

const DEFAULT_FRAME_RATE = 30;
/** Capture cap. Larger frames decode no better and cost the whole budget in getImageData. */
const DEFAULT_MAX_EDGE = 960;
/** Distinct payloads remembered so a stream still on screen is not re-emitted forever. */
const EMITTED_MEMORY = 16;

function defaultWorker(): PoolWorker {
  return new Worker(new URL('../../vendor/decimen/receive-worker.ts', import.meta.url), {
    type: 'module',
  }) as unknown as PoolWorker;
}

export class OpticalScanner {
  private readonly receiver = new OpticalReceiver();
  private readonly emitted: string[] = [];
  private readonly canvas: HTMLCanvasElement;
  private readonly ctx: CanvasRenderingContext2D;
  private pool: DecodeWorkerPool | undefined;
  private stream: MediaStream | undefined;
  private generation = 0;
  /** One-way: a stopped scanner never starts again, a fresh one is constructed instead. */
  private stopped = false;
  private dropped = 0;
  private cameraNotes: CameraNotes | undefined;

  constructor(private readonly opts: OpticalScannerOptions) {
    this.canvas = document.createElement('canvas');
    const ctx = this.canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) throw new Error('camera: no 2d context');
    this.ctx = ctx;
  }

  notes(): CameraNotes | undefined {
    return this.cameraNotes;
  }

  async start(): Promise<CameraNotes> {
    // FIRST, before any permission story: an insecure origin has no mediaDevices at all.
    if (typeof window !== 'undefined' && window.isSecureContext === false) {
      throw new CameraFailure('insecure-context', 'not a secure context');
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new CameraFailure('insecure-context', 'navigator.mediaDevices is unavailable');
    }

    const frameRate = this.opts.frameRate ?? DEFAULT_FRAME_RATE;
    const { stream, exact } = await requestCamera(frameRate);

    // start() awaits a permission prompt, so a stop() can land while it is still in the
    // air. Without this the camera light comes on for a screen that is already gone.
    if (this.stopped) {
      stopStream(stream);
      throw new CameraFailure('unknown', 'the scanner was stopped while the camera opened');
    }
    this.stream = stream;

    try {
      const track = stream.getVideoTracks()[0];
      if (!track) throw new CameraFailure('no-camera', 'the stream carries no video track');

      const caps = probeCameraCapabilities(track);
      let refusedLiveChange = false;
      if (caps.continuousFocus) {
        // A live change some cameras will not make. Refusing it is not a scan failure.
        refusedLiveChange = !(await applyAdvancedConstraint(track, { focusMode: 'continuous' }));
      }

      const settings = track.getSettings();
      this.cameraNotes = {
        requestedFrameRate: frameRate,
        frameRateExact: exact,
        actualFrameRate: settings.frameRate,
        width: settings.width,
        height: settings.height,
        continuousFocus: caps.continuousFocus && !refusedLiveChange,
        torchAvailable: caps.torch,
        refusedLiveChange,
      };

      const video = this.opts.video;
      video.srcObject = stream;
      video.muted = true;
      video.playsInline = true;
      await video.play();
      if (this.stopped) throw new CameraFailure('unknown', 'the scanner was stopped');

      this.pool = new DecodeWorkerPool(this.opts.createWorker ?? defaultWorker, (bytes) =>
        this.onDecoded(bytes),
      );
      this.pool.resize(this.opts.poolSize ?? defaultPoolSize());

      this.runCaptureLoop();
      return this.cameraNotes;
    } catch (error) {
      // Anything after the camera opened has to hand the camera back. A live track behind
      // a failed screen is the one failure mode a user can see from across the room.
      this.stop();
      throw error;
    }
  }

  stop(): void {
    // Bump FIRST: a callback already queued must see a stale generation and return.
    this.generation++;
    this.stopped = true;
    this.pool?.resize(0);
    this.pool = undefined;
    if (this.stream) stopStream(this.stream);
    this.stream = undefined;
    const video = this.opts.video;
    video.pause();
    video.srcObject = null;
    this.receiver.reset();
    this.emitted.length = 0;
    this.dropped = 0;
  }

  private runCaptureLoop(): void {
    const generation = ++this.generation;
    const video = this.opts.video;
    const useVfc = typeof video.requestVideoFrameCallback === 'function';
    const step = () => {
      if (generation !== this.generation) return;
      this.captureOnce();
      if (useVfc) video.requestVideoFrameCallback(step);
      else requestAnimationFrame(step);
    };
    if (useVfc) video.requestVideoFrameCallback(step);
    else requestAnimationFrame(step);
  }

  private captureOnce(): void {
    const video = this.opts.video;
    const vw = video.videoWidth;
    const vh = video.videoHeight;
    if (vw === 0 || vh === 0) return;
    const pool = this.pool;
    if (!pool) return;

    const maxEdge = this.opts.maxCaptureEdge ?? DEFAULT_MAX_EDGE;
    const scale = Math.min(1, maxEdge / Math.max(vw, vh));
    const w = Math.max(1, Math.round(vw * scale));
    const h = Math.max(1, Math.round(vh * scale));
    if (this.canvas.width !== w || this.canvas.height !== h) {
      this.canvas.width = w;
      this.canvas.height = h;
    }
    this.ctx.drawImage(video, 0, 0, w, h);
    const image = this.ctx.getImageData(0, 0, w, h);
    const buf = image.data.buffer as ArrayBuffer;
    // Transferred, not copied. The next getImageData allocates a fresh one.
    if (!pool.submit({ id: 0, buf, w, h }, [buf])) this.dropped++;
  }

  private onDecoded(bytes: Uint8Array): void {
    const status = this.receiver.feed(bytes);
    if (status.kind === 'complete') {
      const key = toHex(status.payload);
      if (!this.emitted.includes(key)) {
        this.emitted.push(key);
        if (this.emitted.length > EMITTED_MEMORY) this.emitted.shift();
        this.opts.onPayload(status.payload);
      }
    }
    this.opts.onProgress?.({
      k: status.kind === 'progress' ? status.k : 0,
      solved: status.kind === 'progress' ? status.solved : 0,
      malformed: this.receiver.malformedCount,
      capped: this.receiver.cappedCount,
      dropped: this.dropped,
    });
  }
}

function defaultPoolSize(): number {
  // Each worker holds its own ~940 KB wasm instance, so this is a memory decision as much
  // as a throughput one. Leave a core for the capture loop and the QR the other side reads.
  const cores = navigator.hardwareConcurrency ?? 2;
  return Math.max(1, Math.min(3, cores - 1));
}

function stopStream(stream: MediaStream): void {
  for (const track of stream.getTracks()) track.stop();
}

async function requestCamera(
  frameRate: number,
): Promise<{ stream: MediaStream; exact: boolean }> {
  const base: MediaTrackConstraints = {
    facingMode: { ideal: 'environment' },
    width: { ideal: 1280 },
    height: { ideal: 720 },
  };
  const attempts: { constraints: MediaTrackConstraints; exact: boolean }[] = [
    { constraints: { ...base, frameRate: { exact: frameRate } }, exact: true },
    { constraints: { ...base, frameRate: { ideal: frameRate } }, exact: false },
    { constraints: base, exact: false },
  ];

  let last: unknown;
  for (const attempt of attempts) {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: attempt.constraints });
      return { stream, exact: attempt.exact };
    } catch (error) {
      // A denial is a decision, not a constraint problem: retrying with a looser shape
      // just fires more prompts at somebody who already said no.
      if (nameOf(error) === 'NotAllowedError' || nameOf(error) === 'SecurityError') {
        throw new CameraFailure('denied', 'camera permission refused');
      }
      last = error;
    }
  }
  throw cameraFailureFor(last);
}

function nameOf(error: unknown): string {
  return error instanceof Error ? error.name : '';
}

function cameraFailureFor(error: unknown): CameraFailure {
  const message = error instanceof Error ? error.message : String(error);
  switch (nameOf(error)) {
    case 'NotFoundError':
    case 'OverconstrainedError':
      return new CameraFailure('no-camera', message);
    case 'NotReadableError':
    case 'AbortError':
      return new CameraFailure('in-use', message);
    default:
      return new CameraFailure('unknown', message);
  }
}
