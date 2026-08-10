// @vitest-environment happy-dom

// The two optical loops, and the instrument that can actually see one stop.
//
// WHY THIS FILE EXISTS. teardownOptics stops the QR player and the camera scanner in one
// breath, and app-lock.test.ts proves the app calls it on a lock. What nothing could see
// until now is whether either stop() ENDS anything. Both loops are driven by a callback that
// re-arms itself, and both are stopped by bumping a generation counter that every scheduled
// callback compares against. Delete either bump and the loop keeps rescheduling itself
// forever against an emptied playlist or a released camera track, holding the closure, the
// 2d context and the element for the life of the page. stop() has three obligations on the
// player alone (end the schedule, empty the playlist, hand back the wake lock) and only one
// of them had any observable consequence in the suite.
//
// THE INSTRUMENT IS THE POINT, AND IT IS WHY THE ASSERTION ORDER BELOW IS DESIGN. Every
// counter this suite had was a counter of WORK: frames painted, frames handed to the decode
// pool. Neither can see the defect, because stop() also removes the work. The player's
// playlist is emptied, so draw() early-returns; the scanner's pool is dropped, so
// captureOnce() early-returns. A work counter therefore reads identically whether the loop
// stopped or is spinning. Measured: with qr-display.ts's `this.generation++` deleted,
// app-lock.test.ts's "stops the code on screen too", whose entire subject is this teardown
// and which counts painted frames, still passes. So the counter here is a count of
// SCHEDULING calls, and every test that stops a loop asserts the work counter on the line
// ABOVE the scheduling counter, so that a run under the defect shows the old instrument
// passing immediately before the new one goes red.
//
// STOPPING IS NOT ONLY stop(). Three more paths end a loop or start one over, and each has
// its own way of leaving something running: play() has to stop the loop that is already
// going before it starts the next one, INCLUDING when the new playlist is empty; play() has
// to put back every piece of state the previous turn moved, or the second turn opens on the
// wrong payload with a dwell clock that already expired; and start() awaits a permission
// prompt and a preview, so a stop() can land in the middle of it and has to leave the camera
// off. Those three are as covered here as stop() is.
//
// WHAT IS FAKE, AND WHY. happy-dom has no canvas raster, no media stack and no Worker, so a
// 2d context, a camera and a decode worker stand in, and requestAnimationFrame /
// requestVideoFrameCallback are replaced by a queue this file pumps by hand: a scheduler a
// test drives is the only way to count re-arms without waiting on a real display. Above
// those the real QrPlayer and the real OpticalScanner run, on the real fountain encoder and
// the real QR rasteriser.
//
// The seams are all in the test (Feathers). qr-display.ts takes the CardFrameStream its
// caller hands it, so a labelled stream that writes down which payload was asked for at
// which seq needs no change in src/, and the scanner takes its worker factory as an option
// for the same reason. Everything installed on a global is put back in an afterEach, because
// a file that leaves navigator.mediaDevices redefined is a file that breaks whichever test
// file happens to run next.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { QrPlayer, QUIET_MODULES } from '../src/ui/qr-display.js';
import { CameraFailure, OpticalScanner } from '../src/ui/camera.js';
import { encodeCardFrames, type CardFrameStream } from '../src/optical.js';
import type { PoolWorker } from '../vendor/decimen/worker-pool.js';

// ---- the scheduler the loops are driven by --------------------------------

/** A hand-pumped scheduler standing in for the display and the video frame callback. */
interface Sched {
  /** Calls to the scheduler. THE instrument: this is what no work counter can see. */
  scheduled: number;
  /** Callbacks handed over and not yet delivered. A live one after stop() is the leak. */
  pending: ((now: number) => void)[];
}

function newSched(): Sched {
  return { scheduled: 0, pending: [] };
}

function schedule(s: Sched, cb: (now: number) => void): number {
  s.scheduled++;
  s.pending.push(cb);
  return s.scheduled;
}

/** Both loops call the bare global, so a stub on globalThis is what they see. */
function stubRaf(s: Sched): void {
  vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => schedule(s, cb));
}

/** Deliver everything due, once each, at `now`. Re-arms land in the next pump, not this one. */
function pump(s: Sched, now = 0): void {
  for (const cb of s.pending.splice(0, s.pending.length)) cb(now);
}

/** One real macrotask, which drains the microtasks behind a fire-and-forget wake lock call. */
async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

/** Put a property back on a global after a test redefined it. */
function restoreGlobal(host: object, key: string): void {
  delete (host as unknown as Record<string, unknown>)[key];
}

// ---- the QR player's half -------------------------------------------------

/** QR frames painted: the WORK counter, kept only to show it cannot see the defect. */
let painted = 0;
/** Frames handed to the decode pool: the capture loop's work counter, same role. */
let submitted = 0;
/** Decode workers terminated. A pool that is never resized to zero leaks its wasm. */
let terminated = 0;
/** The last raster handed to the 2d context, and where it was put. */
let lastImage: ImageData | undefined;
let lastImageAt: { dx: number; dy: number } | undefined;

function fakeCanvas(): HTMLCanvasElement {
  return {
    width: 0,
    height: 0,
    getContext: () => ({
      putImageData: (image: ImageData, dx: number, dy: number) => {
        lastImage = image;
        lastImageAt = { dx, dy };
        painted++;
      },
    }),
  } as unknown as HTMLCanvasElement;
}

interface FakeWakeLock {
  requests: number;
  releases: number;
}

/** happy-dom has no wakeLock at all, so the player's best-effort branch returns early. */
function installFakeWakeLock(): FakeWakeLock {
  const wake: FakeWakeLock = { requests: 0, releases: 0 };
  Object.defineProperty(navigator, 'wakeLock', {
    configurable: true,
    value: {
      request: async () => {
        wake.requests++;
        return {
          release: async () => {
            wake.releases++;
          },
        };
      },
    },
  });
  return wake;
}

/**
 * A real frame stream with a label on it, so a test can say WHICH payload was drawn at WHICH
 * seq. Everything but the note-taking is the shipped encoder.
 */
function labelled(label: string, drawn: string[]): CardFrameStream {
  const stream = encodeCardFrames(new Uint8Array(40).fill(0x51));
  return {
    ...stream,
    frame(seq: number): Uint8Array {
      drawn.push(`${label}${seq}`);
      return stream.frame(seq);
    },
  };
}

// ---- the camera's half ----------------------------------------------------

interface FakeCamera {
  /** getUserMedia calls, so "the track was never stopped" cannot pass as "no track". */
  opened: number;
  /** stop() calls on the video track: the positive control that stop() really ran. */
  stops: number;
  /** Emptied by a test to model a stream that opened and carries no video track. */
  videoTracks: unknown[];
}

/** What the scanner drew and read back: the capture geometry, which is otherwise invisible. */
interface FakeCapture {
  /** One entry per getImageData, in order. The size the decoder is actually handed. */
  frames: { w: number; h: number }[];
  /** The scanner's own offscreen canvas, captured when it asks for its context. */
  canvas: HTMLCanvasElement | undefined;
}

/** The scanner reads every frame straight back out, which happy-dom cannot do. */
function installCanvasContext(): FakeCapture {
  const capture: FakeCapture = { frames: [], canvas: undefined };
  const proto = window.HTMLCanvasElement.prototype as unknown as Record<string, unknown>;
  proto.getContext = function (this: HTMLCanvasElement): unknown {
    capture.canvas = this;
    return {
      drawImage: () => undefined,
      getImageData: (_x: number, _y: number, w: number, h: number) => {
        capture.frames.push({ w, h });
        return { data: new Uint8ClampedArray(w * h * 4), width: w, height: h };
      },
    };
  };
  return capture;
}

function installFakeCamera(): FakeCamera {
  const camera: FakeCamera = { opened: 0, stops: 0, videoTracks: [] };
  const track = {
    kind: 'video',
    stop: () => {
      camera.stops++;
    },
    getSettings: () => ({ frameRate: 30, width: 640, height: 480 }),
    applyConstraints: async () => undefined,
  };
  camera.videoTracks = [track];
  // A REAL MediaStream, because HTMLMediaElement.srcObject type-checks what it is given at
  // runtime and the scanner assigns the stream to the <video>. The track list is the
  // stand-in, since happy-dom refuses to construct a MediaStreamTrack.
  const stream = new MediaStream();
  Object.assign(stream as unknown as Record<string, unknown>, {
    getTracks: () => [track],
    getVideoTracks: () => camera.videoTracks,
  });
  Object.defineProperty(navigator, 'mediaDevices', {
    configurable: true,
    value: {
      getUserMedia: async () => {
        camera.opened++;
        return stream;
      },
    },
  });
  return camera;
}

/**
 * A <video> that reports a frame size, so captureOnce() gets past its own early return and
 * the work counter has something to count. `vfc` picks which branch of runCaptureLoop is
 * exercised: a browser with requestVideoFrameCallback, or one without. The size is a
 * parameter because the capture cap is arithmetic on it.
 */
function fakeVideo(s: Sched, vfc: boolean, w = 640, h = 480): HTMLVideoElement {
  const video = document.createElement('video');
  Object.defineProperty(video, 'videoWidth', { value: w });
  Object.defineProperty(video, 'videoHeight', { value: h });
  if (vfc) {
    Object.assign(video as unknown as Record<string, unknown>, {
      requestVideoFrameCallback: (cb: () => void) => schedule(s, cb),
    });
  }
  return video;
}

/**
 * How many times the preview was actually started. The two stopped-while-opening guards are
 * one behind the other, so the LATER one hides the earlier one from every end-state
 * assertion: both leave the camera off and the loop unarmed. What only the earlier guard
 * buys is that the preview element is never handed a live stream at all, and that is
 * countable.
 */
function countPlays(video: HTMLVideoElement): { count: number } {
  const seen = { count: 0 };
  const real = video.play.bind(video);
  Object.assign(video as unknown as Record<string, unknown>, {
    play: () => {
      seen.count++;
      return real();
    },
  });
  return seen;
}

/**
 * Hold the preview open. start() awaits video.play(), and that await is a window a stop()
 * can land in, so a test needs to decide when it closes. Returns the closer.
 */
function deferredPlay(video: HTMLVideoElement): () => void {
  let release = (): void => undefined;
  Object.assign(video as unknown as Record<string, unknown>, {
    play: () => new Promise<void>((resolve) => (release = () => resolve())),
  });
  return () => release();
}

/** Nothing here decodes. The pool only has to accept a frame and be countable. */
function fakeWorker(): PoolWorker {
  return {
    onmessage: null,
    postMessage: () => {
      submitted++;
    },
    terminate: () => {
      terminated++;
    },
  } as unknown as PoolWorker;
}

/** Resolved or rejected, without asserting which first: some tests care about the state the
 *  camera was left in more than about the error, and that assertion should be the one that
 *  reds. */
async function settle(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => 'resolved',
    (error: unknown) => error,
  );
}

beforeEach(() => {
  painted = 0;
  submitted = 0;
  terminated = 0;
  lastImage = undefined;
  lastImageAt = undefined;
});

afterEach(() => vi.unstubAllGlobals());

describe('the QR player ends its own loop', () => {
  let wake: FakeWakeLock;

  beforeEach(() => {
    wake = installFakeWakeLock();
  });

  afterEach(() => restoreGlobal(navigator, 'wakeLock'));

  it('stops SCHEDULING, which the frame counter next to it cannot see', () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 2, dwellMs: 10_000 });
    player.play([labelled('A', drawn)]);

    // Positive control: the loop really is running, so a frozen count below means stopped
    // rather than never started.
    expect(s.scheduled).toBe(1);
    pump(s, 16);
    pump(s, 32);
    expect(s.scheduled).toBe(3);
    expect(painted).toBeGreaterThan(0);

    player.stop();
    const scheduledAtStop = s.scheduled;
    const paintedAtStop = painted;

    // The callbacks that were already in flight when stop() landed.
    pump(s, 48);
    pump(s, 64);

    // A FRAME counter cannot see the defect: draw() early-returns on the emptied playlist,
    // so this line passes whether the loop stopped or is spinning forever.
    expect(painted).toBe(paintedAtStop);
    // The SCHEDULING counter can.
    expect(s.scheduled).toBe(scheduledAtStop);
    expect(s.pending).toHaveLength(0);
  });

  it('starts nothing at all for an empty playlist', () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 2, dwellMs: 10_000 });

    // Nothing to show is not the same as something to show that paints nothing: the second
    // one is a callback chain re-arming forever over an empty playlist.
    player.play([]);
    expect(painted).toBe(0);
    expect(s.scheduled).toBe(0);

    // Negative control for the line above: the same harness DOES count a real playlist.
    player.play([labelled('A', drawn)]);
    expect(s.scheduled).toBe(1);
  });

  it('stops a RUNNING player when play() is handed nothing to show', () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 2, dwellMs: 10_000 });
    player.play([labelled('A', drawn)]);
    pump(s, 16);
    expect(s.scheduled).toBe(2);

    // The other way a ceremony turn ends. play([]) is how the app says "there is nothing to
    // show now", and the early return for an empty playlist sits AFTER the stop() for
    // exactly this reason: skip the stop and the previous turn's chain re-arms forever with
    // its playlist still loaded, which is the same leak as a missing generation bump reached
    // through a different door.
    player.play([]);
    expect(player.currentIndex()).toBe(0);
    const scheduledAtStop = s.scheduled;

    pump(s, 32);
    pump(s, 48);
    expect(s.scheduled).toBe(scheduledAtStop);
    expect(s.pending).toHaveLength(0);
  });

  it('clears the playlist, so the status line stops naming a stream', () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 2, dwellMs: 1_000 });
    player.play([labelled('A', drawn), labelled('B', drawn)]);

    // 1-based, because it is rendered as "1 of 2" next to the code.
    expect(player.currentIndex()).toBe(1);

    player.stop();
    // Nothing is on screen, and the status line has to agree with that.
    expect(player.currentIndex()).toBe(0);
  });

  it('hands the wake lock back, so the screen can sleep once the code is down', async () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 2, dwellMs: 10_000 });

    // The third obligation of stop(), and the one with no on-screen consequence at all: a
    // lock that is never released is a phone that never sleeps, which is exactly the
    // complaint the wake lock was added to prevent, pointed the other way.
    player.play([labelled('A', drawn)]);
    await flush();
    expect(wake.requests).toBe(1);
    expect(wake.releases).toBe(0);

    player.stop();
    await flush();
    expect(wake.releases).toBe(1);

    // And the sentinel is dropped as it is handed back. Holding on to a released lock means
    // the next stop() releases it a second time, which is a promise rejection swallowed by
    // a catch that exists for a different reason.
    player.stop();
    await flush();
    expect(wake.releases).toBe(1);
  });

  it('CHARACTERIZATION: a stop() in the same tick as play() leaks the wake lock', async () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 2, dwellMs: 10_000 });

    // play() fires the wake lock request and deliberately does not wait for it, so a stop()
    // in the same tick runs releaseWakeLock() while this.wakeLock is still undefined and
    // releases nothing. The sentinel arrives a microtask later and is stored with nobody
    // left to hand it back.
    //
    // I BELIEVE THIS IS WRONG: a device that showed a code for one tick keeps its screen
    // awake until something calls stop() a second time, and the ceremony's own teardown
    // calls it once. It is pinned as it behaves TODAY rather than left uncovered, so that
    // fixing it (an acquire that checks the generation it was started in before storing the
    // sentinel, the same way the frame callbacks do) is a deliberate edit to this test and
    // not a silent change of behaviour.
    player.play([labelled('A', drawn)]);
    player.stop();
    await flush();

    expect(wake.requests).toBe(1);
    expect(wake.releases).toBe(0);
  });

  it('starts a second turn from the beginning of the new playlist', () => {
    const s = newSched();
    stubRaf(s);
    const first: string[] = [];
    const second: string[] = [];
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 2, dwellMs: 1_000 });
    player.play([labelled('A', first), labelled('B', first)]);
    pump(s, 16);
    pump(s, 1_016);
    pump(s, 1_032);
    // The first turn got as far as rotating, so index, the tick counter and the dwell clock
    // have all moved off their starting values.
    expect(first).toEqual(['A0', 'B0']);

    // A ceremony turn ends and another begins on the same player. Every one of those three
    // has to be put back: an index that survives opens the turn on the SECOND payload, a
    // dwell clock that survives has already expired, and a tick counter that survives
    // advances the seq before the first frame has been held long enough to capture.
    player.play([labelled('C', second), labelled('D', second)]);
    expect(second).toEqual(['C0']);
    expect(player.currentIndex()).toBe(1);

    pump(s, 2_048);
    expect(player.currentIndex()).toBe(1);
    expect(second).toEqual(['C0']);
  });

  it('starts the dwell at the first frame, not at the page load', () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 2, dwellMs: 1_000 });
    player.play([labelled('A', drawn), labelled('B', drawn)]);

    // requestAnimationFrame hands out a page-lifetime timestamp, so a ceremony started on a
    // page that has been open for a while sees a `now` far past the dwell on its very first
    // frame. The dwell has to be measured from that first frame. Measured from zero instead,
    // the first payload is replaced after a single refresh and the receiver never sees
    // enough of it to lock on, and the symptom only appears on the second ceremony of a
    // session, which is the last place anyone looks.
    pump(s, 30_000);
    expect(drawn).toEqual(['A0']);
    expect(player.currentIndex()).toBe(1);

    // Negative control: the clock it just started really does run.
    pump(s, 31_000);
    expect(player.currentIndex()).toBe(2);
  });

  it('holds a frame for two refreshes even when asked for one, then advances the seq', () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    // Asked for one. Two refreshes is the floor a capture at 30 fps needs to avoid reading a
    // torn symbol, and the constructor is where that floor is enforced.
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 1, dwellMs: 10_000 });
    player.play([labelled('A', drawn)]);
    expect(drawn).toEqual(['A0']);

    pump(s, 16);
    expect(drawn).toEqual(['A0']);

    // And it does advance, rather than being held forever: a repeated seq is a stream the
    // fountain can never complete, which is a ceremony that hangs on a full-looking screen.
    pump(s, 32);
    expect(drawn).toEqual(['A0', 'A1']);

    // The hold applies to EVERY frame, not only the first. A refresh counter that is not
    // put back to zero advances on every refresh from here on, which is the torn capture
    // the hold exists to prevent, arrived at one frame later than anyone would look.
    pump(s, 48);
    expect(drawn).toEqual(['A0', 'A1']);
    pump(s, 64);
    expect(drawn).toEqual(['A0', 'A1', 'A2']);
  });

  it('rotates to the next payload after the dwell, then holds the new one', () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 2, dwellMs: 1_000 });
    player.play([labelled('A', drawn), labelled('B', drawn)]);
    expect(drawn).toEqual(['A0']);

    // The first callback is what fixes the start of the dwell, so the second is a full
    // dwell later.
    pump(s, 16);
    pump(s, 1_016);
    expect(drawn).toEqual(['A0', 'B0']);
    expect(player.currentIndex()).toBe(2);

    // One refresh later, nowhere near another dwell. A player that rotates on every frame
    // from here on is one the receiver can never lock onto, and it looks fine on screen.
    pump(s, 1_032);
    expect(player.currentIndex()).toBe(2);
    expect(drawn).toEqual(['A0', 'B0']);
  });

  it('does not rotate a single stream with itself', () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    const player = new QrPlayer(fakeCanvas(), { holdRefreshes: 2, dwellMs: 1_000 });
    player.play([labelled('A', drawn)]);
    pump(s, 16);
    pump(s, 32);
    expect(drawn).toEqual(['A0', 'A1']);

    // The dwell is about taking turns, and one payload has nobody to take turns with. A
    // player that rotates a single stream with itself repaints the frame already on screen
    // and puts the hold counter back to zero, so the seq stops advancing on schedule and
    // the fountain runs slower than the pacing comment says it does.
    pump(s, 1_032);
    expect(drawn).toEqual(['A0', 'A1']);

    // Negative control: the seq does still advance, one hold later.
    pump(s, 1_048);
    expect(drawn).toEqual(['A0', 'A1', 'A2']);
  });

  it('sizes the canvas to the symbol it is painting, and paints it at the origin', () => {
    const s = newSched();
    stubRaf(s);
    const drawn: string[] = [];
    const canvas = fakeCanvas();
    // Prior state, so "the canvas is the right size" cannot be satisfied by a canvas that
    // was never written to and happened to agree.
    expect(canvas.width).toBe(0);
    expect(canvas.height).toBe(0);
    const player = new QrPlayer(canvas, { holdRefreshes: 2, dwellMs: 10_000 });

    player.play([labelled('A', drawn)]);
    expect(lastImage).toBeDefined();
    const image = lastImage as ImageData;
    // One canvas pixel per QR module, plus the quiet zone on both sides.
    expect(image.width).toBeGreaterThan(QUIET_MODULES * 2);

    // The canvas has to be resized to the raster before the raster is put on it. It is not
    // resized, the ceremony shows a cropped symbol or, at the starting width of zero,
    // nothing at all, while the frame counter ticks up exactly as it does when it works.
    expect(canvas.width).toBe(image.width);
    expect(canvas.height).toBe(image.height);
    // At the origin: an offset raster loses a module column off the far edge, and the quiet
    // zone is the first thing a decoder needs.
    expect(lastImageAt).toEqual({ dx: 0, dy: 0 });
  });
});

describe('the camera scanner ends its own loop', () => {
  let camera: FakeCamera;
  let capture: FakeCapture;
  let realGetContext: unknown;

  beforeEach(() => {
    realGetContext = (window.HTMLCanvasElement.prototype as unknown as Record<string, unknown>)
      .getContext;
    capture = installCanvasContext();
    camera = installFakeCamera();
  });

  afterEach(() => {
    (window.HTMLCanvasElement.prototype as unknown as Record<string, unknown>).getContext =
      realGetContext;
    restoreGlobal(navigator, 'mediaDevices');
  });

  it('stops SCHEDULING, which the submitted-frame counter cannot see', async () => {
    const s = newSched();
    const scanner = new OpticalScanner({
      video: fakeVideo(s, true),
      onPayload: () => undefined,
      createWorker: fakeWorker,
      poolSize: 1,
    });

    await scanner.start();
    expect(camera.opened).toBe(1);
    expect(s.scheduled).toBe(1);
    pump(s);
    pump(s);
    expect(submitted).toBeGreaterThan(0);
    expect(s.scheduled).toBe(3);

    scanner.stop();
    // Positive control: the track really was released, so this is a stopped scanner and not
    // one that never opened.
    expect(camera.stops).toBe(1);
    const scheduledAtStop = s.scheduled;
    const submittedAtStop = submitted;

    pump(s);
    pump(s);

    // Same shape as the player: the WORK counter is blind here, because stop() drops the
    // pool and captureOnce() returns before it submits anything.
    expect(submitted).toBe(submittedAtStop);
    expect(s.scheduled).toBe(scheduledAtStop);
    expect(s.pending).toHaveLength(0);
  });

  it('runs and stops the same way on a browser with no requestVideoFrameCallback', async () => {
    const s = newSched();
    stubRaf(s);
    const scanner = new OpticalScanner({
      video: fakeVideo(s, false),
      onPayload: () => undefined,
      createWorker: fakeWorker,
      poolSize: 1,
    });

    // The fallback branch. Losing it means a camera that is on, a preview that moves, and
    // exactly one frame ever decoded, which reads as a ceremony that will not complete.
    await scanner.start();
    expect(s.scheduled).toBe(1);
    pump(s);
    pump(s);
    expect(submitted).toBeGreaterThan(0);
    expect(s.scheduled).toBe(3);

    scanner.stop();
    const scheduledAtStop = s.scheduled;
    const submittedAtStop = submitted;

    pump(s);
    pump(s);
    expect(submitted).toBe(submittedAtStop);
    expect(s.scheduled).toBe(scheduledAtStop);
    expect(s.pending).toHaveLength(0);
  });

  it('leaves ONE capture loop running when start() is called twice', async () => {
    const s = newSched();
    const scanner = new OpticalScanner({
      video: fakeVideo(s, true),
      onPayload: () => undefined,
      createWorker: fakeWorker,
      poolSize: 1,
    });

    await scanner.start();
    await scanner.start();
    expect(camera.opened).toBe(2);

    // Each loop is born in a generation of its own, so the older one returns the first time
    // it is called and the newer one carries on: the same mechanism as stop(), used to
    // retire a loop rather than to end one. Born in the SAME generation, both loops survive
    // every check either of them makes, the camera is decoded at twice the rate for as long
    // as the page lives, and it presents as a fast camera rather than as a fault.
    pump(s);
    expect(s.scheduled).toBe(3);
  });

  it('leaves the camera OFF when stop() lands while the prompt is still open', async () => {
    const s = newSched();
    const video = fakeVideo(s, true);
    const plays = countPlays(video);
    const scanner = new OpticalScanner({
      video,
      onPayload: () => undefined,
      createWorker: fakeWorker,
      poolSize: 1,
    });

    // start() awaits a permission prompt, so a lock, a back button or a cancelled ceremony
    // can land while the camera is still opening. The stream arrives AFTER the scanner was
    // told to stop, and one line hands it straight back before anything else touches it.
    // Without that line the camera light comes on for a screen that is already gone, which
    // is the failure a user can see from across the room.
    const opening = scanner.start();
    scanner.stop();
    const outcome = await settle(opening);

    expect(camera.opened).toBe(1);
    // The stream is refused where it arrives, not later: the guard after the preview starts
    // reaches the same end state, so the count of preview starts is the only thing that can
    // tell the two apart, and a preview attached to a live camera on a screen the user has
    // already left is the whole point of refusing early.
    expect(plays.count).toBe(0);
    expect(camera.stops).toBe(1);
    expect(s.scheduled).toBe(0);
    expect(outcome).toBeInstanceOf(CameraFailure);
  });

  it('leaves the camera OFF when stop() lands while the preview is still starting', async () => {
    const s = newSched();
    const video = fakeVideo(s, true);
    const startPreview = deferredPlay(video);
    const scanner = new OpticalScanner({
      video,
      onPayload: () => undefined,
      createWorker: fakeWorker,
      poolSize: 1,
    });

    // The second window of the same shape: the camera is open and the preview element is
    // still starting. A capture loop armed here runs against a scanner that was already
    // stopped, and the generation it is born in is the CURRENT one, so nothing later ends
    // it: this one leaks a loop, not just a track.
    const opening = scanner.start();
    await flush();
    scanner.stop();
    startPreview();
    const outcome = await settle(opening);

    expect(camera.stops).toBe(1);
    expect(s.scheduled).toBe(0);
    expect(outcome).toBeInstanceOf(CameraFailure);
  });

  it('hands the camera back when the screen behind it fails', async () => {
    const s = newSched();
    const scanner = new OpticalScanner({
      video: fakeVideo(s, true),
      onPayload: () => undefined,
      createWorker: fakeWorker,
      poolSize: 1,
    });

    // A stream that opened and then turned out to be unusable. Every failure after the
    // camera opened leaves through one catch, and that catch is the only thing that stops
    // the track: a scan that failed loudly on screen while the camera light stayed on is
    // worse than one that failed quietly.
    camera.videoTracks = [];
    const outcome = await settle(scanner.start());

    expect(camera.opened).toBe(1);
    expect(camera.stops).toBe(1);
    expect(outcome).toBeInstanceOf(CameraFailure);
  });

  it('releases the decode workers and the preview element on stop', async () => {
    const s = newSched();
    const video = fakeVideo(s, true);
    const scanner = new OpticalScanner({
      video,
      onPayload: () => undefined,
      createWorker: fakeWorker,
      poolSize: 2,
    });

    await scanner.start();
    // Prior state, so each assertion below is about a change and not about a value that was
    // already there.
    expect(terminated).toBe(0);
    expect(video.srcObject).not.toBeNull();
    expect(video.paused).toBe(false);

    scanner.stop();
    // Each decode worker holds its own wasm instance, so a pool that is never resized to
    // zero is megabytes held per scan, with no on-screen symptom until the tab is killed.
    expect(terminated).toBe(2);
    // And the preview element keeps the dead stream attached, and keeps thinking it is
    // playing, until it is told otherwise.
    expect(video.srcObject).toBeNull();
    expect(video.paused).toBe(true);
  });

  it('scales a capture down to the cap and never scales one up', async () => {
    const big = newSched();
    const large = new OpticalScanner({
      video: fakeVideo(big, true, 1920, 1080),
      onPayload: () => undefined,
      createWorker: fakeWorker,
      poolSize: 1,
    });
    await large.start();
    pump(big);

    // getImageData is the entire per-frame budget, so a 1080p frame is scaled to the capture
    // cap before it is read back, with the aspect ratio intact: scaling by the SHORT edge
    // instead leaves the long edge over the cap, which is the whole budget spent on pixels
    // no decoder asked for.
    expect(capture.frames[0]).toEqual({ w: 960, h: 540 });
    // The canvas it is read out of has to be resized to match, or the read is of a region
    // that was never drawn.
    expect(capture.canvas?.width).toBe(960);
    expect(capture.canvas?.height).toBe(540);
    large.stop();

    const small = newSched();
    const modest = new OpticalScanner({
      video: fakeVideo(small, true, 320, 240),
      onPayload: () => undefined,
      createWorker: fakeWorker,
      poolSize: 1,
    });
    await modest.start();
    pump(small);

    // A cap is a ceiling, not a target. Upscaling a small frame to it costs the same budget
    // and adds no modules to read.
    expect(capture.frames[1]).toEqual({ w: 320, h: 240 });
    modest.stop();
  });

  it('submits nothing until the camera reports a frame size', async () => {
    const s = newSched();
    const scanner = new OpticalScanner({
      video: fakeVideo(s, true, 0, 0),
      onPayload: () => undefined,
      createWorker: fakeWorker,
      poolSize: 1,
    });

    await scanner.start();
    pump(s);
    pump(s);

    // A camera that has not delivered a frame yet reports a zero size. Without the guard
    // the scale is Infinity, every early refresh reads back a 1x1 image, and each one
    // occupies a decode worker to say nothing.
    expect(capture.frames).toHaveLength(0);
    expect(submitted).toBe(0);
    // Positive control: the loop IS running. It is the capture that declines, not the
    // scheduler that never started.
    expect(s.scheduled).toBe(3);
  });
});
