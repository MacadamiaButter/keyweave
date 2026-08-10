// @vitest-environment happy-dom
// The wire between a rendered control and the decision it takes.
//
// ceremony.test.ts already drives the state machine: confirmMismatch refuses, confirmMatch
// pins and persists, a refusal is terminal. None of that says WHICH BUTTON reaches which
// method, and that gap is not theoretical. Swapping the two selectors in renderCompare, so
// that "They do not match" pins the contact and "The words match" refuses, passed the whole
// suite: 424 of 424 green, typechecking clean. Keyweave's premise is that six differing
// words mean somebody may be sitting between the two devices and NOTHING is pinned, so the
// wire from that button to the refusal is the product, not plumbing. Everything below
// therefore CLICKS a real button on a real screen: no source regex, and no private call
// standing in for a listener.
//
// The screens are cloned from index.html's own templates into happy-dom, so a renamed
// data-role or a template that lost a button fails here the way it would in a browser.
//
// ONE NARROW CAST, and it is deliberate. The optical half cannot run in this environment:
// the show screen needs a canvas 2D context and the scan screen needs a camera. So the
// ceremony is driven to `compare` exactly the way ceremony.test.ts drives it, with two real
// sessions and real fountain frames passed between them, and is then INSTALLED on the app
// through a cast before the render path is entered. Everything after that point is the real
// renderer, the real listeners, the real ceremony and the real vault underneath.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { toHex } from '../src/bytes.js';
import { ARGON2_FLOOR, decryptVaultBlob } from '../src/vault.js';
import { OpticalReceiver, type CardFrameStream } from '../src/optical.js';
import { OWN_CARD_SERIAL, PairingSession } from '../src/pairing-session.js';
import { RelayClient } from '../src/relay-client.js';
import { KeyweaveApp } from '../src/ui/app.js';
import { PairingCeremony } from '../src/ui/ceremony.js';
import {
  REFUSAL_CANCELLED,
  REFUSAL_MISMATCH,
  STEP_COPY,
  SUPERSEDE_NOTICE,
} from '../src/ui/copy.js';
import { KeyweaveSession } from '../src/ui/session.js';
import { MemoryBlobStore } from '../src/ui/storage.js';
import { LocalVaultCrypto } from '../src/ui/vault-crypto.js';

// `__dirname`, not import.meta.url: under the happy-dom environment the module URL is not
// a file URL, and fileURLToPath refuses it.
const CLIENT_DIR = join(__dirname, '..');
const PASSPHRASE = 'seven unrelated words make a passable line here';
// Animation frames to let pass when measuring whether the display loop is alive. QrPlayer
// repaints every HOLD_REFRESHES ticks, so this is several repaints wide either way.
const FRAME_WINDOW = 24;

// ---- the two devices, exactly as ceremony.test.ts builds them ---------------
//
// Reused rather than reinvented: this file's subject is the screens, and a second, subtly
// different way of reaching the words would put the difference between the two fixtures
// into every failure here. Argon2id runs at ARGON2_FLOOR for speed alone.

interface Party {
  crypto: LocalVaultCrypto;
  store: MemoryBlobStore;
  session: KeyweaveSession;
}

async function makeParty(): Promise<Party> {
  const crypto = new LocalVaultCrypto(ARGON2_FLOOR);
  const store = new MemoryBlobStore();
  // idleMs 0 leaves no timer behind: the idle re-lock is a different file's subject, and a
  // live timer under a screen test would fire mid assertion.
  const session = await KeyweaveSession.createIdentity(crypto, store, PASSPHRASE, { idleMs: 0 });
  return { crypto, store, session };
}

function readStream(stream: CardFrameStream): Uint8Array {
  const rx = new OpticalReceiver();
  for (let seq = 0; seq < 400; seq++) {
    const status = rx.feed(stream.frame(seq));
    if (status.kind === 'complete') return status.payload;
  }
  throw new Error('test: the stream never completed');
}

/** Point one device camera at the other screen for the whole of what it is showing. */
async function deliver(from: PairingCeremony, to: PairingCeremony): Promise<void> {
  for (const stream of from.view().playlist) await to.offer(readStream(stream));
}

async function beginPair(
  a: Party,
  b: Party,
  serialB: number = OWN_CARD_SERIAL,
): Promise<{ cerA: PairingCeremony; cerB: PairingCeremony }> {
  const psA = await PairingSession.begin(a.session.keys());
  const psB = await PairingSession.begin(b.session.keys(), serialB);
  return {
    cerA: PairingCeremony.begin(psA, a.session, 'show-first'),
    cerB: PairingCeremony.begin(psB, b.session, 'scan-first'),
  };
}

async function runToCompare(
  a: Party,
  b: Party,
  serialB: number = OWN_CARD_SERIAL,
): Promise<{ cerA: PairingCeremony; cerB: PairingCeremony }> {
  const { cerA, cerB } = await beginPair(a, b, serialB);
  await deliver(cerA, cerB); // turn 1: A shows card and nonce
  cerA.handOff();
  await deliver(cerB, cerA); // turn 2: B shows card, nonce, proof
  cerB.handOff();
  await deliver(cerA, cerB); // turn 3: A shows its proof
  cerA.handOff();
  return { cerA, cerB };
}

// ---- the page ---------------------------------------------------------------

/**
 * index.html's own body, templates and all. Nothing here is a hand-written fixture: a
 * template that lost a data-role fails in this file rather than on somebody's phone.
 *
 * The module entry is dropped on the way in. happy-dom will not fetch it and says so on
 * stderr for every screen this file renders, and main.ts is the one part of the UI that is
 * not under test here: these tests construct the app themselves.
 */
function loadShell(): void {
  const html = readFileSync(join(CLIENT_DIR, 'index.html'), 'utf8');
  const body = /<body[^>]*>([\s\S]*)<\/body>/.exec(html);
  if (!body) throw new Error('no <body> in index.html');
  document.body.innerHTML = body[1]!.replace(/<script[\s\S]*?<\/script>/g, '');
}

/**
 * happy-dom has no 2D canvas context and QrPlayer refuses to construct without one, so the
 * show screen cannot be rendered at all without this. What the player paints is qr-display's
 * subject and optical.test.ts's; what is under test here is the button beside it. It is
 * installed by the one test that renders that screen rather than in a hook, so every other
 * screen in this file runs against unmodified happy-dom.
 *
 * The handle it returns COUNTS frames. Only the player paints, so a count that goes on
 * climbing after the ceremony has ended is a player that nobody stopped, which is the one
 * thing about the optical half this environment can still observe.
 */
function stubCanvasContext(): { painted: number } {
  const handle = { painted: 0 };
  const canvas = window.HTMLCanvasElement.prototype as unknown as {
    getContext(): unknown;
  };
  canvas.getContext = () => ({
    putImageData: () => {
      handle.painted++;
    },
  });
  return handle;
}

/** Let the display loop run: QrPlayer schedules itself with requestAnimationFrame. */
async function frames(count: number): Promise<void> {
  for (let i = 0; i < count; i++) {
    await new Promise((resolve) => requestAnimationFrame(() => resolve(undefined)));
  }
}

/**
 * The relay is never reached from any screen in this file: pairing works with no network at
 * all, and these ceremonies reserve no drop box. A fetch that throws is the honest stand in,
 * because a call that did happen would fail loudly rather than quietly returning a fixture.
 */
function unreachableRelay(): RelayClient {
  return new RelayClient({
    baseUrl: 'https://relay.invalid/',
    fetch: async () => {
      throw new Error('test: no screen here may touch the relay');
    },
  });
}

/** The private surface this file installs into. See the header for why. */
interface AppInternals {
  session: KeyweaveSession | undefined;
  ceremony: PairingCeremony | undefined;
  renderCeremony(): void;
}

function mount(party: Party, ceremony: PairingCeremony): void {
  loadShell();
  // The app reads its chrome elements in field initialisers, so the document has to exist
  // before this line, not merely before the import.
  const app = new KeyweaveApp({
    crypto: party.crypto,
    store: party.store,
    relay: unreachableRelay(),
  });
  const internals = app as unknown as AppInternals;
  internals.session = party.session;
  internals.ceremony = ceremony;
  internals.renderCeremony();
}

function click(name: string): void {
  const button = document.querySelector<HTMLButtonElement>(`#screens [data-role="${name}"]`);
  if (!button) throw new Error(`no [data-role="${name}"] button on the screen`);
  button.click();
}

/**
 * The text in a slot, or '' when the current screen has no such slot. Deliberately total:
 * a mutation that lands on the WRONG SCREEN should be caught by the sentence it printed,
 * not by a null dereference inside this helper.
 */
function slot(name: string): string {
  return document.querySelector(`#screens [data-role="${name}"]`)?.textContent ?? '';
}

function heading(): string {
  return document.querySelector('#screens h1')?.textContent ?? '';
}

/**
 * What a screen reader is told. #live is the polite live region in index.html's shell,
 * OUTSIDE #screens, so it survives the replaceChildren that swaps a screen: what it holds
 * after a render is what the app decided to say about that render. Total for the same
 * reason `slot` is: a shell that lost the region should fail on the sentence, not on a
 * null dereference in here.
 */
function live(): string {
  return document.getElementById('live')?.textContent ?? '';
}

function words(): string[] {
  return [...document.querySelectorAll('#screens [data-role="words"] li')].map(
    (li) => li.textContent ?? '',
  );
}

/**
 * Wait for the verdict to land on a screen.
 *
 * The mismatch path is synchronous and the match path is not: confirmMatch awaits a
 * re-classification, a seal and a write before it renders anything. Polling for the words to
 * leave the page, rather than sleeping a fixed number of milliseconds, is what keeps BOTH
 * arms observable under a mutation: a build that takes the other path still arrives here and
 * is then caught by the assertions rather than by a race.
 */
async function verdictLands(): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt++) {
    if (document.querySelector('#screens [data-role="words"]') === null) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('the compare screen never changed');
}

describe('the verdict buttons are wired to the verdicts', () => {
  it('pressing "They do not match" refuses by name, and pins nothing', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await runToCompare(a, b);
    mount(a, cerA);
    // The screen under test is the compare screen, with the six words on it.
    expect(words()).toHaveLength(6);
    const savesBefore = a.store.saveCount;

    click('mismatch');
    await verdictLands();

    // THE LOAD-BEARING HALF, and it is asserted BEFORE the screen on purpose: a run stops at
    // its first failed expectation, and a refusal screen over a pinned contact is the failure
    // this file exists for, so that is the sentence a broken build should print. The store is
    // asked directly and then the blob is reopened from scratch, because an in-memory check
    // alone stays green while a pin sits in the vault waiting for the next save to carry it,
    // and a saveCount check alone stays green while a pin sits in memory.
    expect(a.session.contacts.size()).toBe(0);
    expect(a.session.contacts.isPinned(b.session.identityPublicKey())).toBe(false);
    expect(a.store.saveCount).toBe(savesBefore);
    expect(decryptVaultBlob((await a.store.load())!, PASSPHRASE).contacts).toHaveLength(0);

    // And the screen names THIS refusal, rather than one of the other seven in copy.ts.
    expect(heading()).toBe(REFUSAL_MISMATCH.title);
  });

  it('pressing "The words match" takes the same state to the paired screen, and does pin', async () => {
    // The positive control for the test above. Without it, a build where BOTH buttons refuse
    // would pass the mismatch test and ship a product that can never pair.
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await runToCompare(a, b);
    mount(a, cerA);
    expect(words()).toHaveLength(6);
    const savesBefore = a.store.saveCount;

    click('match');
    await verdictLands();

    expect(heading()).toBe('Paired');
    expect(slot('identity')).toBe(toHex(b.session.identityPublicKey()));
    expect(a.session.contacts.isPinned(b.session.identityPublicKey())).toBe(true);
    expect(a.store.saveCount).toBe(savesBefore + 1);
    expect(decryptVaultBlob((await a.store.load())!, PASSPHRASE).contacts).toHaveLength(1);
  });
});

describe('the compare screen', () => {
  it('renders the six safety words the machine derived, in order', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA, cerB } = await runToCompare(a, b);
    mount(a, cerA);

    // Against the OTHER device's list as well as this one's, because the thing two people
    // do with this screen is read it against the other screen. Six is the fixed length the
    // safety number is defined at; a screen showing five of them is a screen showing a
    // different comparison from the one the ceremony decided.
    expect(words()).toEqual([...cerA.view().words]);
    expect(words()).toEqual([...cerB.view().words]);
    expect(words()).toHaveLength(6);
  });

  it('carries the R1 trust banner and the turn counter, and drops both once pairing ends', async () => {
    // R1: the app is a web page, so the server that served it can fake both screens. The one
    // sentence that says so has to be visible on the screen where somebody is about to make
    // the trust decision, which is this one. A confirmed defeat of the old text-only test was
    // flipping renderCompare's setChrome to false: the banner vanished from exactly the
    // screen it is load-bearing on, and the assertion stayed green.
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await runToCompare(a, b);
    mount(a, cerA);

    const banner = document.getElementById('tcb')!;
    const steps = document.getElementById('steps')!;
    expect(banner.hidden).toBe(false);
    expect(banner.textContent).toMatch(/tampered copy of this app could show both of you/);
    expect(steps.hidden).toBe(false);
    expect(steps.textContent).toBe('Turn 3 of 3');

    // Negative control: the chrome is not simply always on. A banner that never hides would
    // satisfy the assertion above while saying nothing about when it appears.
    click('match');
    await verdictLands();
    expect(banner.hidden).toBe(true);
    expect(steps.hidden).toBe(true);
  });

  it('shows the supersede notice only when the pin is about to move', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const notice = () => document.querySelector<HTMLElement>('#screens [data-role="supersede"]')!;

    // An ordinary first pairing replaces nothing, so the warning is not on the screen.
    const first = await runToCompare(a, b, 1);
    mount(a, first.cerA);
    expect(notice().hidden).toBe(true);
    expect(notice().textContent).toBe('');
    click('match');
    await verdictLands();

    // Same identity, higher serial. contacts.ts calls that a supersession and demands a
    // fresh in-person ceremony, which is what this second run is, and the screen has to say
    // that the pin is being replaced BEFORE the words are compared.
    const second = await runToCompare(a, b, 2);
    expect(second.cerA.view().supersede).toBe(true);
    mount(a, second.cerA);
    expect(notice().hidden).toBe(false);
    expect(notice().textContent).toBe(SUPERSEDE_NOTICE);
    // Independent of the constant this file imports, because the line above compares the
    // rendered text against the very string the renderer read: both sides move together, so
    // emptying SUPERSEDE_NOTICE in copy.ts leaves a blank warning box under a green
    // assertion. `SUPERSEDE_NOTICE` is read in exactly two places in the repo, app.ts and
    // here, so nothing else would catch it either. What the sentence has to CARRY is that a
    // key is already pinned and that agreeing here throws it away.
    expect(notice().textContent).toMatch(/already pinned/);
    expect(notice().textContent).toMatch(/replaces the old one/);
  });
});

describe('the refusal screen', () => {
  it('prints what happened, what it means and what to do, from the copy object', async () => {
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await runToCompare(a, b);
    mount(a, cerA);

    click('mismatch');
    await verdictLands();

    expect(slot('title')).toBe(REFUSAL_MISMATCH.title);
    expect(slot('detail')).toBe(REFUSAL_MISMATCH.detail);
    expect(slot('advice')).toBe(REFUSAL_MISMATCH.advice);
    // The three parts are three DIFFERENT sentences. A screen that printed one of them twice
    // looks filled in and has quietly dropped either the diagnosis or the instruction.
    expect(slot('detail')).not.toBe(slot('advice'));

    // And what the middle paragraph CARRIES, independent of the constant it was read from.
    // The three assertions above compare the rendered text against the very object the
    // renderer read, so both sides move together: emptying REFUSAL_MISMATCH.detail in
    // copy.ts leaves a blank paragraph under three green assertions. Measured, not
    // supposed: that edit typechecks and passes the six app tests, ceremony.test.ts and
    // public-hygiene, 127 of 127. ceremony.test.ts pins the title and the advice this way
    // already; the diagnosis is the one part nothing pinned, and it is the part that says
    // what a mismatch MEANS, which is the whole reason a person is being asked to stop.
    expect(slot('detail')).toMatch(/relaying between you/);
    expect(slot('detail')).toMatch(/did not derive the same shared secret/);
  });

  it('says what happened in the live region, so it is not silent to a screen reader', async () => {
    // The refusal is what "the six words differ" looks like, which is the moment this
    // product exists for: somebody may be relaying between the two devices. A refusal that
    // repaints the page and writes nothing to the live region reaches a sighted person and
    // nobody else, at the single point where the app is asking for a decision.
    //
    // Nothing else in the suite reads #live on this path, and the two obvious edits were
    // both measured invisible: deleting `this.announce(refusal.title)` from renderRefusal
    // and changing its argument to `refusal.detail` each left this file green and
    // typechecked clean. ui-shell.test.ts asserts the source CONTAINS 'this.announce(',
    // which fourteen call sites satisfy between them, so losing one of them says nothing
    // there; the only other readers of the region, app-unlock.test.ts and
    // app-conversation.test.ts, sit on the unlock, ready and lock paths.
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await runToCompare(a, b);
    mount(a, cerA);

    // Positive control, read BEFORE the click for the same reason the chrome test reads
    // its pair early: an assertion about what the region holds after a refusal would also
    // be satisfied by a region that this ceremony had never written at all, and by a
    // refusal that merely inherited somebody else's sentence.
    expect(live()).toBe('Six words are on screen. Read them out loud and compare.');

    click('mismatch');
    await verdictLands();

    // What is read out is THIS refusal, by the name the screen gives it: not the sentence
    // the compare screen left behind, not one of the other two paragraphs on the screen,
    // and not one of the other seven refusals in copy.ts.
    expect(live()).toBe(REFUSAL_MISMATCH.title);

    // Written is not the same claim as SPOKEN, and the assertions above only prove written.
    // ui-shell.test.ts asks index.html whether the strings aria-live="polite" and
    // role="status" appear ANYWHERE in the file; it never asks whether they are on the
    // element announce() writes into, and it reads markup as text, so it cannot ask whether
    // that element is in the accessibility tree at all. Three mutants, all measured green
    // across this file, ui-shell, app-unlock and app-conversation and all typechecking:
    // adding `hidden` to #live, adding aria-hidden="true" to it, and splitting the two
    // attributes onto a sibling <p> so the file still contains both strings. Each one makes
    // every announcement in the product reach nobody. Same screen reader, one step along.
    const region = document.getElementById('live')!;
    expect(region.getAttribute('aria-live')).toBe('polite');
    expect(region.getAttribute('role')).toBe('status');
    expect(region.hidden).toBe(false);
    expect(region.getAttribute('aria-hidden')).toBe(null);
  });

  it('lands focus on the refusal heading, not on the screen it just replaced', async () => {
    // The other half of the same problem. The live region says the sentence once; focus is
    // what a screen reader and a keyboard READ FROM afterwards, and the compare screen's
    // buttons are gone, so focus that did not move is focus on nothing.
    //
    // The only guard on this today is ui-shell.test.ts, which asserts app.ts CONTAINS
    // "this.screens.querySelector('h1')?.focus()". Source text cannot say WHEN that line
    // runs: lift it above the replaceChildren immediately below it and it focuses the
    // screen being thrown away, which is green there and red here.
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await runToCompare(a, b);
    mount(a, cerA);
    // Control, and it is a second measurement of the same rule on the screen this one is
    // reached from: what the click has to produce is a MOVE, not a heading that had focus
    // all along.
    expect(document.activeElement).toBe(document.querySelector('#screens h1'));

    click('mismatch');
    await verdictLands();

    // Naming the screen first is what stops the line below from being satisfied by focus
    // sitting on some other screen's heading.
    expect(heading()).toBe(REFUSAL_MISMATCH.title);
    expect(document.activeElement).toBe(document.querySelector('#screens h1'));
  });

  it('drops the ceremony chrome it was reached with, rather than still reading Turn 3 of 3', async () => {
    // A refusal is the one screen whose whole job is to say the ceremony STOPPED. Reached
    // from the compare screen it inherits chrome that says the opposite: the R1 banner goes
    // on asking for a trust decision that is no longer on offer, and the counter reads the
    // last turn of three as though one were still in progress. The compare screen's own test
    // runs this control on the arm that PAIRS. The refusing arm is a different call in a
    // different method, and every other test here renders this screen without once looking
    // at the chrome, so deleting the reset leaves them all green.
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await runToCompare(a, b);
    mount(a, cerA);
    const banner = document.getElementById('tcb')!;
    const steps = document.getElementById('steps')!;
    // Read before the click, so the pair below cannot be satisfied by chrome that was never
    // raised in the first place.
    expect(banner.hidden).toBe(false);
    expect(steps.hidden).toBe(false);

    click('mismatch');
    await verdictLands();

    expect(heading()).toBe(REFUSAL_MISMATCH.title);
    expect(banner.hidden).toBe(true);
    expect(steps.hidden).toBe(true);
  });

  it('offers one control, and it goes back to Ready rather than into the ceremony', async () => {
    // Every refusal in this product is terminal. The screen enforces that by having nowhere
    // else to go: one button, and it lands on the screen a ceremony starts from.
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await runToCompare(a, b);
    mount(a, cerA);

    click('mismatch');
    await verdictLands();
    const controls = [...document.querySelectorAll<HTMLButtonElement>('#screens button')];
    expect(controls.map((button) => button.dataset.role)).toEqual(['again']);

    click('again');
    expect(heading()).toBe('Pair in person');
    // And there is no route back to the words from there.
    expect(words()).toEqual([]);
  });

  it('cancelling from the show screen refuses as cancelled, with nothing saved', async () => {
    // The escape hatch on the SHOW screen, which is the only ceremony screen this
    // environment can raise one on: the scan screen needs a camera, so its cancel button is
    // pinned nowhere and a listener that went dead there would fail nothing. This is the one
    // control a person reaches for when something looks wrong, so it has to end where a
    // refusal ends.
    const a = await makeParty();
    const b = await makeParty();
    const { cerA } = await beginPair(a, b);
    const display = stubCanvasContext();
    mount(a, cerA);
    expect(heading()).toBe(STEP_COPY.showCard.heading);
    const savesBefore = a.store.saveCount;

    // Positive control for the teardown assertion below: the display loop IS running on this
    // screen, so "no frames after the cancel" measures a STOP rather than a player that had
    // never started painting in the first place.
    const paintedWhileShowing = display.painted;
    await frames(FRAME_WINDOW);
    expect(display.painted).toBeGreaterThan(paintedWhileShowing);

    click('cancel');

    expect(slot('title')).toBe(REFUSAL_CANCELLED.title);
    expect(slot('advice')).toBe(REFUSAL_CANCELLED.advice);
    expect(a.store.saveCount).toBe(savesBefore);
    expect(a.session.contacts.size()).toBe(0);

    // And the optical half stopped with the ceremony: no frames after the refusal is up.
    // Stated honestly, this is a SECOND MEASUREMENT of a rule app-lock.test.ts already
    // walls on the lock path, not a hole. Deleting `this.player?.stop()` from
    // teardownOptics reds the line below (measured, 9 frames became 17) and reds
    // app-lock.test.ts:506 as well. What is here rather than there is the path: app-lock
    // arrives by the idle lock from the scan screen, this arrives by a person pressing
    // cancel, and the two reach teardownOptics through different callers. Deleting either
    // ONE of those callers is an equivalent mutant, because renderCeremony tears the optics
    // down before it dispatches and renderRefused does it again; that redundancy is why no
    // single-line deletion on this path is visible anywhere, here or in app-lock.
    const paintedAtRefusal = display.painted;
    await frames(FRAME_WINDOW);
    expect(display.painted).toBe(paintedAtRefusal);
  });
});
