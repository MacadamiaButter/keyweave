// @vitest-environment happy-dom
//
// The entry path, EXECUTED: start, renderUnlock, submitPassphrase, renderReady, and the
// camera copy switch. This is the screen every new person meets once and every returning
// person meets every time, and until this file existed none of it had ever run in the
// suite. Its only cover was ui-shell.test.ts reading app.ts as a string, and a measured
// pass over those assertions defeated 19 of 19 single-edit mutations, every one of them
// typechecking clean. A rule that is only read as text is only guarded as text.
//
// The screens come from the REAL index.html templates, so a renamed data-role or a deleted
// field fails here the same way it fails on the page.
//
// The idle re-lock is driven here as well as in app-lock.test.ts, and the split is not an
// accident: that file opens every one of its sessions through the FIRST-RUN screen, so the
// unlock call site is the one entry into the app that no other file executes. The lock is
// wired per call site, which means it can be wired in one and missing in the other.
//
// The crypto is FAKE on purpose. Argon2id at 256 MiB is about three seconds per call on the
// reference box, and none of this is a claim about the KDF: what is pinned is which screen
// appears, which strings it carries, and which calls it does and does not make.
// ceremony.test.ts drives the real LocalVaultCrypto.
//
// Four of the tests below read the screen MID-FLIGHT, while that derivation is still
// running, because for those four there is no other window: on success renderReady replaces
// the whole screen and on failure the error slot is re-shown with new text, so a screen that
// was set up and torn down again is indistinguishable from one that was never set up at all.
// The seam that parks the work is in the FAKE crypto and NOT in src/ (testseam, Feathers): a
// seam added to a test double costs nothing, and a seam added to a security-critical source
// file is the next finding.
//
// CHARACTERIZATION (Feathers, WELC), and what came of it. This file was written to pin what
// the code did TODAY, including one behaviour that was probably wrong: the internal error
// text rendered to the user verbatim. It was named as characterization in its own test
// title and deliberately not fixed here, so that the fix could land in its own commit; when
// it did, that test went RED and was rewritten in the same commit into the rule it now
// states. That is the whole return on pinning a suspected defect before touching it.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { KeyweaveApp, cameraMessage } from '../src/ui/app.js';
import { CAMERA_COPY, UNLOCK_COPY, lockNotice, unlockFailureMessage } from '../src/ui/copy.js';
import { MIN_PASSPHRASE_LENGTH, passphraseHint } from '../src/ui/passphrase.js';
import { IDLE_LOCK_MS } from '../src/ui/session.js';
import { MemoryBlobStore } from '../src/ui/storage.js';
import { RelayClient } from '../src/relay-client.js';
import { createSignedCard } from '../src/card.js';
import { generateKeyManager, keyManagerFromSeeds } from '../src/keys.js';
import { toHex } from '../src/bytes.js';
import type { VaultCrypto } from '../src/ui/vault-crypto.js';
import type { VaultData } from '../src/vault.js';

// __dirname, not import.meta.url: under the happy-dom environment `import.meta.url` is
// resolved against the document's http origin, and fileURLToPath refuses it outright.
const CLIENT_DIR = join(__dirname, '..');

/**
 * The page, from the file the browser is served. Only the body: the CSP meta tag is the
 * deploy gate's subject and not this file's.
 *
 * The module entry is dropped rather than left to be ignored. innerHTML never executes a
 * script, but happy-dom still tries to FETCH one and logs a DOMException per screen, which
 * is 20 stack traces of noise around the first real failure this file ever reports.
 */
function loadShell(): void {
  const html = readFileSync(join(CLIENT_DIR, 'index.html'), 'utf8');
  const body = /<body[^>]*>([\s\S]*)<\/body>/.exec(html);
  if (!body) throw new Error('no <body> in index.html');
  document.body.innerHTML = body[1]!.replace(/<script[\s\S]*?<\/script>/g, '');
}

// Fixed seeds, so the identity the ready screen prints is the same string every run and can
// be derived independently below rather than read back out of the code under test.
const IDENTITY_SEED = new Uint8Array(32).fill(0x11);
const ENCRYPTION_SEED = new Uint8Array(32).fill(0x22);

/** A stored blob is only ever a non-null marker here: the fake crypto never reads it. */
const STORED_BLOB = Uint8Array.from([0xa5, 0x5a, 0x01]);

function vaultData(contacts: Uint8Array[]): VaultData {
  return {
    // Fresh copies every call: Vault.lock() zeroizes these in place.
    identitySeed: Uint8Array.from(IDENTITY_SEED),
    encryptionSeed: Uint8Array.from(ENCRYPTION_SEED),
    contacts,
    highWater: [],
    seen: [],
    messages: [],
    mailboxes: [],
  };
}

/**
 * A VaultCrypto that records what it was asked to do and can be told to refuse. The
 * recording is the point of several tests below: "the screen refused before the crypto was
 * touched" is a claim about a call that did NOT happen, and nothing else can observe it.
 */
class RecordingCrypto implements VaultCrypto {
  readonly created: string[] = [];
  readonly unlocked: string[] = [];
  /** Contacts the opened vault comes back holding, as signed card wire bytes. */
  contacts: Uint8Array[] = [];
  /** When set, both entry points reject with it. */
  refuseWith: Error | undefined;
  /**
   * When set, both entry points PARK here after recording the call, which is the only way
   * to read the screen the app puts up WHILE it derives. The call is recorded before the
   * park so a test can wait for the work to have started rather than counting ticks.
   */
  gate: Promise<void> | undefined;

  async createIdentity(passphrase: string): Promise<{ blob: Uint8Array; data: VaultData }> {
    this.created.push(passphrase);
    if (this.gate) await this.gate;
    if (this.refuseWith) throw this.refuseWith;
    return { blob: STORED_BLOB, data: vaultData(this.contacts) };
  }

  async unlock(_blob: Uint8Array, passphrase: string): Promise<VaultData> {
    this.unlocked.push(passphrase);
    if (this.gate) await this.gate;
    if (this.refuseWith) throw this.refuseWith;
    return vaultData(this.contacts);
  }

  async seal(_data: VaultData): Promise<Uint8Array> {
    return STORED_BLOB;
  }

  forget(): void {}
}

/** Hold the fake crypto at its entry point, and hand back the release. */
function park(crypto: RecordingCrypto): () => void {
  let release = (): void => undefined;
  crypto.gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  return release;
}

/** Never reached on these screens; a call would be the finding, so it throws rather than stubs. */
function unreachableRelay(): RelayClient {
  return new RelayClient({
    baseUrl: 'https://relay.invalid/',
    fetch: async () => {
      throw new Error('test: the unlock and ready screens must not touch the relay');
    },
  });
}

interface Harness {
  app: KeyweaveApp;
  crypto: RecordingCrypto;
  store: MemoryBlobStore;
}

/**
 * A started app. `stored` decides which of the two unlock screens renders, because that is
 * the only thing start() consults.
 *
 * The DOM has to exist BEFORE the constructor runs: KeyweaveApp resolves #screens, #steps,
 * #tcb and #live in FIELD INITIALISERS, so a missing shell throws at `new`, not at start().
 */
async function boot(stored: boolean): Promise<Harness> {
  loadShell();
  const crypto = new RecordingCrypto();
  const store = new MemoryBlobStore();
  if (stored) {
    await store.save(STORED_BLOB);
    store.saveCount = 0;
  }
  const app = new KeyweaveApp({ crypto, store, relay: unreachableRelay() });
  await app.start();
  return { app, crypto, store };
}

function screens(): HTMLElement {
  return document.getElementById('screens')!;
}

/** The one element carrying this data-role on the screen that is currently up. */
function slot<T extends HTMLElement>(name: string): T {
  const found = screens().querySelector<T>(`[data-role="${name}"]`);
  if (!found) throw new Error(`test: no [data-role="${name}"] on the current screen`);
  return found;
}

function textOf(name: string): string {
  return slot(name).textContent ?? '';
}

/** What a screen reader was told. Everything user-visible on these paths also lands here. */
function announced(): string {
  return document.getElementById('live')!.textContent ?? '';
}

function field(id: string): HTMLInputElement {
  return screens().querySelector<HTMLInputElement>(`#${id}`)!;
}

/**
 * The real form event, not a call into a private method. Cancelable because the handler
 * calls preventDefault, and a non-cancelable event would make that a silent no-op. The
 * event is handed back so one test below can ask whether it was in fact cancelled.
 */
function submitForm(passphrase: string, confirmation = ''): Event {
  field('passphrase').value = passphrase;
  field('passphrase-confirm').value = confirmation;
  const event = new Event('submit', { bubbles: true, cancelable: true });
  slot<HTMLFormElement>('form').dispatchEvent(event);
  return event;
}

/**
 * submitPassphrase is invoked as `void this.submitPassphrase(...)`, so there is no promise
 * to await from out here and the two helpers below are how a test knows the screen has
 * finished changing.
 *
 * A real one millisecond delay rather than a zero one: opening the session awaits key
 * derivation, which finishes off the event loop, and a burst of zero-delay ticks can drain
 * faster than that work completes. A fixed number of ticks would then be a test that passes
 * on an idle box and fails on a busy one.
 */
const tick = () => new Promise((resolve) => setTimeout(resolve, 1));

async function waitFor(done: () => boolean, what: string): Promise<void> {
  for (let waited = 0; waited < 2_000; waited++) {
    if (done()) return;
    await tick();
  }
  throw new Error(`test: the screen never reached ${what}`);
}

const waitForReady = () =>
  waitFor(() => screens().querySelector('h1')?.textContent === 'Pair in person', 'the ready screen');

const waitForError = () =>
  waitFor(
    () => screens().querySelector<HTMLElement>('[data-role="error"]')?.hidden === false,
    'a visible error',
  );

/**
 * For the two paths where the assertion is that NOTHING further happened. There is no state
 * to wait for, so this waits out the time the refused work would have taken to start.
 */
async function settle(): Promise<void> {
  for (let index = 0; index < 40; index++) await tick();
}

/** shortHex's contract, spelled out rather than imported, so a change to it is visible here. */
function firstFourGroups(hex: string): string {
  return [hex.slice(0, 4), hex.slice(4, 8), hex.slice(8, 12), hex.slice(12, 16)].join(' ');
}

beforeEach(() => {
  document.body.innerHTML = '';
});

// One test below installs a fake clock, and every other test in this file waits on real
// setTimeout ticks. A leaked fake clock would not fail that test, it would hang the next one.
afterEach(() => {
  vi.useRealTimers();
});

describe('what is in the store decides which screen opens', () => {
  it('an empty store offers to create an identity, and asks for the passphrase twice', async () => {
    await boot(false);
    expect(textOf('title')).toBe('Create your Keyweave identity');
    // The sentence under the title is the fifth thing this screen decides from firstRun, and
    // the only one that says what is about to happen. Given the returning-user sentence, a
    // person who has no keys at all is told the keys are already on the device, wrapped with
    // a passphrase they have never chosen.
    expect(textOf('lede')).toBe(
      'Keyweave generates two keys on this device and wraps them with a passphrase you choose. Nothing is uploaded and there is no account.',
    );
    expect(textOf('submit')).toBe('Create identity');
    // The confirmation field is the whole reason first run is a different screen: there is
    // no recovery, so a typo in the only copy of the passphrase is the vault gone.
    expect(slot('confirm-field').hidden).toBe(false);
    expect(field('passphrase').autocomplete).toBe('new-password');
  });

  it('a stored blob offers to unlock, with no second field to fill in', async () => {
    await boot(true);
    expect(textOf('title')).toBe('Unlock Keyweave');
    // The other side of that same switch. A returning person told that Keyweave is about to
    // generate two keys has been told their vault is gone, on the one screen where the whole
    // remedy is to type the passphrase they already have.
    expect(textOf('lede')).toBe('Your keys are on this device, wrapped with your passphrase.');
    expect(textOf('submit')).toBe('Unlock');
    expect(slot('confirm-field').hidden).toBe(true);
    // A password manager is told which of the two it is looking at; 'new-password' on an
    // unlock screen is what makes one offer to generate a replacement for the only key.
    expect(field('passphrase').autocomplete).toBe('current-password');
  });

  it('opens with the notice, the error and the spinner all down', async () => {
    // The PRIOR state for three assertions further down this file, and the whole reason they
    // mean anything: each of those says a slot CHANGED, and each is satisfied just as well by
    // a template that shipped already in the changed state. Dropping `hidden` from any one of
    // these three in index.html leaves all six app.ts files green, and the attribute is the
    // only thing holding the spinner back, because styles.css gives .busy display:flex.
    await boot(true);
    expect(slot('notice').hidden).toBe(true);
    expect(slot('error').hidden).toBe(true);
    expect(slot('busy').hidden).toBe(true);
  });
});

describe('the hint under the passphrase field is wired to the screen it is on', () => {
  it('grades what has been typed on the create screen, and re-grades it on every keystroke', async () => {
    // The sixth thing this screen decides from firstRun, and the only one nothing in the
    // suite reads: ui-shell.test.ts executes passphraseHint the FUNCTION, which says nothing
    // about which branch this screen wires it into, and no test anywhere looks at
    // [data-role="hint"]. Inverted, the guard costs the create screen its meter entirely,
    // and the person choosing the one passphrase there is no recovery from is left with a
    // sentence about the vault they have not got yet.
    await boot(false);
    const blank = passphraseHint('');
    expect(textOf('hint')).toBe(`${blank.label}. ${blank.detail}`);

    // Both sides of that one come off passphraseHint, so a rewrite of the sentence moves
    // them together and the assertion follows it: changing the too-short label to `0/12
    // chars`, or the sentence after it to `Too short.`, leaves all six app.ts files green.
    // ui-shell.test.ts pins this branch's `acceptable` and `level` and never its words. So
    // the two things a person acts on are anchored to literals here: how far off they are,
    // and that the app is going to refuse rather than warn.
    expect(textOf('hint')).toContain(`0 of ${MIN_PASSPHRASE_LENGTH} characters.`);
    expect(textOf('hint')).toContain(
      `Keyweave will not create a vault under ${MIN_PASSPHRASE_LENGTH} characters.`,
    );

    // The listener, not only the first paint. A meter that never moves keeps telling
    // somebody who has just typed enough characters that they have not.
    const typed = 'correct horse battery staple extra';
    field('passphrase').value = typed;
    field('passphrase').dispatchEvent(new Event('input'));
    const graded = passphraseHint(typed);
    expect(textOf('hint')).toBe(`${graded.label}. ${graded.detail}`);
  });

  it('says nothing about strength on the unlock screen, where there is nothing to grade', async () => {
    // The other side of that same guard, and a separate test because it fails on its own.
    // An existing vault's passphrase is whatever it is: grading it here would tell a
    // returning person their own passphrase is too short, on the screen where the app is
    // about to accept it and where there is nothing they could change anyway.
    await boot(true);
    expect(textOf('hint')).toBe('Enter the passphrase you chose when you created this vault.');
  });

  it('CHARACTERIZATION, suspected wrong: the hint is not attached to the field it grades', async () => {
    // The hint carries id="passphrase-hint" and nothing references it: the input has no
    // aria-describedby, in index.html or anywhere in src/. So the meter is on the screen for
    // somebody who can see it and absent for somebody who cannot, on the one screen where the
    // string being chosen is the whole vault and there is no recovery from choosing it badly.
    //
    // Pinned as it stands, like the error-text characterization below. Wiring the attribute is
    // a one line change to index.html, and it should arrive as a deliberate edit to this test
    // rather than as a silent green.
    await boot(false);
    expect(slot('hint').id).toBe('passphrase-hint');
    expect(field('passphrase').getAttribute('aria-describedby')).toBeNull();
  });
});

describe('the submit event itself', () => {
  it('is cancelled, so pressing the button never navigates the page', async () => {
    // The form carries no method and no action, so an uncancelled submit is a GET back to
    // index.html with `?passphrase=` and the typed passphrase in the URL: in history, in the
    // referrer, and in the address bar, on a screen whose whole subject is that passphrase.
    // The single-page app it reloads over is gone with it, session and all. Nothing in the
    // suite has ever observed this call and deleting the line typechecks.
    await boot(true);
    const event = submitForm('the passphrase for this vault');
    expect(event.defaultPrevented).toBe(true);
    // Let the work that press started finish rather than leaving it in flight.
    await waitForReady();
  });
});

describe('creating an identity checks the passphrase before it costs anything', () => {
  it('a passphrase under the floor is refused without reaching the crypto', async () => {
    const { crypto, store } = await boot(false);
    submitForm('short', 'short');
    await settle();

    expect(textOf('error')).toBe(`Use at least ${MIN_PASSPHRASE_LENGTH} characters.`);
    expect(slot('error').hidden).toBe(false);
    expect(announced()).toBe(`Use at least ${MIN_PASSPHRASE_LENGTH} characters.`);
    // The load-bearing half: the refusal is a return, not a message printed on the way past.
    // Reaching the KDF would generate an identity and write it under a passphrase the app
    // had just told the person was too short.
    expect(crypto.created).toEqual([]);
    expect(store.saveCount).toBe(0);
    expect(textOf('title')).toBe('Create your Keyweave identity');
    // And the screen is still usable, which is the other half of what a refusal means. Both
    // the disable and the spinner sit BELOW these two checks and are never undone on the way
    // out of them, so hoisting either one above the checks typechecks, passes all six app.ts
    // files, and leaves a person a dead Create identity button and a spinner turning under a
    // sentence telling them to type a longer passphrase. A reload is the only way off it.
    expect(slot<HTMLButtonElement>('submit').disabled).toBe(false);
    expect(slot('busy').hidden).toBe(true);
  });

  it('a passphrase that does not match its confirmation is refused without reaching the crypto', async () => {
    const { crypto, store } = await boot(false);
    submitForm('several unrelated words here', 'several unrelated words heer');
    await settle();

    expect(textOf('error')).toBe('The two passphrases are different.');
    expect(slot('error').hidden).toBe(false);
    expect(crypto.created).toEqual([]);
    expect(store.saveCount).toBe(0);
    // Driven again rather than left to the test above, because this is a second `return` out
    // of the same body: a disable added to this branch alone is invisible to that one.
    expect(slot<HTMLButtonElement>('submit').disabled).toBe(false);
    expect(slot('busy').hidden).toBe(true);
  });
});

describe('unlocking applies neither check, and that is correct', () => {
  it('a two character passphrase goes straight to the crypto on an existing vault', async () => {
    // An existing vault's passphrase is whatever it is. The length floor is a refusal to
    // CREATE a weak vault, not a claim about what can be typed here, and the confirmation
    // field is not even on this screen. A later tidy-up that shares one validation block
    // between the two paths would lock somebody out of their own device, so the absence of
    // both checks is pinned rather than left to be inferred from an `if (args.firstRun)`.
    const { crypto } = await boot(true);
    submitForm('ab');
    await waitForReady();

    expect(crypto.unlocked).toEqual(['ab']);
    expect(crypto.created).toEqual([]);
    // And it went through: the ready screen is up, so there is no error slot left to read.
    expect(screens().querySelector('h1')?.textContent).toBe('Pair in person');
    expect(screens().querySelector('[data-role="error"]')).toBeNull();
  });
});

describe('the session the unlock path opens is wired to the screens', () => {
  it('the idle re-lock arrives on the screen, and not only in the vault', async () => {
    // THE UNLOCK CALL SITE, which is every session after the first one. app.ts opens by
    // naming the idle re-lock as one of the three things this file has to get right, and the
    // way it goes wrong is silent: session.ts empties the vault on the timer whether or not
    // anything is listening, so a call site that opens the session WITHOUT the onLock
    // callback leaves the ready screen holding its two buttons over keys that are gone, the
    // scan screen holding a live camera, and the first thing to touch a key throwing into a
    // promise nobody holds. Nothing inside the session can observe which callbacks it was
    // handed, so the only honest check is that the lock reaches the screen.
    const { crypto } = await boot(true);

    // The fake clock is installed after start() and before the submit, so the vault's idle
    // timer is armed against it from the moment the session exists. Unlock is a promise
    // chain rather than a timer, so the ticks are what let it settle.
    vi.useFakeTimers();
    submitForm('ab');
    for (let waited = 0; waited < 2_000; waited++) {
      if (screens().querySelector('h1')?.textContent === 'Pair in person') break;
      await vi.advanceTimersByTimeAsync(1);
    }
    // Which of the two call sites this test stands on, and it is the point of the test: every
    // other file that drives this form fills the confirmation field, so they all open
    // createIdentity, and the unlock call site is reached in this file or nowhere.
    expect(crypto.unlocked).toEqual(['ab']);
    expect(announced()).toBe('Ready to pair in person.');

    // CONTROL, and the assertions below are worth little without it: just short of the
    // window nothing has moved, so what follows is the vault's own timer expiring rather
    // than a screen that would have changed on any advance at all.
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS - 1_000);
    expect(screens().querySelector('h1')?.textContent).toBe('Pair in person');

    await vi.advanceTimersByTimeAsync(1_000);

    // The notice is the whole difference a person can see. The vault empties itself either
    // way; this is the part that tells them why the screen changed and that nothing they
    // were doing survived it. Read off the h1 rather than the title slot, because the slot
    // helper throws where the screen never changed at all and a thrown lookup is a worse
    // failure message than the screen this test was left staring at.
    expect(screens().querySelector('h1')?.textContent).toBe('Unlock Keyweave');
    expect(slot('notice').hidden).toBe(false);
    expect(textOf('notice')).toBe(lockNotice(Math.round(IDLE_LOCK_MS / 60_000)));
    expect(announced()).toBe('Keyweave locked itself.');
  });
});

describe('the screen while the derivation is still running', () => {
  it('takes the submit button away and puts the spinner up before it starts waiting', async () => {
    // The half of the busy pair that has never been watched: "the button is back and the
    // spinner is gone AFTER a failed unlock", below, is satisfied just as well by a screen
    // that never disabled or showed either of them. Argon2id at 256 MiB is around three
    // seconds of live button, and a second press on it starts a second derivation over the
    // top of the first.
    const { crypto } = await boot(true);
    const release = park(crypto);
    submitForm('the passphrase for this vault');
    await waitFor(() => crypto.unlocked.length === 1, 'the crypto being called');

    expect(slot<HTMLButtonElement>('submit').disabled).toBe(true);
    expect(slot('busy').hidden).toBe(false);

    release();
    await waitForReady();
  });

  it('clears the error the last attempt left, before the next one can fail again', async () => {
    // A mistyped passphrase is the expected outcome on this screen, so a second attempt is
    // the normal case and not an edge. Without the clear, the sentence explaining why the
    // LAST attempt failed stays up for the whole of this one, next to a visible spinner: the
    // person is told their passphrase was rejected and that it is being checked, at once.
    const { crypto } = await boot(true);
    crypto.refuseWith = new Error('vault: decrypt failed');
    submitForm('the wrong passphrase entirely');
    await waitForError();
    // Control. The error really is up, so what the next attempt does to it means something.
    expect(slot('error').hidden).toBe(false);

    crypto.refuseWith = undefined;
    const release = park(crypto);
    submitForm('the passphrase for this vault');
    await waitFor(() => crypto.unlocked.length === 2, 'the second attempt reaching the crypto');

    expect(slot('error').hidden).toBe(true);

    release();
    await waitForReady();
  });

  it('tells a returning person their vault is being unwrapped, on screen and out loud', async () => {
    const { crypto } = await boot(true);
    const release = park(crypto);
    submitForm('the passphrase for this vault');
    await waitFor(() => crypto.unlocked.length === 1, 'the unlock call');

    // The same switch as the title and the lede, one screen further in. Told that a NEW
    // wrapping key is being derived, a returning person has been told their vault is being
    // replaced, which is the most alarming thing this screen could possibly say.
    expect(textOf('busy-text')).toBe('Unwrapping your vault. A few seconds, deliberately.');
    // And a screen reader is told something at all: several silent seconds after a press
    // read as a page that ignored it.
    expect(announced()).toBe('Working');

    release();
    await waitForReady();
  });

  it('tells a new person a wrapping key is being derived, on screen and out loud', async () => {
    const { crypto } = await boot(false);
    const release = park(crypto);
    submitForm('several unrelated words here', 'several unrelated words here');
    await waitFor(() => crypto.created.length === 1, 'the create call');

    // The create side of the same sentence, driven separately: a swap fails on whichever of
    // the two screens is read first, and each screen is somebody's only screen.
    expect(textOf('busy-text')).toBe('Deriving your wrapping key. A few seconds, deliberately.');
    expect(announced()).toBe('Working');

    release();
    await waitForReady();
  });
});

describe('a failed unlock', () => {
  it('leaves the screen usable: the button comes back and the spinner goes', async () => {
    const { crypto } = await boot(true);
    crypto.refuseWith = new Error('vault: decrypt failed');
    submitForm('the wrong passphrase entirely');
    await waitForError();

    // Without this the only way out of a mistyped passphrase is a page reload, on the one
    // screen where a mistyped passphrase is the expected outcome.
    expect(slot<HTMLButtonElement>('submit').disabled).toBe(false);
    expect(slot('busy').hidden).toBe(true);
    expect(slot('error').hidden).toBe(false);
  });

  it('a refused passphrase is said in the product copy, never in the internal error text', async () => {
    // THIS TEST WAS A CHARACTERIZATION AND IS NOW A RULE. What it used to pin was the
    // defect: submitPassphrase rendered `error.message` straight into the error slot and
    // read it out to a screen reader, so whatever sentence the vault, the KDF worker or the
    // storage layer happened to put in an Error was the product's most common failure
    // message. copy.ts opens by saying the copy is part of the security and lives in one
    // file the suite can read, and this was the one user-facing path that walked past it.
    //
    // The error string used here is the one the shipped vault actually throws, so what is
    // being routed is the real thing rather than a fixture-shaped one.
    const { crypto } = await boot(true);
    crypto.refuseWith = new Error('vault: unlock failed (wrong passphrase or tampered blob)');
    submitForm('the wrong passphrase entirely');
    await waitForError();

    expect(textOf('error')).toBe(UNLOCK_COPY.wrongPassphrase);
    expect(announced()).toBe(UNLOCK_COPY.wrongPassphrase);
    // THE NEGATIVE HALF, and the one that discriminates: both assertions above move with
    // copy.ts, so a constant reworded back into the developer's own sentence would satisfy
    // them. This does not.
    expect(textOf('error')).not.toContain('vault:');
    expect(announced()).not.toContain('vault:');
  });

  it('the layer-below error is kept for a developer, off the screen and out of the live region', async () => {
    // "Route it through copy.ts" must not mean "throw the diagnosis away": a person
    // reporting a failure and a developer reading their devtools want different sentences.
    // A data attribute is neither rendered nor announced, so it is a place to keep one that
    // is not a second sentence on the page.
    const { crypto } = await boot(true);
    crypto.refuseWith = new Error('vault: unlock failed (wrong passphrase or tampered blob)');
    submitForm('the wrong passphrase entirely');
    await waitForError();

    expect(slot('error').dataset.detail).toBe(
      'vault: unlock failed (wrong passphrase or tampered blob)',
    );
    // And it is genuinely not on the screen: textContent is what is painted and what a
    // screen reader reads, and the attribute is in neither.
    expect(textOf('error')).not.toContain('vault:');
    expect(announced()).not.toContain('vault:');
  });

  it('a validation refusal carries no diagnostic, rather than a stale one from before', async () => {
    // The same element is reused for every failure on this screen, so an attribute that is
    // only ever SET leaves the previous failure's diagnosis attached to the next one. That
    // is worse than not having it: it is a wrong diagnosis that looks authoritative.
    const { crypto } = await boot(false);
    crypto.refuseWith = new Error('vault: unlock failed (wrong passphrase or tampered blob)');
    submitForm('several unrelated words here', 'several unrelated words here');
    await waitForError();
    expect(slot('error').dataset.detail).toBe(
      'vault: unlock failed (wrong passphrase or tampered blob)',
    ); // control: it really was set once

    crypto.refuseWith = undefined;
    submitForm('short', 'short');
    await settle();
    expect(textOf('error')).toBe(`Use at least ${MIN_PASSPHRASE_LENGTH} characters.`);
    expect(slot('error').dataset.detail).toBeUndefined();
  });

  it('each failure the layers below can throw gets its own sentence, and none is the default', () => {
    // Called rather than driven, because the mapping is a pure function and the branches it
    // has are decidable by calling it. The two matched strings are the ones vault.ts and
    // session.ts really throw, quoted from those files.
    expect(unlockFailureMessage(new Error('vault: unlock failed (wrong passphrase or tampered blob)'))).toBe(
      UNLOCK_COPY.wrongPassphrase,
    );
    expect(unlockFailureMessage(new Error('session: no vault on this device'))).toBe(
      UNLOCK_COPY.noVault,
    );
    // Anything else, including a storage layer failing in its own words and a throw that is
    // not an Error at all, lands on the line that claims nothing about the cause.
    expect(unlockFailureMessage(new Error('the storage quota was exceeded'))).toBe(
      UNLOCK_COPY.unknown,
    );
    expect(unlockFailureMessage('a bare string')).toBe(UNLOCK_COPY.unknown);

    // Negative control: three distinct strings, so a mapping whose arms all returned one
    // constant would fail here rather than pass every line above. And the default really is
    // the one that says the passphrase was not refused, which is the claim that would be
    // wrong on the wrong-passphrase path.
    expect(new Set(Object.values(UNLOCK_COPY)).size).toBe(3);
    expect(UNLOCK_COPY.unknown).toContain('not a refused passphrase');
    expect(UNLOCK_COPY.wrongPassphrase).not.toContain('not a refused passphrase');
  });
});

describe('the reveal button', () => {
  it('toggles the passphrase between hidden and shown, and says which state it is in', async () => {
    await boot(true);
    const reveal = slot<HTMLButtonElement>('reveal');
    const input = field('passphrase');
    const icon = () => reveal.querySelector('use')!.getAttribute('href');

    expect(input.type).toBe('password');
    expect(reveal.getAttribute('aria-pressed')).toBe('false');
    expect(icon()).toBe('#i-eye');

    reveal.click();
    expect(input.type).toBe('text');
    expect(reveal.getAttribute('aria-pressed')).toBe('true');
    // The label and the icon both describe the ACTION, so they invert while the state does
    // not: with the passphrase on screen the button offers to hide it.
    expect(reveal.getAttribute('aria-label')).toBe('Hide passphrase');
    expect(icon()).toBe('#i-eye-off');

    reveal.click();
    expect(input.type).toBe('password');
    expect(reveal.getAttribute('aria-pressed')).toBe('false');
    expect(reveal.getAttribute('aria-label')).toBe('Show passphrase');
    expect(icon()).toBe('#i-eye');
  });
});

describe('the ready screen', () => {
  it('prints the short identity and hides the contacts block when nothing is pinned', async () => {
    const { crypto } = await boot(false);
    submitForm('several unrelated words here', 'several unrelated words here');
    await waitForReady();
    expect(crypto.created).toEqual(['several unrelated words here']);

    // Derived here from the same seed rather than read back from the screen, so the sentence
    // and the truncation are both decided by this file.
    const keys = await keyManagerFromSeeds(
      Uint8Array.from(IDENTITY_SEED),
      Uint8Array.from(ENCRYPTION_SEED),
      'noble',
    );
    const expected = firstFourGroups(toHex(keys.identityPublicKey()));
    expect(textOf('identity')).toBe(`This device identity starts ${expected}.`);
    // Four groups of four, not the whole key: the point is a value two people could read to
    // each other, and the full 64 characters is a value nobody reads at all.
    expect(textOf('identity')).not.toContain(toHex(keys.identityPublicKey()));

    // An empty contacts block would be a heading over nothing on the first screen after
    // setup, which is the one screen where "you have paired with nobody" is the normal case.
    expect(slot('contacts').hidden).toBe(true);
    expect(slot('contact-list').children).toHaveLength(0);
  });

  it('lists one row per pinned peer, in the order they were pinned', async () => {
    // The only way back into a conversation after a reload. Two peers, because a rule that
    // renders the first contact and a rule that renders every contact agree on one.
    const first = await generateKeyManager('noble');
    const second = await generateKeyManager('noble');
    const cards = [
      await createSignedCard(first.manager, 1),
      await createSignedCard(second.manager, 1),
    ];

    loadShell();
    const crypto = new RecordingCrypto();
    crypto.contacts = cards;
    const store = new MemoryBlobStore();
    await store.save(STORED_BLOB);
    const app = new KeyweaveApp({ crypto, store, relay: unreachableRelay() });
    await app.start();
    submitForm('the passphrase for this vault');
    await waitForReady();

    expect(slot('contacts').hidden).toBe(false);
    const rows = [...slot('contact-list').querySelectorAll('[data-role="label"]')];
    expect(rows.map((row) => row.textContent)).toEqual([
      `Identity ${firstFourGroups(toHex(first.manager.identityPublicKey()))}`,
      `Identity ${firstFourGroups(toHex(second.manager.identityPublicKey()))}`,
    ]);
    // Each row is a button, because opening a conversation is an action and not a link to
    // somewhere else in a single-page app that has no routes.
    expect(slot('contact-list').querySelectorAll('button[data-role="open"]')).toHaveLength(2);
  });
});

describe('what the camera failed at is named, not summarised', () => {
  it('maps every camera outcome to its own sentence, including the one with no prompt', async () => {
    // 'insecure-context' is the arm that has never executed anywhere, and it is the one that
    // most needs its own sentence: on plain HTTP a phone reports navigator.mediaDevices as
    // UNDEFINED, so the API is ABSENT rather than refused, and to the person holding the
    // phone that is indistinguishable from a broken camera. Telling them permission was
    // denied sends them into a settings screen that has nothing in it to change.
    expect(cameraMessage('insecure-context')).toBe(CAMERA_COPY.insecureContext);
    expect(cameraMessage('denied')).toBe(CAMERA_COPY.denied);
    expect(cameraMessage('no-camera')).toBe(CAMERA_COPY.noCamera);
    expect(cameraMessage('in-use')).toBe(CAMERA_COPY.inUse);
    // Anything the camera layer could not classify, including a kind added later and not
    // wired up here, falls to the sentence that claims nothing about the cause.
    expect(cameraMessage('nonsense-from-a-future-browser')).toBe(CAMERA_COPY.unknown);

    // Negative control: five distinct strings, so a switch whose arms all returned the same
    // constant would fail here rather than pass every line above.
    const said = [
      cameraMessage('insecure-context'),
      cameraMessage('denied'),
      cameraMessage('no-camera'),
      cameraMessage('in-use'),
      cameraMessage('unknown'),
    ];
    expect(new Set(said).size).toBe(5);
  });
});
