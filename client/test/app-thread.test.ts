// @vitest-environment happy-dom
//
// The conversation thread, EXECUTED rather than read as text.
//
// Everything below used to be guarded by regexes over app.ts in ui-shell.test.ts. A measured
// pass defeated 19 of 19 single-edit mutations to these rules, all of them typechecking
// clean, including `return record.receivedAtMs - record.timestampMs > RUN_GAP_MS` collapsed
// to `return false`, which switches the relay-withheld display rule off entirely. A regex
// that reads the word `heldBack(` in the grouping expression cannot tell that apart from a
// working rule. Calling the functions can.
//
// legacy: this is a CHARACTERIZATION suite. It pins what the code does TODAY, including two
// behaviours that look wrong (marked CHARACTERIZATION in their titles, with the reasoning in
// a comment). Fixing them here would make a later regression unattributable, so the fix, if
// there is one, is a separate commit that has to change one of these tests deliberately.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  RUN_GAP_MS,
  clockOf,
  decodeBody,
  heldBack,
  metaFor,
  renderThread,
} from '../src/ui/app.js';
import { CONVERSATION_COPY } from '../src/ui/copy.js';
import { utf8 } from '../src/bytes.js';
import type { MessageRecord } from '../src/vault.js';

/**
 * The real templates, from the real index.html. renderThread clones `tpl-message` out of the
 * document, so a stub `<li>` written here would test a fixture rather than the shipped
 * markup: the whole point of ui-shell.test.ts's template checks is that the hooks live in
 * one place, and this suite reads that same place.
 */
function loadShell(): void {
  const html = readFileSync(join(__dirname, '..', 'index.html'), 'utf8');
  const body = /<body[^>]*>([\s\S]*)<\/body>/.exec(html);
  if (!body) throw new Error('no <body> in index.html');
  // The module entry is dropped rather than loaded. Nothing here drives the real bootstrap,
  // and leaving the tag in makes the DOM try to fetch it and print a DOMException per call,
  // which is noise that a real failure would then have to be found inside. That the page
  // loads exactly one module entry, from this origin, is ui-shell.test.ts's rule.
  document.body.innerHTML = body[1]!.replace(/<script\b[\s\S]*?<\/script>/g, '');
}

const PEER = new Uint8Array(32).fill(7);
// A fixed instant, so nothing here depends on when the suite runs. Every rendered clock is
// built by calling clockOf() rather than written out, because toLocaleString() answers to
// the machine's timezone and locale and a hardcoded string would pin the box, not the rule.
const T = Date.UTC(2026, 7, 9, 12, 0, 0);

function inbound(over: Partial<MessageRecord> = {}): MessageRecord {
  return { peerId: PEER, direction: 'in', timestampMs: T, body: utf8('hello'), ...over };
}

function outbound(over: Partial<MessageRecord> = {}): MessageRecord {
  return {
    peerId: PEER,
    direction: 'out',
    timestampMs: T,
    body: utf8('hello'),
    delivery: 'queued',
    ...over,
  };
}

/**
 * A detached list is enough: renderThread only ever calls replaceChildren on it. Handing it a
 * fresh <ol> every call is also what makes that sentence unfalsifiable from here, so the
 * sentence itself is pinned by 'painting the same list twice leaves one copy of the
 * conversation' below, which reuses one list the way the shipped screen does.
 */
function paint(records: readonly MessageRecord[]): HTMLElement[] {
  loadShell();
  const list = document.createElement('ol');
  renderThread(list, records);
  return [...list.children] as HTMLElement[];
}

function metaOf(row: HTMLElement): HTMLElement {
  return row.querySelector<HTMLElement>('[data-role="meta"]')!;
}

function bodyOf(row: HTMLElement): HTMLElement {
  return row.querySelector<HTMLElement>('[data-role="body"]')!;
}

const startsRun = (rows: readonly HTMLElement[]): boolean[] =>
  rows.map((row) => row.classList.contains('msg-start'));

/**
 * Which side each bubble is on. Read as the side classes a row actually carries rather than
 * as a boolean, so a row carrying BOTH of them, or neither, is a different answer from a row
 * carrying the wrong one.
 */
const sides = (rows: readonly HTMLElement[]): string[] =>
  rows.map((row) =>
    [...row.classList].filter((name) => name === 'msg-out' || name === 'msg-in').join(' '),
  );

/** What the reader actually sees on a row: a hidden meta line reads as nothing at all. */
const printedMeta = (row: HTMLElement): string =>
  metaOf(row).hidden ? '' : (metaOf(row).textContent ?? '');

describe('the grouping window is a number, not an expression nobody checks', () => {
  it('RUN_GAP_MS is five minutes in milliseconds', () => {
    // Every other boundary assertion in this file is written in terms of the imported
    // constant, which makes all of them blind to the constant itself moving: change
    // 5 * 60_000 to 4 * 60_000 and the strict-boundary test still passes, at the new
    // boundary. This is the one assertion that notices, so it is a literal on purpose.
    expect(RUN_GAP_MS).toBe(300_000);
  });
});

describe('heldBack decides whether the relay sat on a message', () => {
  it('an outbound record is never held back, whatever arrival time it carries', () => {
    // An outbound record has no arrival time in normal operation, so the direction check
    // looks redundant until you ask what happens if one ever gets a receivedAtMs: this
    // device's own send clock against this device's own clock is not a relay delay, and
    // calling it one would print "Reached this device at" on a message the reader wrote.
    expect(heldBack(outbound({ receivedAtMs: T + RUN_GAP_MS * 100 }))).toBe(false);
  });

  it('an inbound record with no arrival time is not held back', () => {
    // receivedAtMs is absent on records admitted before the field existed. Absent is not
    // evidence of a delay, and guessing one from the sender's clock alone would hand the
    // decision back to the relay, which is the thing this rule exists to take it away from.
    expect(heldBack(inbound({ receivedAtMs: undefined }))).toBe(false);
  });

  it('the threshold is strict: exactly RUN_GAP_MS is not held back, one millisecond more is', () => {
    expect(heldBack(inbound({ receivedAtMs: T + RUN_GAP_MS }))).toBe(false);
    expect(heldBack(inbound({ receivedAtMs: T + RUN_GAP_MS + 1 }))).toBe(true);
  });

  it('CHARACTERIZATION: a negative delta from clock skew is not held back', () => {
    // The delta is SIGNED and one-sided (R12 residual). A message that arrives BEFORE its
    // sender claims to have written it means the two clocks disagree, and the reading here
    // is that a disagreement in that direction is not a relay holding anything back, so
    // nothing is said about it at all. The alternative reading, that any large disagreement
    // is worth naming on the screen, is a product decision and not this commit's.
    expect(heldBack(inbound({ receivedAtMs: T - RUN_GAP_MS * 2 }))).toBe(false);
  });
});

describe('metaFor says whose clock each time is', () => {
  it('a held-back inbound line names the arrival first and the sender claim second', () => {
    // The two numbers are from different clocks and only one of them is a fact this device
    // observed. Printing them without saying which is which would let the sender's claim
    // pass as an arrival time, which on exactly these records is the number the relay chose.
    const record = inbound({ receivedAtMs: T + RUN_GAP_MS + 1 });
    expect(metaFor(record)).toBe(
      `Reached this device at ${clockOf(T + RUN_GAP_MS + 1)}, sent at ${clockOf(T)}`,
    );
  });

  it('a plain inbound line names only the sender clock, so the two arms are not swapped', () => {
    // The pair is the point: swap the ternary and an ordinary message starts claiming a
    // relay delay while a withheld one stops reporting one. Either half alone would still
    // pass with the condition inverted.
    expect(metaFor(inbound())).toBe(`Received, sent at ${clockOf(T)}`);
    expect(metaFor(inbound({ receivedAtMs: T + 1000 }))).toBe(`Received, sent at ${clockOf(T)}`);
  });

  it('an outbound line prints the delivery state and then the time', () => {
    // R9: the relay sends back no receipt, so "handed over" is the last true thing this
    // device knows and "queued" means it has not even got that far. Reversing these two
    // tells someone their message left the device when it is still sitting on it.
    expect(metaFor(outbound({ delivery: 'queued' }))).toBe(
      `${CONVERSATION_COPY.queued}, ${clockOf(T)}`,
    );
    expect(metaFor(outbound({ delivery: 'relayed' }))).toBe('Handed to the relay, ' + clockOf(T));
    // An outbound record with no delivery state at all reads as the weaker claim.
    expect(metaFor(outbound({ delivery: undefined }))).toBe(
      `${CONVERSATION_COPY.queued}, ${clockOf(T)}`,
    );
  });
});

describe('clockOf never renders a broken date as a date', () => {
  it('an unreadable timestamp is named as one, and a readable one is localised', () => {
    // A record can carry a timestamp this device cannot make sense of. "Invalid Date" on a
    // message line looks like a bug in the message; a sentence looks like what it is.
    expect(clockOf(Number.NaN)).toBe('an unreadable time');
    expect(clockOf(T)).toBe(new Date(T).toLocaleString());
  });
});

describe('decodeBody renders a body that is authentic but not necessarily valid', () => {
  it('invalid UTF-8 becomes replacement characters instead of throwing', () => {
    // Authenticity is what the seal proves; well-formedness is not. A fatal decoder here
    // would turn one malformed body into a conversation that will not render at all.
    const body = new Uint8Array([...utf8('ok'), 0x80]);
    expect(() => decodeBody(body)).not.toThrow();
    expect(decodeBody(body)).toBe('ok�');
  });

  it('CHARACTERIZATION: a leading byte order mark is stripped, so the body is not byte-faithful', () => {
    // TextDecoder defaults ignoreBOM to false, which means the BOM is REMOVED. The doc
    // comment above decodeBody says a body is "whatever bytes the sender sealed", and this
    // is the one case where the rendered text is not that: a sender who deliberately began
    // a message with U+FEFF sees it silently dropped on the other device, and nothing on
    // the screen says so. Pinned as-is; the claim gap is noted rather than fixed here.
    const withBom = new Uint8Array([0xef, 0xbb, 0xbf, ...utf8('hi')]);
    expect(decodeBody(withBom)).toBe('hi');
    // A second BOM survives, which is what makes the first one a decoder rule rather than
    // a rule about the character.
    const twoBoms = new Uint8Array([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, ...utf8('hi')]);
    expect(decodeBody(twoBoms)).toBe('﻿hi');
  });
});

describe('a held-back message is always a run of its own', () => {
  it('shatters the run around it, so all three neighbours print their own meta', () => {
    // The invariant this whole rule exists for (residual R3). The thread sorts on the
    // SENDER's clock, so a blob the relay withheld lands wherever the sender wrote it,
    // which can be far above the last thing the reader saw. Only the last message of a run
    // prints a meta line, so left inside a neighbouring run the withheld message would
    // print NOTHING: the relay's decision to sit on it would render as ordinary read
    // history. Here all three records are inbound and two seconds apart, which is every
    // reason to group them, and the middle one is withheld, so all three stand alone.
    const rows = paint([
      inbound({ timestampMs: T }),
      inbound({ timestampMs: T + 1000, receivedAtMs: T + 1000 + RUN_GAP_MS + 1 }),
      inbound({ timestampMs: T + 2000 }),
    ]);
    expect(rows).toHaveLength(3);
    expect(startsRun(rows)).toEqual([true, true, true]);
    expect(printedMeta(rows[0]!)).toBe(`Received, sent at ${clockOf(T)}`);
    expect(printedMeta(rows[1]!)).toBe(
      `Reached this device at ${clockOf(T + 1000 + RUN_GAP_MS + 1)}, sent at ${clockOf(T + 1000)}`,
    );
    expect(printedMeta(rows[2]!)).toBe(`Received, sent at ${clockOf(T + 2000)}`);
  });

  it('and without one, the same three records collapse into a single run', () => {
    // The negative control for the test above. Three inbound records two seconds apart are
    // one exchange and print one timestamp, at the bottom. Without this, a rule that put
    // every message in its own run would pass the shattering test while destroying the
    // grouping the screen is built on. The single edit that shows it is the direction check
    // inverted, `previous.direction !== record.direction` to `===`: three inbound records
    // then start three runs and this goes red. Writing `true ||` in front of the
    // `previous === undefined` guard means the same thing but is NOT a fair mutation, since
    // that disjunct is what narrows `previous` for the three lines under it and removing it
    // fails to typecheck, so it could never have landed quietly in the first place.
    const rows = paint([
      inbound({ timestampMs: T }),
      inbound({ timestampMs: T + 1000 }),
      inbound({ timestampMs: T + 2000 }),
    ]);
    expect(startsRun(rows)).toEqual([true, false, false]);
    expect(rows.map(printedMeta)).toEqual([
      '',
      '',
      `Received, sent at ${clockOf(T + 2000)}`,
    ]);
  });
});

describe('run grouping', () => {
  it('the gap boundary is strict: exactly RUN_GAP_MS groups, one millisecond more does not', () => {
    const together = paint([inbound(), inbound({ timestampMs: T + RUN_GAP_MS })]);
    expect(startsRun(together)).toEqual([true, false]);
    expect(printedMeta(together[0]!)).toBe('');

    const apart = paint([inbound(), inbound({ timestampMs: T + RUN_GAP_MS + 1 })]);
    expect(startsRun(apart)).toEqual([true, true]);
    expect(printedMeta(apart[0]!)).toBe(`Received, sent at ${clockOf(T)}`);
  });

  it('a change of direction breaks a run however close the two messages are', () => {
    // gestalt: which side a bubble sits on is the only thing carrying who sent it, so a run
    // that spans both sides would put one timestamp on an exchange between two people.
    const rows = paint([outbound(), inbound({ timestampMs: T + 1000 })]);
    expect(startsRun(rows)).toEqual([true, true]);
    // And the sides themselves, because the run break above survives the two arms of that
    // ternary being swapped: the directions still differ, so the run still breaks, and every
    // message the reader wrote simply moves over to the peer's side and every message the
    // peer wrote moves to the reader's. msg-out and msg-in occur in exactly four places in
    // the repo, app.ts and three rules in styles.css, and until this line none of them was a
    // test, so that swap was a whole-conversation misattribution nothing would have noticed.
    expect(sides(rows)).toEqual(['msg-out', 'msg-in']);
    expect(printedMeta(rows[0]!)).toBe(`${CONVERSATION_COPY.queued}, ${clockOf(T)}`);
    expect(printedMeta(rows[1]!)).toBe(`Received, sent at ${clockOf(T + 1000)}`);
  });

  it('CHARACTERIZATION: a run prints only its last delivery state, so a queued message sits under a relayed line', () => {
    // SUSPECTED WRONG, pinned deliberately. Row 0 is still queued on this device and row 1
    // has been handed over; because only the last message of a run prints, the reader sees
    // one line saying "Handed to the relay" sitting under both. In the one product that
    // ships CONVERSATION_COPY.deliveryNote specifically to stop "sent" being read as
    // "delivered", a message that has not left the device is displayed under a line saying
    // the relay took it. The grouping rule is per-run and knows nothing about delivery.
    const rows = paint([
      outbound({ timestampMs: T, delivery: 'queued' }),
      outbound({ timestampMs: T + 1000, delivery: 'relayed' }),
    ]);
    expect(startsRun(rows)).toEqual([true, false]);
    expect(metaOf(rows[0]!).hidden).toBe(true);
    expect(metaOf(rows[0]!).textContent).toBe('');
    expect(printedMeta(rows[1]!)).toBe(`Handed to the relay, ${clockOf(T + 1000)}`);
  });

  it('CHARACTERIZATION: renderThread does not sort, so descending input renders descending', () => {
    // Sorting is messaging.conversation()'s contract (messaging.ts, sorted on the sender's
    // timestamp with a stable tiebreak) and renderThread trusts it completely. Given the
    // reverse it still groups the two records, and the one meta line it prints belongs to
    // the OLDER record, at the bottom. Pinned so that anyone moving the sort discovers that
    // this function is the place it was not.
    const rows = paint([inbound({ timestampMs: T + 60_000 }), inbound({ timestampMs: T })]);
    expect(startsRun(rows)).toEqual([true, false]);
    expect(printedMeta(rows[0]!)).toBe('');
    expect(printedMeta(rows[1]!)).toBe(`Received, sent at ${clockOf(T)}`);
  });
});

describe('renderThread replaces the thread rather than adding to it', () => {
  it('painting the same list twice leaves one copy of the conversation', () => {
    // The shipped screen holds ONE list element and repaints into it: renderConversation
    // captures the thread node once and its paint() closure runs on every 20 second poll,
    // after every send and after every refresh. So replaceChildren is not an implementation
    // detail of how rows arrive; appending instead would add the entire conversation to the
    // screen again every twenty seconds, and the reader would watch their own history
    // multiply while reading it. Every other test in this file hands renderThread a fresh
    // <ol>, which makes append and replaceChildren indistinguishable, so this is the one
    // place the difference is visible.
    loadShell();
    const list = document.createElement('ol');
    const records = [inbound({ timestampMs: T }), outbound({ timestampMs: T + 1000 })];
    renderThread(list, records);
    expect(list.children).toHaveLength(2);
    renderThread(list, records);
    expect(list.children).toHaveLength(2);
    // And a poll that brings one new message shows three rows, not the rows already on the
    // screen plus a fresh three, which is what the repaint after a sync hands this function.
    renderThread(list, [...records, inbound({ timestampMs: T + 2000, body: utf8('later') })]);
    expect([...list.children].map((row) => bodyOf(row as HTMLElement).textContent)).toEqual([
      'hello',
      'hello',
      'later',
    ]);
  });
});

describe('a message body is text and only text', () => {
  it('markup in a body is rendered as literal characters and builds no element', () => {
    // The body is attacker-controlled in the only sense that matters here: it is whatever
    // the peer sealed, and a peer is somebody you met once in person, not somebody you
    // trust with script execution on your own page. setText is textContent, so this is
    // structural rather than a filter, and the assertion is that no element appears at all
    // rather than that a particular string was escaped.
    const evil = '<script>alert(1)</script><img src=x onerror=alert(2)>';
    const rows = paint([inbound({ body: utf8(evil) })]);
    const body = bodyOf(rows[0]!);
    expect(body.textContent).toBe(evil);
    expect(body.children).toHaveLength(0);
    expect(rows[0]!.querySelector('script')).toBeNull();
    expect(rows[0]!.querySelector('img')).toBeNull();
  });
});
