// The app shell, checked as text.
//
// There is no jsdom in this project and adding one to assert that a button is 44 pixels
// tall would be a worse trade than reading the stylesheet. What IS checked here is
// everything that is decidable from the source and would otherwise only be caught by
// somebody looking at the page in the right browser at the right moment:
//
//   - the CSP-relevant shape of index.html (no inline script, no inline handler, no
//     external origin, no style attribute), which is the half of R13 that lives in markup;
//   - accessibility invariants that are easy to lose in a refactor: a label per input, a
//     live region, focus rings, touch targets, reduced motion, a light scheme;
//   - the honesty rules the copy is held to, including the one sentence that names R1 and
//     the sentence about the relay that must never come back;
//   - that every template id and data-role app.ts reaches for actually exists. This is the
//     cheap loop that catches a renamed hook, and it has to be machine-checked because a
//     missing data-role is a runtime throw on one screen nobody opens during a smoke test.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NOSCRIPT_NOTICE } from '../src/ui/copy.js';
import { MIN_PASSPHRASE_LENGTH, passphraseHint } from '../src/ui/passphrase.js';
import type { FlushReport, ReceiveReport } from '../src/messaging.js';

const CLIENT_DIR = fileURLToPath(new URL('..', import.meta.url));
const UI_DIR = join(CLIENT_DIR, 'src', 'ui');

const html = readFileSync(join(CLIENT_DIR, 'index.html'), 'utf8');
const css = readFileSync(join(UI_DIR, 'styles.css'), 'utf8');
const appSource = readFileSync(join(UI_DIR, 'app.ts'), 'utf8');

function uiFiles(): string[] {
  return readdirSync(UI_DIR)
    .filter((name) => statSync(join(UI_DIR, name)).isFile())
    .map((name) => relative(CLIENT_DIR, join(UI_DIR, name)))
    .sort();
}

function matchesOf(source: string, pattern: RegExp): string[] {
  return [...source.matchAll(pattern)].map((m) => m[1]!);
}

/**
 * Comments removed, like the patent firewall's own text arms. The prose rules below ban
 * phrases, and a file has to be able to say in a comment which phrase it is avoiding and
 * why. Without this the honest thing to write is a deleted comment.
 */
function stripComments(rel: string, source: string): string {
  if (rel.endsWith('.html')) return source.replace(/<!--[\s\S]*?-->/g, ' ');
  return source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ');
}

function prose(rel: string): string {
  return stripComments(rel, readFileSync(join(CLIENT_DIR, rel), 'utf8'));
}

const markup = stripComments('index.html', html);
const styles = stripComments('styles.css', css);

/** The balanced-brace body of the first rule or at-rule whose header matches `header`. */
function braceBody(source: string, header: string): string {
  const start = source.indexOf(header);
  if (start < 0) throw new Error(`no block for ${header}`);
  const open = source.indexOf('{', start + header.length - 1);
  if (open < 0) throw new Error(`no opening brace for ${header}`);
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}' && --depth === 0) return source.slice(open + 1, i);
  }
  throw new Error(`unbalanced braces after ${header}`);
}

/** The body of a class method, found by name and read to its matching brace. */
function methodBody(source: string, name: string): string {
  const match = new RegExp(`\\n  (?:private |public )?(?:async )?${name}\\(`).exec(source);
  if (!match) throw new Error(`no method ${name}`);
  return braceBody(source.slice(match.index), ')');
}

function token(block: string, name: string): string {
  const match = new RegExp(`--${name}:\\s*([^;]+);`).exec(block);
  if (!match) throw new Error(`no --${name} in block`);
  return match[1]!.trim();
}

/** WCAG 2.x relative luminance and contrast ratio, for #rrggbb only. */
function luminance(hex: string): number {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const linear = channels.map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * linear[0]! + 0.7152 * linear[1]! + 0.0722 * linear[2]!;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

describe('index.html is CSP-clean by construction', () => {
  it('has no inline script and no inline event handler', () => {
    const inline = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)].filter(
      ([, , body]) => (body ?? '').trim().length > 0,
    );
    expect(inline).toEqual([]);
    // onclick, onsubmit, onload and every other on* attribute.
    expect(html.match(/\s\bon[a-z]+\s*=/i)).toBeNull();
  });

  it('has no external origin, no webfont and no style attribute', () => {
    expect(html.match(/https?:\/\//)).toBeNull();
    // The SVG namespace attribute: omitted because the HTML parser implies it, which keeps
    // the one string that would otherwise be a permanent exception out of the bundle.
    expect(markup.match(/\sxmlns\s*=/)).toBeNull();
    // Every subresource is same-origin and absolute, so no preconnect can creep in.
    const links = matchesOf(markup, /<link[^>]+href="([^"]+)"/g);
    expect(links.length).toBeGreaterThan(0);
    for (const href of links) expect(href.startsWith('/')).toBe(true);
    expect(markup.match(/\sstyle="/)).toBeNull();
    expect(markup).not.toContain('<img');
  });

  it('loads exactly one module entry, from this origin', () => {
    const srcs = matchesOf(html, /<script[^>]+src="([^"]+)"/g);
    expect(srcs).toEqual(['/src/ui/main.ts']);
    expect(html).toContain('type="module"');
  });

  it('the stylesheet fetches nothing', () => {
    expect(styles).not.toContain('@font-face');
    expect(styles.match(/url\s*\(/)).toBeNull();
    expect(styles.match(/@import/)).toBeNull();
    // Inter if the reader already has it, platform font otherwise. Never a download.
    expect(css).toContain("Inter, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif");
  });
});

describe('accessibility invariants', () => {
  it('every input has a real label bound to it', () => {
    const inputs = matchesOf(html, /<input\b[^>]*\sid="([^"]+)"/g);
    expect(inputs.length).toBeGreaterThan(1);
    for (const id of inputs) {
      expect(html, `no <label for="${id}">`).toContain(`for="${id}"`);
    }
  });

  it('there is a polite live region for ceremony state changes', () => {
    expect(html).toMatch(/aria-live="polite"/);
    expect(html).toMatch(/role="status"/);
    expect(appSource).toContain('this.announce(');
  });

  it('every screen heading can take focus when the screen changes', () => {
    const headings = [...markup.matchAll(/<h1\b[^>]*>/g)].map((m) => m[0]);
    expect(headings.length).toBeGreaterThanOrEqual(7);
    for (const heading of headings) {
      expect(heading, `heading without tabindex: ${heading}`).toContain('tabindex="-1"');
    }
    // Every section names its heading, so the screen is announced as a region.
    const sections = [...markup.matchAll(/<section\b[^>]*>/g)].map((m) => m[0]);
    expect(sections.length).toBe(headings.length);
    for (const section of sections) expect(section).toContain('aria-labelledby=');
    expect(appSource).toContain("this.screens.querySelector('h1')?.focus()");
  });

  it('icons are SVG symbols, and nothing anywhere is an emoji', () => {
    expect(html).toContain('<symbol id="i-shield"');
    const pictographic = /\p{Extended_Pictographic}/u;
    // Negative control: a rule that matches nothing passes on an empty tree too. The
    // character is built from code points so this file stays scannable by its own rule.
    expect(pictographic.test(String.fromCodePoint(0x1f512))).toBe(true);
    expect(pictographic.test('a plain sentence')).toBe(false);
    for (const rel of ['index.html', ...uiFiles()]) {
      const source = readFileSync(join(CLIENT_DIR, rel), 'utf8');
      // The test names the class of character it bans; scanning itself always matches.
      expect(pictographic.test(source), `${rel} contains an emoji`).toBe(false);
    }
  });

  it('the hidden attribute actually hides, despite the author display rules', () => {
    // Several classes set display (flex), which beats the UA stylesheet's [hidden] rule.
    // Every screen uses `hidden` to toggle the busy state, the retry button and the
    // confirm field, so without an explicit override those never hide.
    expect(styles).toMatch(/\[hidden\]\s*\{\s*display:\s*none\s*!important/);
    expect(markup).toMatch(/\shidden\b/);
  });

  it('the stylesheet keeps focus rings, touch targets, reduced motion and a light scheme', () => {
    expect(css).toContain(':focus-visible');
    expect(css).toMatch(/--tap:\s*44px/);
    expect(css).toMatch(/min-height:\s*var\(--tap\)/);
    expect(css).toMatch(/min-width:\s*var\(--tap\)/);
    expect(css).toContain('@media (prefers-reduced-motion: reduce)');
    expect(css).toContain('@media (prefers-color-scheme: light)');
  });

  it('more contrast means more contrast in BOTH schemes', () => {
    // The values that raise contrast on a dark page (near-white text, white-alpha borders)
    // LOWER it on a light one, and this block sits after the light-scheme block, so an
    // unscoped version wins the cascade wherever both queries match. Everything painted
    // var(--muted) is affected, including the R1 trust banner and the "Stop pairing"
    // escape hatch, so this is recomputed rather than pattern-matched.
    const darkBg = token(braceBody(css, ':root'), 'bg');
    const lightBg = token(braceBody(css, '@media (prefers-color-scheme: light)'), 'bg');
    const more = braceBody(css, '@media (prefers-contrast: more)');
    const lightArm = braceBody(more, '@media (prefers-color-scheme: light)');

    // 7:1 is the AAA bar, and asking for more contrast is asking for at least that.
    expect(contrast(token(more, 'muted'), darkBg)).toBeGreaterThanOrEqual(7);
    expect(contrast(token(lightArm, 'muted'), lightBg)).toBeGreaterThanOrEqual(7);

    // Negative control: the dark-scheme value on the light background, which is what an
    // unscoped block produces. If this ever clears the bar the check has stopped looking.
    expect(contrast(token(more, 'muted'), lightBg)).toBeLessThan(4.5);
  });

  it('the two verdict buttons are equally weighted and neither is a submit', () => {
    const compare = html.slice(
      html.indexOf('<template id="screen-compare">'),
      html.indexOf('</template>', html.indexOf('<template id="screen-compare">')),
    );
    expect(compare).toContain('data-role="match"');
    expect(compare).toContain('data-role="mismatch"');
    // Same class, so neither is the styled happy path.
    const classes = matchesOf(compare, /<button\s+class="([^"]+)"/g);
    expect(classes).toEqual(['btn btn-verdict', 'btn btn-verdict']);
    // No form, so Enter cannot submit; no autofocus, so nothing is pre-selected.
    expect(compare).not.toContain('<form');
    expect(compare).not.toContain('autofocus');
    expect(compare).not.toContain('type="submit"');
    for (const type of matchesOf(compare, /<button[^>]+type="([^"]+)"/g)) {
      expect(type).toBe('button');
    }
  });
});

describe('the copy is held to the honesty rules', () => {
  it('R1 is named in the product, on the ceremony screens', () => {
    expect(html).toContain('id="tcb"');
    const banner = html.slice(html.indexOf('id="tcb"'), html.indexOf('</p>', html.indexOf('id="tcb"')));
    expect(banner).toMatch(/server/i);
    expect(banner).toMatch(/matching words/i);
    // Shown during the ceremony, hidden elsewhere: setChrome is the only thing that toggles it.
    expect(appSource).toContain('setHidden(this.tcb, !ceremonyVisible)');
  });

  it('the noscript notice is the declared one, verbatim, and the retracted claim stays gone', () => {
    // index.html sits outside copy.ts, which is the one file the honesty gates read, and
    // that is the hole the old sentence fell through: "It sends nothing to a server while
    // you pair" shipped in the signed v0.1.1 tag while reserveInbox() POSTs /v1/mailboxes
    // on the same button press (proven by execution; residual R19 is the honest statement).
    // A <noscript> notice cannot be rendered from copy.ts at runtime, so the pin runs the
    // other way: the claim is DECLARED in copy.ts and the markup must carry it verbatim.
    const start = html.indexOf('<noscript>');
    expect(start).toBeGreaterThan(-1);
    const block = html.slice(start, html.indexOf('</noscript>', start));
    expect(block.replace(/\s+/g, ' ')).toContain(NOSCRIPT_NOTICE);

    // The retracted claim does not come back, in any whitespace shape, anywhere in the
    // shell or the UI sources. Negative control first, so a green run means the pattern
    // is looking rather than toothless.
    const retracted = /sends\s+nothing to a server/i;
    expect(retracted.test('It sends\n            nothing to a server while you pair.')).toBe(true);
    for (const rel of ['index.html', ...uiFiles()]) {
      const source = prose(rel);
      expect(retracted.test(source), `${rel} still carries the retracted noscript claim`).toBe(
        false,
      );
    }
  });

  it('nothing claims the relay cannot link two mailboxes', () => {
    // That sentence was written once, was false, and was deleted. It does not come back.
    const forbidden = [
      /cannot tell that two mailboxes/i,
      /cannot link/i,
      /does not know who (?:is )?talk/i,
      /anonymous/i,
    ];
    // Negative control: the exact sentence that was deleted, and a comment carrying it,
    // so a green result means the rule is looking rather than that the rule is toothless.
    const deleted = 'the relay cannot tell that two mailboxes belong to people who know each other';
    expect(forbidden.some((p) => p.test(deleted))).toBe(true);
    expect(forbidden.some((p) => p.test(stripComments('x.ts', `// ${deleted}\n`)))).toBe(false);

    for (const rel of ['index.html', ...uiFiles()]) {
      const source = prose(rel);
      for (const pattern of forbidden) {
        expect(pattern.test(source), `${rel} matches ${pattern}`).toBe(false);
      }
    }
    // And the opposite is stated where a user will see it. The sentence moved out of the
    // markup and into copy.ts when messaging arrived, because it is now shown on two screens
    // (paired and conversation) and one copy of a load-bearing sentence beats two.
    const copy = readFileSync(join(UI_DIR, 'copy.ts'), 'utf8');
    expect(copy).toMatch(
      /relay that carries your messages\s+sees which mailbox is written and read, when, from which network address/,
    );
    expect(appSource).toContain('CONVERSATION_COPY.metadataNote');
    expect(html).toContain('data-role="metadata"');
    expect(html).toContain('data-role="metadata-note"');
  });

  it('the in-person requirement is stated as the reason, not as a suggestion', () => {
    expect(html).toMatch(/no network\s+path/);
    expect(html).toMatch(/Pairing over a call or a photo does\s+not give you this/);
  });

  it('every refusal tells the user what was saved, and none of them says try again', () => {
    const copy = readFileSync(join(UI_DIR, 'copy.ts'), 'utf8');
    for (const advice of matchesOf(copy, /advice:\s*\n?\s*'([^']+)'/g)) {
      expect(advice.length).toBeGreaterThan(20);
    }
    // "Try again in person" is fine; a bare "try again" over the same channel is not.
    expect(copy).not.toMatch(/\btry again\.\s*'/i);
    expect(copy).toContain('Do not retry this over a call, a photo or a screen share');
  });

  it('the paired screen offers messaging without claiming more than pairing did', () => {
    // Was "messaging is not built yet" for the whole of the pairing work package. Messaging
    // exists now, so the rule changed deliberately: the screen may offer a conversation, and
    // it must carry the slot for the sentence about what the relay sees.
    const paired = html.slice(
      html.indexOf('<template id="screen-paired">'),
      html.indexOf('</template>', html.indexOf('<template id="screen-paired">')),
    );
    expect(paired).not.toMatch(/not built yet/);
    expect(paired).toContain('data-role="message"');
    expect(paired).toContain('data-role="no-mailbox"');
    expect(paired).toContain('data-role="metadata"');
    // The button is enabled only where there is somewhere to put a message.
    expect(methodBody(appSource, 'renderPaired')).toContain('view.mailboxLinked');
    expect(methodBody(appSource, 'renderPaired')).toContain('message.disabled = true');
  });

  it('nothing tells the user nothing was lost on the path where something was', async () => {
    // A pull that dies mid body has already been deleted by the relay (delete-on-pull), so
    // the message is gone and the sender cannot resend it. The generic timeout line says
    // "Nothing was lost", which on that path is a false reassurance, and a false reassurance
    // at the moment of failure is worse than a blunt truth: it is the sentence the person
    // keeps, and it talks them out of the one step that recovers the message.
    //
    // ASSERTED ON THE RENDERED STRING, by calling the function. The previous version of this
    // test read the guard out of app.ts with a regex, and a regex is not a wall: inverting
    // the condition it was watching by one character left it green. The line the person
    // reads is decidable by execution, so it is decided by execution, which is why the
    // builder moved out of the DOM-coupled module and into copy.ts.
    const { syncSummary, interruptedPullMessage, relayFailureMessage } = await import(
      '../src/ui/copy.js'
    );
    const { RelayError } = await import('../src/relay-client.js');
    const flush = (over: Partial<FlushReport> = {}): FlushReport => ({
      relayed: 0,
      queued: 0,
      stuck: 0,
      failure: undefined,
      ...over,
    });
    const receive = (over: Partial<ReceiveReport> = {}): ReceiveReport => ({
      listed: 0,
      accepted: 0,
      vanished: 0,
      unopenable: 0,
      duplicate: 0,
      stale: 0,
      defective: 0,
      unread: 0,
      interrupted: 0,
      failure: undefined,
      ...over,
    });
    const timedOut = () => new RelayError('timeout', 'relay: no answer inside the deadline');

    // 1. THE FALSE REASSURANCE, which is the case this whole rule exists for: the receive
    // half timed out with a pull in flight. The generic line is gone and the blunt one is
    // there, and the WHOLE string is pinned, so inverting the guard fails here.
    const lostOne = syncSummary({
      flush: flush(),
      receive: receive({ listed: 1, interrupted: 1, failure: timedOut() }),
    });
    expect(lostOne).toBe(`0 new messages. ${interruptedPullMessage()}`);
    expect(lostOne).not.toMatch(/Nothing was lost/);

    // 2. THE BENIGN TIMEOUT, which is the reason the line is not simply deleted: a pass that
    // timed out with nothing in flight destroyed nothing, and saying so is true and useful.
    const benign = syncSummary({
      flush: flush(),
      receive: receive({ listed: 2, unread: 2, failure: timedOut() }),
    });
    expect(benign).toBe(
      `0 new messages. 2 still waiting at the relay. ${relayFailureMessage('timeout')}`,
    );
    expect(benign).toContain('Nothing was lost');
    expect(benign).not.toContain('may be gone');

    // 3. THE COMBINED LINE, joined as sentences. Every other transport line names something
    // specific the loss sentence does not cover, so it is kept and the loss sentence is
    // added to it. One stop between the two, not two.
    const both = syncSummary({
      flush: flush(),
      receive: receive({ listed: 1, interrupted: 1, failure: new RelayError('network', 'x') }),
    });
    expect(both).toBe(
      `0 new messages. ${relayFailureMessage('network')} ${interruptedPullMessage()}`,
    );
    expect(both).toContain('refused to follow. A message was being collected');
    expect(both).not.toContain('..');

    // 4. THE PHASE DECIDES, and this is the pair that pins it. A FLUSH timeout left its
    // record queued and re-offered, so "nothing was lost" is true of the send half and it
    // stands even while the receive half reports a loss: two sentences about two different
    // halves of one refresh. Suppressing it here was suppressing a true sentence for the
    // wrong reason, and this case is the only one that tells the two rules apart.
    const sendTimedOut = syncSummary({
      flush: flush({ queued: 2, failure: timedOut() }),
      receive: receive({ listed: 1, interrupted: 1, failure: timedOut() }),
    });
    expect(sendTimedOut).toBe(
      `2 still queued here. 0 new messages. ${relayFailureMessage('timeout')} ` +
        `${interruptedPullMessage()}`,
    );

    // 5. The ordinary refresh, so the shape of a healthy line is pinned too.
    expect(syncSummary({ flush: flush({ relayed: 1 }), receive: receive({ accepted: 1 }) })).toBe(
      '1 handed to the relay. 1 new message.',
    );

    // And the screen is what calls it: a builder nothing renders would pass every assertion
    // above while the conversation kept its own copy.
    expect(appSource).toContain('syncSummary(await messaging.sync(peerId))');
    expect(appSource).not.toContain('function describeSync');

    // Negative control: the wording that must not be what an interrupted pull prints. Both
    // sentences exist in copy.ts, so a test that only checked "the file mentions loss" would
    // pass with the branch deleted; the rendered strings above are the load-bearing part.
    const copy = readFileSync(join(UI_DIR, 'copy.ts'), 'utf8');
    expect(copy).toContain('Nothing was lost');
    expect(braceBody(copy, 'export function interruptedPullMessage(')).not.toMatch(
      /nothing was lost/i,
    );
  });

  it('nothing in the messaging copy says a message was delivered', () => {
    // R9: delete-on-pull is at-most-once and v0 has no acknowledgement, so "the relay took
    // it" is the last true thing this device knows. A screen that says "Delivered" or "Read"
    // is claiming something no code here can observe.
    const copy = readFileSync(join(UI_DIR, 'copy.ts'), 'utf8');
    const forbidden = [/\bdelivered\b/i, /\bread receipt/i, /\bseen by\b/i, /\bdelivery confirmed/i];
    // Negative control: the wording that is banned, so a pass means the rule is looking.
    expect(forbidden.some((p) => p.test('Delivered to their device'))).toBe(true);
    for (const rel of ['index.html', ...uiFiles()]) {
      const source = prose(rel);
      for (const pattern of forbidden) {
        expect(pattern.test(source), `${rel} matches ${pattern}`).toBe(false);
      }
    }
    // And the honest sentence is present, in the copy and on the screen.
    expect(copy).toContain('Handed to the relay means the relay accepted the bytes');
    expect(html).toContain('data-role="delivery-note"');
  });

  it('a message the relay held back is never rendered as ordinary read history', () => {
    // The thread sorts on the sender's authenticated clock, so a blob the relay withheld
    // and released later lands wherever the sender wrote it, above everything already
    // read. Left inside a neighbouring run it would print nothing at all, because only the
    // last message of a run prints a meta line. Both halves are checked: its own run, and
    // a meta line that names the arrival as well as the claimed send time.
    const thread = braceBody(appSource, 'function renderThread(');
    for (const edge of ['startsRun', 'endsRun']) {
      const rule = thread.slice(thread.indexOf(`const ${edge} =`));
      expect(rule.slice(0, rule.indexOf(';')), `${edge} ignores a held-back message`).toContain(
        'heldBack(',
      );
    }
    const meta = braceBody(appSource, 'function metaFor(');
    expect(meta).toContain('heldBack(record)');
    expect(meta).toMatch(/Reached this device at/);
    // And the fact it reads is the LOCAL one, not another sender-supplied number.
    expect(braceBody(appSource, 'function heldBack(')).toContain('record.receivedAtMs');
    // Negative control: the rule is looking at the grouping, not at the whole file.
    expect(thread.includes('heldBack(')).toBe(true);
    expect(braceBody(appSource, 'function clockOf(').includes('heldBack(')).toBe(false);
  });

  it('the conversation screen states the forward-secrecy limit where it applies', () => {
    // R4: v0 seals with long term keys, so a later key compromise reads past messages. The
    // one screen where that matters is the one holding the messages.
    const copy = readFileSync(join(UI_DIR, 'copy.ts'), 'utf8');
    expect(copy).toMatch(/seals with long term keys/);
    expect(html).toContain('data-role="forward-note"');
    expect(appSource).toContain('CONVERSATION_COPY.forwardSecrecyNote');
  });

  it('messaging is a poll on a visible screen, with no background machinery', () => {
    // secondsys, and a privacy property: a service worker or a push subscription would keep
    // fetching a mailbox after the tab is gone, which is traffic the relay sees and the
    // person does not.
    for (const rel of uiFiles()) {
      const source = readFileSync(join(CLIENT_DIR, rel), 'utf8');
      for (const banned of ['serviceWorker', 'Notification', 'pushManager', 'showNotification']) {
        expect(source.includes(banned), `${rel} reaches for ${banned}`).toBe(false);
      }
    }
    // The poll is cleared by the one function every screen change goes through, so the lock
    // path and the refusal path get it for free.
    expect(methodBody(appSource, 'show')).toContain('this.stopPolling()');
  });
});

describe('the idle re-lock reaches the screens', () => {
  // session.ts empties the vault on a timer whatever screen is up. The screens are what
  // has to notice: without this wiring the ready screen keeps two buttons that throw into
  // a promise nobody holds, and the scan screen keeps the camera running behind a frozen
  // count, which is the privacy failure and not merely a dead button.
  it('both ways into a session install the lock callback', () => {
    expect(appSource).toMatch(/const opts = \{ onLock: \(\) => this\.onLock\(\) \}/);
    for (const entry of ['createIdentity', 'unlock']) {
      const call = new RegExp(`KeyweaveSession\\.${entry}\\(([\\s\\S]*?)\\n\\s*\\)`).exec(
        appSource,
      );
      expect(call, `no KeyweaveSession.${entry} call`).not.toBeNull();
      expect(call![1], `${entry} is opened without the lock callback`).toContain('opts');
    }
  });

  it('the lock reaction releases the camera and says which thing happened', () => {
    const body = methodBody(appSource, 'onLock');
    expect(body).toContain('this.teardownOptics()');
    expect(body).toContain('this.ceremony = undefined');
    expect(body).toContain('lockNotice(');
    // A screen with the lock notice on it, not the ceremony chrome.
    expect(body).toContain('this.renderUnlock(');
  });

  it('nothing awaits the ceremony without a catch, because both callers discard it', () => {
    // `void this.beginCeremony(...)` and `void this.offerPayload(...)`: an unguarded
    // rejection there changes no screen and tears nothing down.
    for (const name of ['beginCeremony', 'offerPayload']) {
      const body = methodBody(appSource, name);
      expect(body, `${name} has no catch`).toMatch(/catch \(error\)/);
      expect(body, `${name} does not route the failure`).toContain('this.failCeremony(');
    }
    const fail = methodBody(appSource, 'failCeremony');
    expect(fail).toContain('this.teardownOptics()');
    expect(fail).toContain('this.locked()');
  });

  it('a lock at the compare screen is not reported as a storage failure', () => {
    // "writing the vault back to this browser failed" with advice about private windows is
    // the wrong sentence for a lock, in the one product whose premise is honest screens.
    const body = methodBody(appSource, 'confirmMatch');
    const lock = body.indexOf('this.onLock()');
    const write = body.indexOf('this.renderWriteFailure(');
    expect(lock).toBeGreaterThan(-1);
    expect(write).toBeGreaterThan(-1);
    expect(lock, 'the storage failure is reached before the lock is ruled out').toBeLessThan(
      write,
    );
  });

  it('the lock notice names the duration the constant actually enforces', async () => {
    const { IDLE_LOCK_MS } = await import('../src/ui/session.js');
    const { lockNotice } = await import('../src/ui/copy.js');
    expect(lockNotice(Math.round(IDLE_LOCK_MS / 60_000))).toContain('5 minutes');
    expect(lockNotice(5)).toMatch(/passphrase is forgotten/);
    expect(lockNotice(5)).toMatch(/camera released/);
    expect(lockNotice(5)).toMatch(/Nothing was saved/);
  });

  it('the lock notice is true on every screen it can appear on, not only in a ceremony', async () => {
    // ONE STRING, EVERY SCREEN. onLock renders this from a timer under whatever is up, so a
    // clause that is only true of the ceremony is a false clause on the conversation screen,
    // and the four assertions above are all satisfied by wording that is. Residual R17 is
    // where the exception this corrects is declared; these are its shipped-copy half.
    const { lockNotice } = await import('../src/ui/copy.js');
    const notice = lockNotice(5);

    // The timer measures time since the last unlocked READ of the vault, not since the
    // person last did anything: it can expire while a refresh is stalled on the relay,
    // which is exactly the window in which a conversation screen reaches this notice.
    expect(notice).not.toMatch(/nothing happening/);
    expect(notice).toMatch(/nothing on this device reading the keys/);

    // "Nothing was saved" as its own sentence is true of a dropped pairing and false of a
    // conversation, whose outbound messages are sealed and WRITTEN before the relay is
    // called. It is scoped to the pairing, and what survives is said out loud rather than
    // left for the reader to doubt.
    expect(notice).toMatch(/dropped and the camera released\. Nothing was saved from it\./);

    // SENT, and deliberately not "sent or collected". An outbound message is sealed and
    // written before the relay call, so "sent" survives a lock. INBOUND does not: receive()
    // makes accepted messages durable at a single persist() AFTER its loop, so a lock landing
    // mid pass loses everything that pass had collected, and the relay has already deleted
    // those blobs. Residual R18. This notice is rendered in exactly that situation, so the
    // earlier wording made the product's own lock screen assert the thing that was untrue.
    expect(notice).toMatch(/Messages you had already sent are still on this device/);
    expect(notice).not.toMatch(/collected are still on this device/);
  });
});

describe('every hook app.ts reaches for exists in the markup', () => {
  const templateIds = matchesOf(html, /<template\s+id="([^"]+)"/g);
  const dataRoles = new Set(matchesOf(html, /data-role="([^"]+)"/g));
  const elementIds = new Set(matchesOf(html, /\sid="([^"]+)"/g));

  it('finds the markup it is supposed to be checking', () => {
    expect(templateIds.length).toBeGreaterThanOrEqual(7);
    expect(dataRoles.size).toBeGreaterThan(20);
  });

  it('every cloneScreen id is a template', () => {
    const used = matchesOf(appSource, /cloneScreen\('([^']+)'\)/g);
    expect(used.length).toBeGreaterThanOrEqual(7);
    for (const id of used) expect(templateIds, `no <template id="${id}">`).toContain(id);
  });

  it('every data-role app.ts looks up is present', () => {
    // Any root, not only `fragment`: the contact and message rows are cloned per item and
    // look their hooks up on the row, and a rule that only read `fragment` would have gone
    // quiet on exactly the markup that is generated rather than written once.
    const used = matchesOf(appSource, /\brole<[^>]+>\(\s*[A-Za-z_$][\w$]*,\s*'([^']+)'/g);
    expect(used.length).toBeGreaterThan(20);
    for (const name of used) {
      expect(dataRoles.has(name), `no [data-role="${name}"] in index.html`).toBe(true);
    }
  });

  it('every element id app.ts looks up is present', () => {
    const byIds = matchesOf(appSource, /byId<[^>]+>\('([^']+)'\)/g);
    const selectors = matchesOf(appSource, /querySelector<[^>]+>\('#([^']+)'\)/g);
    expect(byIds.length).toBeGreaterThanOrEqual(4);
    for (const id of [...byIds, ...selectors]) {
      expect(elementIds.has(id), `no #${id} in index.html`).toBe(true);
    }
  });

  it('no template is orphaned', () => {
    const used = new Set(matchesOf(appSource, /cloneScreen\('([^']+)'\)/g));
    const orphans = templateIds.filter((id) => !used.has(id));
    expect(orphans, 'a screen template nothing renders').toEqual([]);
  });
});

describe('the passphrase hint says only what it knows', () => {
  it('refuses a short passphrase for a new vault', () => {
    const short = passphraseHint('a'.repeat(MIN_PASSPHRASE_LENGTH - 1));
    expect(short.acceptable).toBe(false);
    expect(short.level).toBe('too-short');
  });

  it('accepts at the floor and grades on length, never on guessability', () => {
    expect(passphraseHint('a'.repeat(MIN_PASSPHRASE_LENGTH)).acceptable).toBe(true);
    expect(passphraseHint('Password123!').acceptable).toBe(true);
    // The point: it does not call an obvious passphrase strong.
    expect(passphraseHint('Password123!').detail).toMatch(/not a measure of how hard/);
    expect(passphraseHint('correct horse battery staple extra').level).toBe('good');
    expect(passphraseHint('correct horse battery staple extra').detail).toMatch(
      /line from a song/,
    );
  });

  it('counts code points, so an accented character counts once', () => {
    expect(passphraseHint('é'.repeat(6)).label).toContain('12 characters');
  });
});
