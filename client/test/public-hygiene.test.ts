// Public-hygiene gates. Keyweave is a public repository under a real identity, and these
// are the house rules that are cheap to enforce and expensive to notice by eye.
//
// U+2014 (em dash): banned in everything Keyweave AUTHORS. It reads as an AI tell, and a
// sweep at publish time is the wrong moment to discover 90 of them. Enforced here instead
// of by a shell gate so it fails in the same command as everything else.
//
// client/vendor/** is EXEMPT and that exemption is load-bearing, not laziness: those files
// carry someone else's copyright, their comments are the most valuable part of what was
// vendored, and rewriting third-party prose to satisfy our own style heuristic is a worse
// trade than an exemption a reviewer can see. The test asserts the exemption still has
// something in it, so silently rewriting the vendored comments also fails.
//
// Forbidden identifiers (the fourth rule, added after the fact): names that belong to the
// machines this project is built on and not to the project. See the block above that rule
// for why it is written as shapes rather than as a list of names, and the block after it for
// the part of that problem this file does not and cannot solve.
//
// Unfilled placeholders (the fifth rule): fill-in-later markers left in published markdown.
// The one that prompted it sat in the verification section of a security document, where an
// instruction nobody can follow is worse than an absent one, because the reader believes
// they checked something.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage', '.claude']);
const TEXT_EXT = /\.(ts|js|mjs|cjs|json|md|py|sh|conf|service|html|css|txt|yml|yaml)$/;

// Third-party text we carry verbatim. Nothing outside this list is exempt.
const VENDOR_PREFIXES = ['client/vendor/', 'LICENSES/'];
// Machine-generated or upstream-sourced files we do not hand-edit.
const GENERATED = new Set(['client/package-lock.json', 'client/src/bip39-english.ts', 'LICENSE']);

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const abs = join(dir, name);
    if (statSync(abs).isDirectory()) walk(abs, out);
    else if (TEXT_EXT.test(name)) out.push(relative(REPO_ROOT, abs));
  }
  return out;
}

const isVendored = (rel: string) => VENDOR_PREFIXES.some((p) => rel.startsWith(p));

// Built from the code point, never written literally: a gate whose own source contains the
// character it bans has to exempt itself, and a self-exempting gate is one edit away from
// being no gate at all. This way the scan covers this file too.
const EM_DASH = String.fromCharCode(0x2014);
const countEmDashes = (source: string) => source.split(EM_DASH).length - 1;

// ---------------------------------------------------------------------------------------
// FORBIDDEN IDENTIFIERS.
//
// This rule exists because it was missing. Five lines naming the build machine's numeric
// user id passed 543 green tests and were published. The three rules above would have
// caught a stray em dash or the word "unhackable" in those same lines; nothing read what
// they actually said. As shipped, the gate banned an adjective and permitted a machine.
//
// TWO THINGS THIS RULE DELIBERATELY DOES NOT DO.
//
// It carries no list of the real host names, accounts or addresses it is meant to keep out.
// This file is published. A list of private names IS the leak, whether it is spelled in
// plain text or hidden in code points, and it goes stale the day a machine is renamed. Each
// rule below is a SHAPE instead: a numeric user id, an address in a range that cannot be
// routed on the public internet, a machine named after its platform, a mail address at a
// domain that is not reserved for documentation. A shape catches the name nobody listed.
//
// It does not honour the vendor exemption above. That exemption is about third-party PROSE
// STYLE, and no part of that reasoning says an upstream file may name this build host.
// Generated files are skipped, for an unrelated reason stated at the scan itself.
//
// Every sample below is assembled at run time from pieces. The scan covers this file, so a
// sample written out whole would be reported by the rule it belongs to, and the usual repair
// for that is an exemption for this file, which is how a gate stops being one.
//
// WHAT THIS GATE COVERS IS A NAMED SUBSET, AND THE REST IS STILL A HUMAN'S JOB.
//
// The shapes below were measured against the real sanitization pass that moved this project
// out of a private tree, and they cover one part of it: the numeric user id, the host named
// after its platform, the unroutable address, the suffix that only resolves inside somebody's
// network, the personal mail address. Five other things that same pass had to remove BY HAND
// are invisible here, and they are missing because they cannot be written as rules, not
// because nobody got to them yet. None of them has a shape:
//
//   * a public IP address, which is indistinguishable from any other public IP address
//   * an internal workflow or ticket id from a private tracker
//   * commit ids belonging to the private history this repository was extracted from
//   * the names of models and of internal work lanes
//   * internal role and process vocabulary that only means anything inside that estate
//
// A regular expression cannot separate any of those from legitimate content, and one written
// to try would flag enough ordinary prose to be switched off by the first person it annoyed.
// So this file is a floor and not a clearance. READING THE WHOLE TRANSFER DIFF BEFORE
// PUBLISHING REMAINS A REQUIRED STEP, and a green run here does not stand in for it. The
// failure this paragraph exists to prevent is the ordinary one: a gate appears, the manual
// read quietly stops happening, and the five classes above go out on the next extract with
// nothing at all looking at them.
// ---------------------------------------------------------------------------------------

type Hit = { match: string; index: number };
type IdRule = { what: string; sample: string; find: (text: string) => Hit | null };

const reRule = (what: string, re: RegExp, sample: string): IdRule => ({
  what,
  sample,
  find: (text) => {
    const m = re.exec(text);
    return m ? { match: m[0], index: m.index } : null;
  },
});

// Assembled from a part rather than written as one literal, so that the whole rule fits on a
// line somebody will read. All four octets are required in each branch.
const OCT = '[0-9]{1,3}';
const PRIVATE_V4 = new RegExp(
  `\\b(?:(?:10|100)\\.${OCT}|192\\.168|172\\.(?:1[6-9]|2[0-9]|3[01]))\\.${OCT}\\.${OCT}\\b`,
);

// A mail address is read as a person unless its domain cannot belong to one: the domains
// RFC 2606 reserves for documentation, this project's own public domain, and the hostile
// placeholder the URL-parsing fixtures use as the counterparty. Everything else is somebody,
// including the account-derived addresses git writes into a commit without being asked.
const MAIL = /[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}/g;
const IMPERSONAL_DOMAIN =
  /(?:^|\.)(?:example|invalid|test|localhost|example\.(?:com|net|org)|localfirstlab\.org|evil\.net)$/;

const FORBIDDEN: IdRule[] = [
  // The estate's private work ledger numbers its items with a severity letter and an index.
  // Narrow on purpose: widening it to the neighbouring letters would flag hardware names
  // such as an Apple M-series chip, and a rule people learn to override is worth less than a
  // rule with a stated edge.
  reRule('an internal ledger id', /\bH[0-9]{1,2}\b/, 'H' + '1'),

  reRule('a numeric user id', /\buid[ _]?[0-9]+\b/i, 'uid' + '1000'),

  // A host named after its platform. Kept to platform words so that ordinary hyphenated
  // prose (sealed-box, store-and-forward, relay-host) does not trip it. Known edge: written
  // in lower case, encrypt-then-MAC matches. Spell that primitive in capitals rather than
  // loosening this.
  reRule(
    'a machine name',
    /\b[a-z][a-z0-9]*-(ubuntu|debian|fedora|nixos|nas|mac|laptop|desktop|vps|pi|lab)\b/,
    'some' + '-ubuntu',
  ),

  // Addresses that cannot be routed on the public internet, so one of them in a document is
  // describing somebody's own network. Demanding four octets is what keeps this off the npm
  // version this project pins. The loopback address is deliberately absent: the relay binds
  // to it and the deploy notes quote it correctly.
  reRule('a private network address', PRIVATE_V4, '10.' + '0.0.18'),

  // Suffixes that only resolve inside somebody's own network.
  reRule(
    'an internal DNS suffix',
    /\.(?:local|lan|internal|home\.arpa|ts\.net)\b/,
    '.' + 'internal',
  ),

  {
    what: 'a personal mail address',
    sample: 'person' + '@' + 'somewhere.tld',
    find: (text) => {
      for (const m of text.matchAll(MAIL)) {
        const domain = m[0].slice(m[0].lastIndexOf('@') + 1).toLowerCase();
        if (!IMPERSONAL_DOMAIN.test(domain)) return { match: m[0], index: m.index };
      }
      return null;
    },
  },
];

// ---------------------------------------------------------------------------------------
// UNFILLED PLACEHOLDERS.
//
// A fill-in-later marker is invisible to every other rule here. Three of them sat in the
// verification section of docs/REPRODUCIBLE-BUILD.md through a fully green suite: the
// signing key fingerprint and, twice, the URL the key is fetched from. Published in that
// state the section still reads as instructions, so a verifier follows it, cannot complete
// it, and has no way to tell an unfinished document from one they have misread.
//
// SCOPED TO MARKDOWN, on purpose. Prose is where fill-in markers live. The same shape in a
// .ts file is a generic type parameter, so widening this rule would make it the one people
// switch off, and a rule with a stated edge is worth more than a rule people override.
//
// ALL-CAPS ONLY, also on purpose. The docs are full of ordinary metavariables (a tag, a ref,
// an address, an app origin, a value quoted from a release body) and not one of them is an
// unfinished edit. Restricting the shape to capitals is what separates "the author means any
// value here" from "the author meant to come back to this".
// ---------------------------------------------------------------------------------------

// Assembled from pieces for the same reason the em dash above is, and built fresh at each
// use so no lastIndex is carried between scans. This file is markdown-exempt only because of
// its extension; nothing here would need an exemption if the scope were ever widened.
const PLACEHOLDER_SRC = '<' + '[A-Z][A-Z0-9-]{2,}' + '>';
const findPlaceholders = (text: string) => [...text.matchAll(new RegExp(PLACEHOLDER_SRC, 'g'))];

// Tokens in that shape which are NOT unfinished edits, each pinned to the file that needs
// it. Pinned rather than blanket, so the same spelling appearing anywhere else is still
// caught, and asserted live below, so an exemption cannot outlive the thing it excuses.
const PLACEHOLDER_EXEMPT: { file: string; token: string; why: string }[] = [
  {
    file: 'docs/DEPLOY.md',
    token: '<' + 'HOST' + '>',
    why: "fail2ban's own required macro inside a failregex; filling it in breaks the filter",
  },
];

const lineOf = (text: string, index: number) => text.slice(0, index).split('\n').length;

describe('public hygiene', () => {
  const files = walk(REPO_ROOT);

  it('finds the tree it is supposed to be scanning', () => {
    expect(files.length).toBeGreaterThan(30);
    expect(files).toContain('client/src/optical.ts');
    expect(files).toContain('docs/NAMED-RESIDUALS.md');
    expect(files).toContain('relay/keyweave_relay.py');
  });

  it('no U+2014 em dash in anything Keyweave authors', () => {
    const offenders: string[] = [];
    for (const rel of files) {
      if (isVendored(rel) || GENERATED.has(rel)) continue;
      const count = countEmDashes(readFileSync(join(REPO_ROOT, rel), 'utf8'));
      if (count) offenders.push(`${rel} (${count})`);
    }
    expect(offenders).toEqual([]);
  });

  it('the vendor exemption is a real exemption, not an empty one', () => {
    // If this drops to zero, someone rewrote upstream comments to satisfy the rule above.
    // That is the outcome the exemption exists to prevent, so it fails here rather than
    // passing quietly.
    let vendored = 0;
    for (const rel of files) {
      if (!isVendored(rel)) continue;
      vendored += countEmDashes(readFileSync(join(REPO_ROOT, rel), 'utf8'));
    }
    expect(vendored).toBeGreaterThan(0);
  });

  it('no marketing-claim words in prose', () => {
    // Honest-claims framing. A security product that says "unbreakable" has told you
    // something about its authors, not its cryptography.
    const BANNED = /\b(unbreakable|military[- ]grade|bank[- ]grade|NSA[- ]proof|100% secure|unhackable)\b/i;
    const offenders: string[] = [];
    for (const rel of files) {
      if (isVendored(rel) || GENERATED.has(rel)) continue;
      // The rule names its own banned words; scanning this file would always match.
      if (rel === 'client/test/public-hygiene.test.ts') continue;
      const m = BANNED.exec(readFileSync(join(REPO_ROOT, rel), 'utf8'));
      if (m) offenders.push(`${rel}: ${m[0]}`);
    }
    expect(offenders).toEqual([]);
  });

  it('the forbidden-identifier rules are live, and none of them is a dragnet', () => {
    // Two failures this closes, and both have happened to gates elsewhere. A rule list that
    // quietly empties out reports nothing and reads as clean, which is why the count is
    // asserted and why every rule has to demonstrate a match. And a rule broad enough to
    // flag ordinary text gets switched off by the first person it annoys, which is why the
    // benign column is here: these are strings this repository legitimately contains.
    expect(FORBIDDEN.length).toBeGreaterThan(4);
    for (const rule of FORBIDDEN) {
      expect(rule.find(rule.sample), `${rule.what}: its own sample`).not.toBeNull();
    }

    const BENIGN = [
      'R1 and R18 are residual ids, not ledger ids',
      'a sealed-box over a store-and-forward relay-host',
      'encrypt-then-MAC',
      'bind_host = 127.0.0.1',
      'node v22.22.1 and npm 10.9.4',
      'the documentation range 203.0.113.10',
      'a@b.example and pw@relay.example',
      'https://relay.keyweave.localfirstlab.org',
    ];
    for (const rule of FORBIDDEN) {
      for (const ok of BENIGN) {
        expect(rule.find(ok), `${rule.what} matched ${ok}`).toBeNull();
      }
    }
  });

  it('no forbidden identifiers in anything this repository publishes', () => {
    // The walk is the other way this passes over nothing and calls it clean: if the file
    // list stops matching, an empty offender list means "read nothing", which is
    // indistinguishable from "found nothing". Every line this rule was written for was in
    // docs/ and none was in client/, so both ends of the tree are named here.
    expect(files.filter((rel) => rel.startsWith('docs/')).length).toBeGreaterThan(4);
    expect(files).toContain('README.md');
    expect(files).toContain('scripts/reproduce.sh');
    expect(files).toContain('client/test/public-hygiene.test.ts');

    const offenders: string[] = [];
    for (const rel of files) {
      // Generated files are skipped, and NOT for the vendor reason: client/package-lock.json
      // is a wall of base64 integrity hashes, where a two-character pattern matches noise
      // sooner or later. Nothing hand-writes those files, so nothing hand-writes a machine
      // name into one. client/vendor/** is scanned.
      if (GENERATED.has(rel)) continue;
      const text = readFileSync(join(REPO_ROOT, rel), 'utf8');
      for (const rule of FORBIDDEN) {
        const hit = rule.find(text);
        if (hit) offenders.push(`${rel}:${lineOf(text, hit.index)} ${rule.what}: ${hit.match}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('the placeholder rule is live, and it leaves prose metavariables alone', () => {
    // Split from the scan below for the reason the forbidden-identifier pair is split: the
    // runner stops at the first failing assertion, so a rule that has quietly stopped
    // matching anything has to fail here rather than turning the scan into a clean report of
    // a file it never really read.
    expect(findPlaceholders('<' + 'FINGERPRINT' + '>').length, 'its own sample').toBe(1);
    expect(findPlaceholders('<' + 'KEY-URL' + '>').length, 'a hyphenated sample').toBe(1);

    // Strings this repository's documentation legitimately contains.
    const BENIGN = [
      'checkout <tag> and build it',
      'AUTHFAIL client=<ip> method=GET',
      'the <meta> CSP in the built page',
      'served from <app-origin> with no third party',
      'pass the <value from the release body>',
      'a same-origin relay at <origin>',
      'const seen = new Map<K, V>();',
    ];
    for (const ok of BENIGN) {
      expect(findPlaceholders(ok), `placeholder rule matched ${ok}`).toEqual([]);
    }

    // An exemption that has outlived its cause is a permanent hole in the shape of a comment.
    // If one of these fails, delete the entry rather than re-pointing it at something else.
    for (const e of PLACEHOLDER_EXEMPT) {
      expect(files, `exempted file is gone: ${e.file} (${e.why})`).toContain(e.file);
      const text = readFileSync(join(REPO_ROOT, e.file), 'utf8');
      expect(text.includes(e.token), `${e.file} no longer contains its exempted token`).toBe(true);
    }
  });

  it('no unfilled placeholder in the published markdown', () => {
    const docs = files.filter((rel) => rel.endsWith('.md'));
    // Same guard as the walk assertions above: an empty offender list has to mean "found
    // nothing", never "read nothing", and the document this rule was written for is named.
    expect(docs.length).toBeGreaterThan(4);
    expect(docs).toContain('docs/REPRODUCIBLE-BUILD.md');
    expect(docs).toContain('README.md');

    const offenders: string[] = [];
    for (const rel of docs) {
      if (isVendored(rel) || GENERATED.has(rel)) continue;
      const text = readFileSync(join(REPO_ROOT, rel), 'utf8');
      for (const m of findPlaceholders(text)) {
        if (PLACEHOLDER_EXEMPT.some((e) => e.file === rel && e.token === m[0])) continue;
        offenders.push(`${rel}:${lineOf(text, m.index)} ${m[0]}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
