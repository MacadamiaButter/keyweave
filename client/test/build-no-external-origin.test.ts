// R13 CLOSURE, half two: the build-time assertion.
//
// zxing-wasm compiles a jsdelivr CDN into its default `locateFile`. The vendored decode
// worker overrides that before the first decode, so nothing reaches the CDN at runtime
// today, but a string in the bundle is one library upgrade or one reordered init away from
// turning a pairing ceremony into a third-party fetch. That failure is silent, which is
// exactly why it is asserted here rather than trusted to a code comment.
//
// HOW IT RUNS: this file SHELLS `npm run build` and scans what it emits. It is a vitest
// test, not a separate `npm run gate`, so a plain `npm test` cannot miss it and no pipeline
// configuration has to remember it. (`npm run gate` exists too and is just typecheck plus
// this suite.) The scan reads every emitted byte, binaries included, in latin1 so a wasm
// blob is searched as bytes rather than being skipped for not being text.
//
// IT DOES NOT BUILD INTO dist/, AND THAT IS A SECURITY PROPERTY, not tidiness. It used to.
// Because the last configuration this file builds is the SPLIT one, `npm test` left behind
// a complete, deployable-looking client/dist wired to `https://relay.keyweave.example`, a
// host nobody owns. Measured in the repository after a plain test run:
//
//     grep -oE "https?://[A-Za-z0-9.*_-]+" client/dist/index.html
//         -> https://relay.keyweave.example
//
// Build, then test, then upload dist/ and you have shipped a client whose CSP permits and
// whose RelayClient targets an origin that does not exist: every send is a network error
// with no explanation, and if anyone ever registers that name it stops being merely silent.
// So each configuration is built into its own directory under os.tmpdir() with vite's
// --outDir, scanned there, and removed. dist/ is the developer's, and the last test here
// proves this run did not touch it. Verified byte-identical: an --outDir build of the same
// configuration produces the same index.html sha256 as a dist/ build.
//
// WHAT CHANGED WITH THE SPLIT RELAY (residual R2, work package 7). The rule used to be
// "zero http(s) origins in dist/". A deployment with the relay on its own origin puts that
// one origin in the bundle legitimately, so the rule is now:
//
//     no origin OTHER than the one this build was configured with, and that one by EXACT
//     STRING EQUALITY.
//
// It is deliberately NOT `hit.startsWith(configuredOrigin)`, and that is not pedantry: a
// prefix rule accepts `https://relay.example.com.evil.net/` for a configured origin of
// `https://relay.example.com`, which is precisely the substitution this gate exists to
// catch. Each hit therefore has its FULL origin extracted (scheme, host, optional port,
// terminated by `/`, a quote, whitespace, a backtick or end of input) and compared with
// `===`.
//
// defdepth: this scan stays an INDEPENDENT wall. It does not import build-config.mjs. The
// expected default policy is a hardcoded literal here, and the expected split policy is
// that literal with one substitution, so a mistake in the generator cannot also rewrite the
// oracle that is supposed to catch it. Whether the generator agrees with the DOCUMENT is a
// different question and is asked in test/deploy-csp-verifier.test.ts.
//
// THE RESULT for the default build: zero. Stripping was possible, so this is an absolute
// assertion and not a list of known-benign occurrences. Two came up while writing it and
// both were fixed at the source rather than exempted:
//   - the jsdelivr default, rewritten to a same-origin path that cannot resolve, by
//     vite.config.ts. The first attempt reported success while shipping the URL, because
//     a production worker bundle is a separate rollup build that does not inherit
//     `plugins`; that is what makes the DIST SCAN, not the plugin, the actual gate.
//   - `http://www.w3.org/2000/svg`, dragged in by qrcode's SVG renderer through the
//     package entry. An XML namespace is never fetched, but a rule with no exceptions is
//     worth more than a rule with one explained exception, so the import moved to
//     qrcode's core module and the string went away.

import { describe, it, expect, afterAll, beforeAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLIENT_DIR = fileURLToPath(new URL('..', import.meta.url));

/** The developer's own build output. This suite READS its hash and never writes it. */
const DIST = join(CLIENT_DIR, 'dist');

/**
 * Where this suite's builds actually go. Outside the repository on purpose: a scratch
 * directory inside it would need a .gitignore entry, and an entry there is one edit away
 * from a scratch build being mistaken for a release artifact.
 */
const SCRATCH = mkdtempSync(join(tmpdir(), 'keyweave-distscan-'));

afterAll(() => {
  rmSync(SCRATCH, { recursive: true, force: true });
});

/** The env var that chooses the topology. One value; see client/build-config.mjs. */
const RELAY_ORIGIN_ENV = 'KEYWEAVE_RELAY_ORIGIN';

/**
 * The default policy, hardcoded. This is the string Keyweave shipped before the relay
 * origin was configurable, and the default build must stay byte-identical to it.
 * docs/DEPLOY-CSP.md publishes the same value.
 */
const EXPECTED_DEFAULT_CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; " +
  "connect-src 'self'; img-src 'self'; media-src 'self' mediastream:; style-src 'self'; " +
  "font-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/** A host nobody owns, so a build that leaks it into a commit is obvious. */
const TEST_ORIGIN = 'https://relay.keyweave.example';

/**
 * The split-origin policy, derived from the literal above by the ONE substitution the
 * feature is allowed to make. leastpriv: `connect-src` grows by exactly one origin, and
 * every other directive is untouched. Writing it this way means an extra source, a widened
 * `script-src` or a dropped `frame-ancestors` all fail this test.
 */
const EXPECTED_SPLIT_CSP = EXPECTED_DEFAULT_CSP.replace(
  "connect-src 'self';",
  `connect-src 'self' ${TEST_ORIGIN};`,
);

/**
 * Every `http://` or `https://` in the bytes, with the whole authority that follows it. The
 * match ENDS at the first `/`, quote, backtick, whitespace, backslash or angle bracket,
 * which is what makes the comparison below an origin comparison rather than a prefix test.
 *
 * `@` AND `%` ARE IN THE CLASS DELIBERATELY, and leaving them out was a real hole. Without
 * `@`, a compiled-in `https://relay.keyweave.example@evil.net/` extracted as
 * `https://relay.keyweave.example`, compared EQUAL to the configured origin, and was
 * filtered out as benign. The host a browser actually connects to there is `evil.net`: the
 * part before the `@` is userinfo. That is the same substitution the exact-match rule was
 * written to catch, one syntax further along. `%` is in for the same reason one step more
 * obscure: a percent escape in the authority can spell a host that does not look like
 * itself.
 *
 * Including them costs nothing, because a CONFIGURED origin can never contain either.
 * build-config.mjs rejects `https://a@b.example` as carrying credentials and rejects a
 * percent escape because the parser decodes it and the value stops being byte-identical to
 * its own origin. So the rule stays a single byte-for-byte equality against what was
 * extracted, and anything carrying userinfo or an escape simply cannot match.
 */
// The `i` is load-bearing, not tidiness. URL schemes are case-insensitive, so
// fetch("HTTPS://evil.net/x") is a working request; without the flag the scan
// extracts NOTHING from those bytes and an uppercase-scheme origin is invisible
// to the wall rather than reported as an offender. A configured relay origin is
// always lowercase (normalizeRelayOrigin requires url.origin === raw), so any
// uppercase-scheme hit necessarily fails the byte-exact comparison below.
const ORIGIN_RE = /https?:\/\/[A-Za-z0-9._:@%[\]-]*/gi;

/**
 * The host a browser would really contact for an extracted authority: everything after the
 * LAST `@`, since every earlier `@` is inside userinfo. Reporting only; the gate itself
 * compares the raw extraction. This exists so the failure message names `https://evil.net`
 * rather than making the reader parse the URL in their head at the moment they are least
 * inclined to.
 */
function realOrigin(extracted: string): string {
  const sep = extracted.indexOf('://');
  if (sep < 0) return extracted;
  const scheme = extracted.slice(0, sep + 3);
  const authority = extracted.slice(sep + 3);
  const at = authority.lastIndexOf('@');
  return at < 0 ? extracted : scheme + authority.slice(at + 1);
}

/** Left behind by vite.config.ts where the CDN origin used to be. */
const STRIP_MARKER = 'keyweave-refuses-external-origin';

/** The token index.html carries before vite fills it in. Must never reach dist/. */
const CSP_PLACEHOLDER = '__KEYWEAVE_CSP__';

interface Build {
  /** The value of KEYWEAVE_RELAY_ORIGIN, or null for the default (same-origin) build. */
  configured: string | null;
  files: string[];
  /** Path relative to the output root, mapped to the emitted bytes read as latin1. */
  bytes: Map<string, string>;
  log: string;
}

function walk(root: string, dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const abs = join(dir, name);
    if (statSync(abs).isDirectory()) walk(root, abs, out);
    else out.push(relative(root, abs));
  }
  return out;
}

/** A scratch output directory of its own, named so a stray one says which case made it. */
function outDirFor(label: string): string {
  return join(SCRATCH, label);
}

/**
 * The vite arguments that send a build somewhere other than dist/.
 *
 * `--emptyOutDir` is required because the target is outside the project root: without it
 * vite refuses to empty the directory and only warns, which would leave a previous case's
 * files in place and let this suite scan a mixture of two builds.
 */
function outDirArgs(out: string): string[] {
  return ['--', '--outDir', out, '--emptyOutDir'];
}

/**
 * Build with the given configuration into its own scratch directory and snapshot the
 * result into memory.
 */
function build(configured: string | null, label: string): Build {
  const out = outDirFor(label);
  rmSync(out, { recursive: true, force: true });
  const env = { ...process.env };
  if (configured === null) delete env[RELAY_ORIGIN_ENV];
  else env[RELAY_ORIGIN_ENV] = configured;
  // Throws on a non-zero exit, so a broken build fails this suite rather than scanning a
  // stale directory from a previous run. The rm above is what makes that true.
  const log = execFileSync('npm', ['run', 'build', ...outDirArgs(out)], {
    cwd: CLIENT_DIR,
    encoding: 'utf8',
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const files = walk(out, out).sort();
  const bytes = new Map<string, string>();
  // latin1: one char per byte, so a wasm binary is searchable and nothing is skipped.
  for (const rel of files) bytes.set(rel, readFileSync(join(out, rel), 'latin1'));
  return { configured, files, bytes, log };
}

/**
 * Run a build and report only whether it exited zero. For the refusal cases.
 *
 * Also aimed at a scratch directory: a refusal is supposed to abort at config load with
 * nothing emitted, but a case that stops being refused must not be able to overwrite the
 * developer's dist/ as the way it announces that.
 */
function buildStatus(value: string, label: string): { status: number | null; output: string } {
  const result = spawnSync('npm', ['run', 'build', ...outDirArgs(outDirFor(label))], {
    cwd: CLIENT_DIR,
    encoding: 'utf8',
    env: { ...process.env, [RELAY_ORIGIN_ENV]: value },
  });
  return { status: result.status, output: `${result.stderr ?? ''}${result.stdout ?? ''}` };
}

/**
 * A hash of every file in dist/, or null when there is no dist/ at all.
 *
 * Taken at module load, which is before any build in this file runs, and compared again at
 * the end. Cheap enough to be a real assertion rather than a promise in a comment.
 */
function distFingerprint(): string | null {
  if (!existsSync(DIST)) return null;
  const hash = createHash('sha256');
  for (const rel of walk(DIST, DIST).sort()) {
    hash.update(rel);
    hash.update(readFileSync(join(DIST, rel)));
  }
  return hash.digest('hex');
}

const DIST_BEFORE = distFingerprint();

function countIn(target: Build, rel: string, needle: string): number {
  return (target.bytes.get(rel) ?? '').split(needle).length - 1;
}

function countEverywhere(target: Build, needle: string): number {
  return target.files.reduce((total, rel) => total + countIn(target, rel, needle), 0);
}

interface Hit {
  file: string;
  /** Exactly the bytes that were extracted. This is what the gate compares. */
  origin: string;
  /** Where a browser would really connect. Reporting only; see realOrigin(). */
  host: string;
  context: string;
}

/** Every origin in every emitted file, with the file it came from and some context. */
function originsIn(target: Build): Hit[] {
  const found: Hit[] = [];
  for (const rel of target.files) {
    const source = target.bytes.get(rel)!;
    for (const match of source.matchAll(ORIGIN_RE)) {
      found.push({
        file: rel,
        origin: match[0],
        host: realOrigin(match[0]),
        // Enough context that the next person can see what it is at a glance.
        context: source.slice(match.index, match.index + 60).replace(/[^\x20-\x7e]/g, '.'),
      });
    }
  }
  return found;
}

/** How an offending hit is printed: the real host first, because that is the answer. */
function describeHit(hit: Hit): string {
  return `${hit.file}: connects to ${hit.host} | ${hit.context}`;
}

function metaCsp(target: Build): string {
  const html = target.bytes.get('index.html')!;
  const match = html.match(
    /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"\s*\/?>/,
  );
  expect(match, 'no CSP meta tag in the built index.html').not.toBeNull();
  return match![1]!;
}

let defaultBuild: Build;
let splitBuild: Build;

describe('R13: the built bundle reaches no unconfigured origin', () => {
  beforeAll(() => {
    // Once per configuration, reused by every assertion below: a build is the slowest thing
    // in the suite and there are exactly two configurations worth having.
    defaultBuild = build(null, 'default');
    splitBuild = build(TEST_ORIGIN, 'split');
  }, 600_000);

  describe('the default build (same-origin relay, what ships unless told otherwise)', () => {
    it('emitted the artifacts it is supposed to scan', () => {
      expect(defaultBuild.files).toContain('index.html');
      expect(defaultBuild.files.some((f) => f.endsWith('.js'))).toBe(true);
      expect(defaultBuild.files.some((f) => f.endsWith('.css'))).toBe(true);
      expect(defaultBuild.files.some((f) => f.endsWith('.wasm'))).toBe(true);
      // Both workers, or the scan below is not looking at the code that holds the decoder.
      expect(defaultBuild.files.some((f) => f.includes('receive-worker'))).toBe(true);
      expect(defaultBuild.files.some((f) => f.includes('vault-worker'))).toBe(true);
      expect(defaultBuild.log).toContain('stripExternalOrigins');
    });

    it('no http or https origin survives anywhere in dist', () => {
      const offenders = originsIn(defaultBuild).map(describeHit);
      expect(offenders, 'an external origin reached the build output').toEqual([]);
    });

    it('the CDN default really was stripped, and not merely absent', () => {
      // The tripwire. Today zxing-wasm ships exactly one CDN default and the plugin rewrites
      // it, so this is 1. If it ever reads 0, the assertion above still holds but the reason
      // has changed: either the library stopped shipping the default (fine, confirm and
      // update this number) or the plugin stopped running against the worker bundle (not
      // fine, and the failure it caused once was invisible from the build log alone).
      expect(
        countEverywhere(defaultBuild, STRIP_MARKER),
        'the origin-strip plugin left no trace in dist/',
      ).toBe(1);
    });

    it('nothing creates an object URL, which is what lets the CSP drop blob:', () => {
      // script-src and worker-src were tightened to 'self' with no blob: on the evidence
      // that no code in the bundle can produce a blob URL. This is that evidence, checked.
      //
      // Executable artifacts only. index.html carries the comment that explains the
      // tightening, and a scan that reads its own documentation as a violation would teach
      // the next person to delete the documentation.
      const executable = defaultBuild.files.filter(
        (rel) => rel.endsWith('.js') || rel.endsWith('.wasm'),
      );
      expect(executable.length).toBeGreaterThan(2);
      const offenders = executable.filter(
        (rel) => countIn(defaultBuild, rel, 'createObjectURL') > 0,
      );
      expect(offenders, 'dist creates an object URL; the CSP assumes nothing does').toEqual([]);
    });

    it('the shipped CSP is byte-identical to the policy that shipped before WP7', () => {
      expect(metaCsp(defaultBuild)).toBe(EXPECTED_DEFAULT_CSP);
      // The one directive whose absence is invisible: no wasm, no decoder, no error.
      expect(metaCsp(defaultBuild)).toContain("'wasm-unsafe-eval'");
    });

    it('the placeholder was substituted, not shipped', () => {
      // A page served with content="__KEYWEAVE_CSP__" has no policy and no symptom, which is
      // the new failure mode generating the policy introduces. Checked in dist rather than
      // trusted to the plugin that throws, for the same reason the origin scan is here.
      expect(countEverywhere(defaultBuild, CSP_PLACEHOLDER)).toBe(0);
      expect(countEverywhere(splitBuild, CSP_PLACEHOLDER)).toBe(0);
    });

    it('the built page has no inline script and no inline handler', () => {
      const html = defaultBuild.bytes.get('index.html')!;
      // <script> with a body, as opposed to <script src=...></script>.
      const inline = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)].filter(
        ([, , body]) => (body ?? '').trim().length > 0,
      );
      expect(inline.map((m) => m[0].slice(0, 80))).toEqual([]);
      expect(/\son[a-z]+\s*=/i.test(html)).toBe(false);
      // A build that inlined the CSS would need style-src 'unsafe-inline'.
      expect(/<style\b[^>]*>[\s\S]*?\S[\s\S]*?<\/style>/.test(html)).toBe(false);
    });

    it('the decoder loads its wasm from a same-origin asset path', () => {
      const worker = defaultBuild.files.find((f) => f.includes('receive-worker'));
      expect(worker).toBeDefined();
      const source = defaultBuild.bytes.get(worker!)!;
      const wasmRef = source.match(/[^"']*zxing_reader[A-Za-z0-9_.-]*\.wasm/);
      expect(wasmRef, 'the worker no longer references the wasm asset').not.toBeNull();
      expect(wasmRef![0].startsWith('/')).toBe(true);
      expect(defaultBuild.files.some((f) => f.endsWith(wasmRef![0].replace(/^\//, '')))).toBe(true);
    });
  });

  describe('the split build (relay on its own origin, residual R2)', () => {
    it('carries the configured origin and NOTHING else', () => {
      const hits = originsIn(splitBuild);
      // A positive control first. Zero hits would pass a naive "no unexpected origin" test
      // while meaning the origin never reached the bundle at all, which is a broken build,
      // not a clean one.
      expect(hits.length, 'the configured relay origin never reached dist/').toBeGreaterThan(0);

      const offenders = hits
        // EXACT MATCH, against the RAW extracted bytes. Not startsWith:
        // `https://relay.keyweave.example.evil.net` starts with the configured origin and
        // is a different server entirely. And not against realOrigin() either, because
        // `https://evil.net@relay.keyweave.example` has the right real host while still
        // shipping credentials nobody wrote; a configured origin contains no `@` and no
        // `%`, so raw equality refuses both shapes with one rule.
        .filter((hit) => hit.origin !== TEST_ORIGIN)
        .map(describeHit);
      expect(offenders, 'an origin other than the configured relay was emitted').toEqual([]);

      // Both consumers, named. If either drops out the topology is half-applied: a page
      // whose CSP permits an origin its code never calls, or code that calls an origin the
      // page's own policy forbids.
      expect(hits.some((h) => h.file === 'index.html')).toBe(true);
      expect(hits.some((h) => h.file.endsWith('.js'))).toBe(true);
    });

    it('the lookalike-suffix trap the exact match exists for is really caught', () => {
      // The negative control for the RULE, not for the build. If someone relaxes the filter
      // above to startsWith or includes, this is the test that says what was lost.
      const lookalike = `${TEST_ORIGIN}.evil.net`;
      expect(lookalike.startsWith(TEST_ORIGIN)).toBe(true);
      expect(lookalike === TEST_ORIGIN).toBe(false);
      // And the extractor really does read the whole host rather than stopping early, in
      // each of the terminators that occur in real emitted code.
      for (const sample of [
        `fetch("${lookalike}/v1/mailboxes")`,
        `const u='${lookalike}';`,
        `x = \`${lookalike}\`;`,
        `connect-src 'self' ${lookalike}; img-src 'self'`,
      ]) {
        expect([...sample.matchAll(ORIGIN_RE)][0]![0]).toBe(lookalike);
      }
    });

    it('userinfo cannot hide a different host from the extractor', () => {
      // The hole this closes, measured: with `@` outside the character class,
      // `https://relay.keyweave.example@evil.net/` extracted as
      // `https://relay.keyweave.example`, compared EQUAL to the configured origin and was
      // dropped as benign. A browser given that URL connects to evil.net.
      const table: { emitted: string; extracted: string; connectsTo: string }[] = [
        {
          emitted: `fetch("${TEST_ORIGIN}@evil.net/v1/mailboxes")`,
          extracted: `${TEST_ORIGIN}@evil.net`,
          connectsTo: 'https://evil.net',
        },
        {
          // Two `@`: only the last one ends the userinfo, so an extractor that split on the
          // first would still name the wrong host.
          emitted: `fetch("${TEST_ORIGIN}@a@evil.net/x")`,
          extracted: `${TEST_ORIGIN}@a@evil.net`,
          connectsTo: 'https://evil.net',
        },
        {
          // Percent escapes, same idea one step more obscure.
          emitted: `const u="https://relay.keyweave%2eexample.evil.net";`,
          extracted: 'https://relay.keyweave%2eexample.evil.net',
          connectsTo: 'https://relay.keyweave%2eexample.evil.net',
        },
      ];

      for (const row of table) {
        const hit = [...row.emitted.matchAll(ORIGIN_RE)][0]![0];
        expect(hit, `extractor stopped early in: ${row.emitted}`).toBe(row.extracted);
        // The gate's own comparison. Each of these must be an offender.
        expect(hit === TEST_ORIGIN, `${hit} slipped past the exact match`).toBe(false);
        expect(realOrigin(hit)).toBe(row.connectsTo);
      }

      // The reason raw equality is enough: a configured origin cannot carry either
      // character, because build-config.mjs refuses both. Stated here so that if someone
      // ever relaxes the validator, the pair of rules is visibly coupled.
      expect(TEST_ORIGIN).not.toContain('@');
      expect(TEST_ORIGIN).not.toContain('%');
    });

    it('connect-src names self AND the relay, and nothing else moved', () => {
      const csp = metaCsp(splitBuild);
      const connect = /connect-src ([^;]+);/.exec(csp);
      expect(connect, 'no connect-src in the built policy').not.toBeNull();
      expect(connect![1]).toContain("'self'");
      expect(connect![1]).toContain(TEST_ORIGIN);
      // The whole policy, so a second source or a loosened directive elsewhere fails here.
      expect(csp).toBe(EXPECTED_SPLIT_CSP);
      expect(csp).toContain("'wasm-unsafe-eval'");
    });

    it('still strips the CDN default exactly once', () => {
      expect(countEverywhere(splitBuild, STRIP_MARKER)).toBe(1);
    });
  });

  describe('the build refuses a relay origin it cannot safely interpolate', () => {
    // This value is spliced into a security policy string. A build that accepted
    // `https://x.example; script-src 'unsafe-inline'` would ship a page whose CSP carries an
    // extra directive nobody wrote, and the page would look and behave perfectly.
    //
    // Shelled rather than unit-tested against the validator, because the property asserted
    // is "the BUILD aborts". A static check of the validator would not notice if
    // vite.config.ts stopped calling it. Each refusal costs about 0.6s, because the value is
    // read at config load and the build dies before it emits anything.
    //
    // THE WILDCARD ROW IS THE ONE THAT WAS REALLY BROKEN. `https://*` parses, and its
    // `url.origin` is byte-identical to what was typed, so every check the validator had
    // passed it and the build shipped `connect-src 'self' https://*`: permission to connect
    // to any https origin at all, which is the exact opposite of what this variable exists
    // to express. The rest of the rows are the neighbours of that one.
    it.each([
      ["https://x.example; script-src 'unsafe-inline'", 'a semicolon'],
      ['https://relay.example/v1', 'a path'],
      ['https://*', 'a bare wildcard: connect-src to anywhere'],
      ['https://*.example.com', 'a wildcard label'],
      ['https://ex*mple.com', 'a wildcard inside a label'],
      ['https://exa_mple.com', 'an underscore, which is not LDH'],
      ['https://-lead.example', 'a label starting with a hyphen'],
      ['https://trail-.example', 'a label ending with a hyphen'],
      ['https://exa..mple', 'an empty label'],
      [`https://${'a'.repeat(64)}.example`, 'a label over 63 characters'],
      ['https://localhost', 'a single-label host'],
    ])(
      'refuses %s (%s) with a non-zero exit',
      (value) => {
        const { status, output } = buildStatus(value, 'refused');
        expect(status, `the build accepted ${value}`).not.toBe(0);
        expect(status).not.toBeNull();
        // The message has to name what was wrong, or the operator's next move is a guess.
        expect(output).toContain(RELAY_ORIGIN_ENV);
        // And nothing was emitted: a refusal that half-wrote an output directory would be a
        // second failure mode wearing the first one's clothes.
        expect(existsSync(outDirFor('refused'))).toBe(false);
      },
      300_000,
    );

    it(
      'still BUILDS for an IPv6 literal, which a hand-written host check breaks first',
      () => {
        // The positive control for the grammar, at build level. A rule that refused
        // everything would satisfy every assertion above while making the feature unusable,
        // and `https://[::1]:8443` is the shape most likely to be collateral damage:
        // brackets and colons, through the URL parser, the CSP string and vite's `define`.
        // The rest of the positive table is unit-level in test/build-config.test.ts, because
        // it does not need a whole build to be decided. The other shelled positive is the
        // split build above, which is a plain dotted name.
        const { status, output } = buildStatus('https://[::1]:8443', 'accepted-ipv6');
        expect(status, `the build refused a legitimate origin: ${output.slice(-400)}`).toBe(0);
        const html = readFileSync(join(outDirFor('accepted-ipv6'), 'index.html'), 'utf8');
        expect(html).toContain("connect-src 'self' https://[::1]:8443;");
      },
      300_000,
    );
  });
});

describe("the suite leaves the developer's dist/ alone", () => {
  it('client/dist is byte-for-byte what it was before these builds ran', () => {
    // Runs last in this file, which is the only place it can run: the builds happen in
    // beforeAll above. `npm test` used to leave dist/ holding the SPLIT build, wired to a
    // relay origin nobody owns, and a dist/ produced by a test run is indistinguishable by
    // eye from one produced by `npm run build`. Hashing the whole tree rather than
    // index.html alone, because the assets carry the compiled-in origin too.
    expect(distFingerprint()).toBe(DIST_BEFORE);
  });
});
