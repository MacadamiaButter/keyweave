// The verification command in docs/DEPLOY-CSP.md, run against a synthesized response.
//
// That command is the only gate in the deploy runbook, and it is pasted by a human who has
// just reloaded a live server. A gate that reports failure on a correct deploy is worse
// than no gate: the operator's next move is to go and change a configuration that was
// right, or to drop the check. So the command is extracted from the document verbatim and
// executed here against three inputs whose correct answers are known.
//
// The pattern is run through /bin/sh so it is the real grep on this machine with the real
// pattern text, quoting included, rather than a JavaScript approximation of either.
//
// SECOND JOB, added with the split relay (work package 7). The policy is now GENERATED from
// KEYWEAVE_RELAY_ORIGIN by client/build-config.mjs, and this document publishes both the
// policy strings and the nginx blocks an operator pastes. A document that quietly disagrees
// with the generator is worse than one that says nothing, because it is the thing a person
// copies at 2am. So every published block is compared, byte for byte, with what the
// generator emits. This is the doc-versus-code question; whether the BUILD emits the right
// bytes is asked separately, and without importing the generator, in
// test/build-no-external-origin.test.ts.

import { describe, it, expect, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_CONFIG_LINE, cspPolicy, nginxCspBlock } from '../build-config.mjs';

const DOC = readFileSync(fileURLToPath(new URL('../../docs/DEPLOY-CSP.md', import.meta.url)), 'utf8');
const DEPLOY_DOC = readFileSync(fileURLToPath(new URL('../../docs/DEPLOY.md', import.meta.url)), 'utf8');

/** The example split origin the document uses throughout. Matches docs/DEPLOY.md. */
const DOC_ORIGIN = 'https://relay.keyweave.localfirstlab.org';

/** The `grep ...` half of the documented one-liner, exactly as written. */
function documentedGrep(): string {
  const match = /\|\s*(grep\s+[^\n`]+)/.exec(DOC);
  if (!match) throw new Error('no piped grep in DEPLOY-CSP.md');
  return match[1]!.trim();
}

/** Every policy string the document publishes, in document order. */
function documentedPolicies(): string[] {
  return [...DOC.matchAll(/```\n(default-src 'none';[^\n]+)\n```/g)].map((m) => m[1]!);
}

/** The FIRST policy block: the default (same-origin) policy. */
function documentedPolicy(): string {
  const first = documentedPolicies()[0];
  if (first === undefined) throw new Error('no CSP block in DEPLOY-CSP.md');
  return first;
}

/** Every ```nginx fenced block, in document order. */
function documentedNginxBlocks(): string[] {
  return [...DOC.matchAll(/```nginx\n([\s\S]*?)\n```/g)].map((m) => m[1]!);
}

/** Run the documented pattern over `input`. Returns the count it prints. */
function run(input: string): number {
  const out = execFileSync('sh', ['-c', documentedGrep()], {
    input,
    encoding: 'utf8',
    // grep exits 1 when it selects nothing, which is a legitimate answer here.
    stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
  return Number(out);
}

function safeRun(input: string): number {
  try {
    return run(input);
  } catch (error) {
    const out = (error as { stdout?: string }).stdout ?? '';
    return Number(out.trim());
  }
}

/** What `curl -sI` prints: CRLF line endings, header value on one line. */
const crlf = (...lines: string[]) => lines.map((l) => `${l}\r\n`).join('') + '\r\n';

describe('the DEPLOY-CSP verification command answers correctly', () => {
  it('finds the command and the policy it is supposed to be checking', () => {
    expect(documentedGrep()).toMatch(/^grep\s/);
    expect(documentedPolicy()).toContain("'wasm-unsafe-eval'");
  });

  it('prints 1 for a correctly deployed header', () => {
    // The regression: `script-src` is the second of eleven directives, so the line does not
    // end at wasm-unsafe-eval. An anchored pattern printed 0 here, for a correct deploy.
    const response = crlf('HTTP/2 200', `content-security-policy: ${documentedPolicy()}`);
    expect(safeRun(response)).toBe(1);
  });

  it('prints 0 when the header is missing', () => {
    expect(safeRun(crlf('HTTP/2 200', 'server: nginx', 'referrer-policy: no-referrer'))).toBe(0);
  });

  it('prints 0 when curl refused the response, which is what a paste wrap looks like', () => {
    // The 2026-08-05 incident this document exists because of: a long add_header value
    // carrying a real newline. nginx -t accepts it, and curl reports
    // `curl: (8) Header without colon` on stderr with nothing on stdout.
    expect(safeRun('')).toBe(0);
  });

  it('prints 0 when the break landed before the load-bearing directive', () => {
    const policy = documentedPolicy();
    const cut = policy.indexOf("'wasm-unsafe-eval'");
    expect(cut).toBeGreaterThan(0);
    const wrapped = crlf(
      'HTTP/2 200',
      `content-security-policy: ${policy.slice(0, cut).trimEnd()}`,
      ` ${policy.slice(cut)}`,
    );
    expect(safeRun(wrapped)).toBe(0);
  });
});

describe('DEPLOY-CSP publishes exactly what the generator produces', () => {
  it('publishes both topologies, default first', () => {
    // Order matters and is asserted rather than assumed: the extractor above, and every
    // assertion in this file that talks about "the" policy, means the DEFAULT one.
    const policies = documentedPolicies();
    expect(policies.length).toBe(2);
    expect(policies[0]).toBe(cspPolicy(null));
    expect(policies[1]).toBe(cspPolicy(DOC_ORIGIN));
  });

  it('the split policy adds one source to connect-src and changes nothing else', () => {
    // Stated against the DOCUMENT, so a hand-edit widening some other directive in the
    // published string fails here even if the generator is fine.
    const [plain, split] = documentedPolicies();
    expect(split).toBe(plain!.replace("connect-src 'self';", `connect-src 'self' ${DOC_ORIGIN};`));
  });

  it('publishes the generated nginx block for each topology', () => {
    const blocks = documentedNginxBlocks();
    expect(blocks.length).toBe(2);
    expect(blocks[0]).toBe(nginxCspBlock(null));
    expect(blocks[1]).toBe(nginxCspBlock(DOC_ORIGIN));
  });

  it('the published policy strings are single lines, which is the property that broke once', () => {
    for (const policy of documentedPolicies()) {
      expect(policy).not.toContain('\n');
      expect(policy.split(';').length).toBe(11);
    }
  });
});

// ---------------------------------------------------------------------------------------
// DEPLOY.md step 6b: the deploy-time agreement check, EXECUTED.
//
// The build derives the header and the bundle from one value, so they cannot disagree at
// BUILD time. Deploy time is a different question and nothing was asking it: the header is
// pasted by a person, out of a print-csp.mjs run that may have been given a different origin
// than the artifact sitting next to it. Both halves are then internally consistent and the
// pair is wrong.
//
// Step 6b compares the two as they actually exist on the wire. That check is shell in a
// markdown file, which is the least tested kind of code there is, so it is extracted from
// the document and RUN here against synthesized responses whose right answers are known. A
// fake `curl` on PATH supplies them: no network, and the real pipeline text, quoting
// included, rather than a JavaScript approximation of it.
// ---------------------------------------------------------------------------------------

const SHIM_DIR = mkdtempSync(join(tmpdir(), 'keyweave-curl-shim-'));

afterAll(() => {
  rmSync(SHIM_DIR, { recursive: true, force: true });
});

{
  // -sI prints the response headers, anything else prints the body. Both come from the
  // environment, so one shim serves every case below.
  const shim = [
    '#!/bin/sh',
    'for a in "$@"; do case "$a" in -sI|-Is|-I) exec printf %s "$FAKE_HEADERS";; esac; done',
    'exec printf %s "$FAKE_BODY"',
    '',
  ].join('\n');
  writeFileSync(join(SHIM_DIR, 'curl'), shim);
  chmodSync(join(SHIM_DIR, 'curl'), 0o755);
}

/** The one ```bash block in DEPLOY.md that talks about connect-src: step 6b. */
function agreementBlock(): string {
  const blocks = [...DEPLOY_DOC.matchAll(/```bash\n([\s\S]*?)\n```/g)]
    .map((m) => m[1]!)
    .filter((b) => b.includes('connect-src'));
  if (blocks.length !== 1) {
    throw new Error(`expected exactly one connect-src block in DEPLOY.md, found ${blocks.length}`);
  }
  return blocks[0]!;
}

/** The origin the block is written against, read out of the block itself. */
function blockWant(): string {
  const match = /^WANT=(\S+)/m.exec(agreementBlock());
  if (!match) throw new Error('step 6b does not set WANT');
  return match[1]!;
}

const headerResponse = (policy: string | null) =>
  policy === null
    ? 'HTTP/2 200\r\nserver: static\r\n\r\n'
    : `HTTP/2 200\r\ncontent-security-policy: ${policy}\r\n\r\n`;

const pageBody = (policy: string) =>
  `<!doctype html>\n<html><head>\n<meta http-equiv="Content-Security-Policy" content="${policy}" />\n</head></html>\n`;

/** Run step 6b with a fake curl answering with these two responses. */
function runAgreement(headers: string, body: string): { status: number | null; out: string } {
  const result = spawnSync('sh', ['-c', agreementBlock()], {
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${SHIM_DIR}${delimiter}${process.env.PATH ?? ''}`,
      FAKE_HEADERS: headers,
      FAKE_BODY: body,
    },
  });
  return { status: result.status, out: `${result.stdout ?? ''}${result.stderr ?? ''}` };
}

describe('the DEPLOY step 6b agreement check answers correctly', () => {
  const want = blockWant();
  const right = cspPolicy(want);
  const other = cspPolicy('https://relay.someone-else.example');

  it('is written against an origin the build would actually accept', () => {
    // A block whose WANT the validator refuses would be untestable and undeployable.
    expect(() => cspPolicy(want)).not.toThrow();
    expect(right).toContain(`connect-src 'self' ${want};`);
  });

  it('passes when the header and the bundle agree', () => {
    const { status, out } = runAgreement(headerResponse(right), pageBody(right));
    expect(out).toContain('OK: header and bundle name the same relay origin');
    expect(out).not.toContain('STOP');
    expect(status).toBe(0);
  });

  it('STOPS when the pasted header was generated for a different origin', () => {
    // The exact failure it exists for: two internally consistent halves, wrong as a pair.
    const { status, out } = runAgreement(headerResponse(other), pageBody(right));
    expect(out).toContain('STOP: header and bundle disagree');
    expect(status).not.toBe(0);
  });

  it('STOPS when the served bundle is the wrong artifact, before looking at the header', () => {
    const { status, out } = runAgreement(headerResponse(right), pageBody(other));
    expect(out).toContain('STOP: the served bundle names a different relay');
    // And it does not then also report on the header, which would be an answer to a
    // question nobody should be asking yet.
    expect(out).not.toContain('same relay origin');
    expect(status).not.toBe(0);
  });

  it('reports a header-less host as a NOTE, not a failure, because that is option 2', () => {
    // GitHub Pages cannot send the header at all. A check that called that a hard failure
    // would be a gate the operator has to ignore every single time, which is a deleted gate.
    const { status, out } = runAgreement(headerResponse(null), pageBody(right));
    expect(out).toContain('NOTE: no CSP response header');
    expect(out).not.toContain('STOP');
    expect(status).toBe(0);
  });

  it('is not fooled by a page that merely mentions the origin outside the policy', () => {
    // A positive control on the extraction: the comparison has to read connect-src, not
    // "does the word appear somewhere in the response".
    const body = `${pageBody(other)}<p>relay: ${want}</p>\n`;
    const { out } = runAgreement(headerResponse(right), body);
    expect(out).toContain('STOP: the served bundle names a different relay');
  });

  it('STOPS on a suffix lookalike, which a substring test accepted', () => {
    // Round 2, 2026-08-09. The first version of this gate compared with
    // `case "$doc" in *"$WANT"*)`, so a served pair naming <want>.evil.net
    // printed OK. That is the SAME lookalike hole the dist scan had to close
    // in round 1, reintroduced at deploy time by the fix for something else,
    // which is precisely why a fix gets its own adversarial round.
    const lookalike = cspPolicy(`${want}.evil.net`);
    const { status, out } = runAgreement(headerResponse(lookalike), pageBody(lookalike));
    expect(out).toContain('STOP: the served bundle names a different relay');
    expect(status).not.toBe(0);
  });

  it('STOPS when the header agrees on connect-src but tampers elsewhere', () => {
    // Comparing only the connect-src directive passed a header carrying
    // worker-src 'none', which blocks both ES-module workers: the QR decoder
    // never starts and nothing anywhere surfaces an error. The invariant is
    // that the header and the meta tag are ONE string, so compare the whole.
    const tampered = right.replace("worker-src 'self'", "worker-src 'none'");
    expect(tampered).not.toBe(right);
    const { status, out } = runAgreement(headerResponse(tampered), pageBody(right));
    expect(out).toContain('STOP: header and bundle disagree');
    expect(status).not.toBe(0);
  });
});

/** The step-5 guard, extracted from the document and EXECUTED rather than read. */
function step5Guard(): string {
  const match = /^case "\$KEYWEAVE_RELAY_ORIGIN" in$[\s\S]*?^esac$/m.exec(DEPLOY_DOC);
  if (!match) throw new Error('DEPLOY.md step 5 has no KEYWEAVE_RELAY_ORIGIN guard');
  return match[0];
}

describe('the DEPLOY step 5 origin gate cannot pass vacuously', () => {
  const guard = step5Guard();
  const run = (env: Record<string, string>) =>
    spawnSync('sh', ['-c', guard], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '', ...env } });

  it('refuses an unset variable, which would make grep -cF match every line', () => {
    // Measured 2026-08-09 against the real artifact: with the variable unset,
    // `grep -cF "" dist/index.html` printed 440, the file's own line count,
    // which reads exactly like "found it" for a bundle built by someone else.
    const r = run({});
    expect(r.status).not.toBe(0);
    expect(`${r.stdout}${r.stderr}`).toContain('STOP');
  });

  it('refuses a value that is not an https origin', () => {
    expect(run({ KEYWEAVE_RELAY_ORIGIN: 'relay.example' }).status).not.toBe(0);
  });

  it('accepts the real thing', () => {
    expect(run({ KEYWEAVE_RELAY_ORIGIN: 'https://relay.example' }).status).toBe(0);
  });
});

describe('no line an operator pastes is long enough to wrap', () => {
  // The 2026-08-05 rule, applied to every file a person copies commands out of. Fenced
  // blocks only: prose wrapping in a terminal is harmless, a wrapped config or command line
  // is the incident. Comment lines inside a config block count too, because a wrapped
  // comment puts its tail at column zero where nginx reads it as a directive.
  const RUNBOOKS = ['DEPLOY-APP.md', 'DEPLOY-CSP.md', 'DEPLOY.md', 'REPRODUCIBLE-BUILD.md'];

  it.each(RUNBOOKS)('%s', (name) => {
    const text = readFileSync(fileURLToPath(new URL(`../../docs/${name}`, import.meta.url)), 'utf8');
    // Indented fences count: a block nested in a numbered list is still pasted.
    const fence = /^[ \t]*```(?:bash|sh|nginx|console)\n([\s\S]*?)\n[ \t]*```/gm;
    const blocks = [...text.matchAll(fence)];
    // A rule that scans nothing passes. Each of these files does carry paste blocks.
    expect(blocks.length, `no pasteable block found in ${name}`).toBeGreaterThan(0);
    const offenders: string[] = [];
    for (const block of blocks) {
      for (const line of block[1]!.split('\n')) {
        if (line.length > MAX_CONFIG_LINE) offenders.push(`${line.length}: ${line}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
