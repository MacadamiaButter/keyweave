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

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage', '.claude']);
const TEXT_EXT = /\.(ts|js|mjs|cjs|json|md|py|conf|service|html|css|txt|yml|yaml)$/;

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
});
