// The relay-origin validator, as a table.
//
// WHY THIS FILE EXISTS AND WHAT IT IS NOT. `test/build-no-external-origin.test.ts` shells a
// real `npm run build` for the refusal cases, and that stays the wall: it is the only thing
// that would notice if vite.config.ts stopped calling the validator at all. What it cannot
// afford is breadth, because every row there is a process. So the wall keeps the rows whose
// point is "the BUILD aborts", and the full grammar, positives included, is decided here in
// milliseconds by calling the function.
//
// THE DEFECT THIS TABLE WAS WRITTEN FOR. `normalizeRelayOrigin` used to end at
//
//     if (url.origin !== raw) reject(...)
//
// which reads like a complete answer and is not one. Measured:
//
//     node --input-type=module -e "import {normalizeRelayOrigin,cspPolicy}
//       from './build-config.mjs'; console.log(cspPolicy(normalizeRelayOrigin('https://*')))"
//     -> default-src 'none'; ...; connect-src 'self' https://*; ...
//
// `https://*` parses, `url.origin` is byte-identical to what was typed, and the emitted
// policy permits the client to connect to ANY https origin. Every guard in the module was
// working exactly as written; none of them was asking whether the thing they all agreed on
// was a HOST. So the module now carries an explicit host grammar, and this is its table.
//
// The positive rows matter as much as the negative ones. A grammar that refuses everything
// satisfies every negative row while making the feature unusable, and the two shapes a
// hand-written host check gets wrong first are a bracketed IPv6 literal and punycode.

import { describe, it, expect } from 'vitest';
import {
  MAX_CONFIG_LINE,
  RELAY_ORIGIN_ENV,
  cspPolicy,
  nginxCspBlock,
  normalizeRelayOrigin,
  relayOriginFromEnv,
} from '../build-config.mjs';

/** Values the build must refuse, each with the substring its message has to contain. */
const REFUSED: [value: string, why: string, names: string][] = [
  // The wildcards. The first row is the one that shipped.
  ['https://*', 'a bare wildcard is connect-src to anywhere', 'wildcard in its host'],
  ['https://*.example.com', 'a wildcard label', 'wildcard in its host'],
  ['https://ex*mple.com', 'a wildcard inside a label', 'wildcard in its host'],
  // Characters the WHATWG host parser passes through untouched.
  ['https://exa_mple.com', 'an underscore is not LDH', 'letters, digits'],
  ['https://-lead.example', 'a label may not start with a hyphen', 'letters, digits'],
  ['https://trail-.example', 'a label may not end with a hyphen', 'letters, digits'],
  ['https://exa..mple', 'an empty label', 'empty label'],
  [`https://${'a'.repeat(64)}.example`, 'a label over 63 characters', 'the limit is 63'],
  [`https://${`${'a'.repeat(63)}.`.repeat(4)}example`, 'a host over 253 characters', 'the limit is 253'],
  ['https://relay.example.', 'a trailing dot leaves an empty last label', 'empty label'],
  ['https://localhost', 'a single-label host', 'single-label'],
  ['https://localhost:8151', 'a single-label host with a port', 'single-label'],
  // All-numeric hosts are judged as addresses, never as names. Both of these are refused by
  // the URL parser before the grammar sees them, which is worth pinning: the grammar's
  // numeric branch is the layer UNDER that, and a parser change is what would expose it.
  ['https://1.2.3.4.5', 'five octets is neither an address nor a name', 'absolute URL'],
  ['https://256.1.1.1', 'an octet above 255', 'absolute URL'],
  // Injection into the policy string, which is what the whole module is for. The spaced
  // forms are the ones an operator would actually type; the unspaced ones are here so the
  // semicolon and comma rules are exercised rather than shadowed by the space rule.
  ["https://x.example; script-src 'unsafe-inline'", 'a semicolon appends a directive', 'space'],
  ["https://x.example;script-src", 'a semicolon with no space', "';'"],
  ['https://x.example, https://y.example', 'a comma appends a source', 'space'],
  ['https://x.example,https://y.example', 'a comma with no space', "','"],
  ["https://x.example'", 'a quote', 'single quote'],
  ['https://$host.example', 'an nginx variable reference', "'$'"],
  ['https://x .example', 'a space', 'space'],
  // Shapes that are not an origin at all.
  ['https://relay.example/v1', 'a path', 'path'],
  ['https://relay.example/', 'a trailing slash', 'trailing slash'],
  ['https://relay.example?a=1', 'a query string', 'query'],
  ['https://relay.example#x', 'a fragment', 'fragment'],
  ['https://user:pw@relay.example', 'credentials', 'credentials'],
  ['ftp://relay.example', 'a scheme that is not http or https', 'scheme'],
  ['relay.example', 'not an absolute URL', 'absolute URL'],
  // Values the URL parser rewrites, caught by the byte-identity rule rather than the
  // grammar. Kept in the same table because to an operator they are one rule: what you
  // typed is what gets deployed, or the build stops.
  ['https://RELAY.example', 'an uppercase host is normalised', 'byte-identical'],
  ['https://127.1', 'a shorthand IPv4 is expanded', 'byte-identical'],
  ['https://0127.0.0.1', 'a leading zero is read as octal', 'byte-identical'],
  ['https://relay%2eexample.com', 'a percent escape is decoded', 'byte-identical'],
  ['https://relay.example:443', 'a default port is dropped', 'byte-identical'],
];

/** Values the build must accept, unchanged. */
const ACCEPTED: [value: string, why: string][] = [
  ['https://relay.example', 'a dotted LDH name'],
  ['https://relay.keyweave.localfirstlab.org', 'the origin DEPLOY.md uses'],
  ['https://relay.example:8443', 'a name with an explicit port'],
  ['http://relay.example', 'http, for a private preview'],
  ['https://[::1]:8443', 'a bracketed IPv6 literal'],
  ['https://[2001:db8::1]', 'a bracketed IPv6 literal with no port'],
  ['https://127.0.0.1:8151', 'a dotted-quad IPv4 literal'],
  ['https://255.255.255.255', 'the top of the IPv4 range'],
  ['https://xn--e1afmkfd.xn--p1ai', 'punycode, which is ordinary LDH'],
  ['https://a-b.c-d.example', 'inner hyphens'],
  [`https://${'a'.repeat(63)}.example`, 'a label at exactly 63 characters'],
];

describe('normalizeRelayOrigin refuses anything that is not one origin', () => {
  it.each(REFUSED)('refuses %s (%s)', (value, _why, names) => {
    let message: string | null = null;
    try {
      normalizeRelayOrigin(value);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message, `accepted ${value}`).not.toBeNull();
    // The message has to name the variable and say what was wrong, or the operator's next
    // move after a failed build is a guess.
    expect(message).toContain(RELAY_ORIGIN_ENV);
    expect(message, `message did not say why: ${message}`).toContain(names);
    // And it has to quote the value back, so a variable set in the wrong shell is visible.
    expect(message).toContain(JSON.stringify(value).slice(1, 12));
  });

  it('a refused value never reaches a policy string', () => {
    // The consequence, stated separately from the mechanism. cspPolicy re-validates rather
    // than trusting its caller, so there is no second door into the same string.
    for (const [value] of REFUSED) {
      expect(() => cspPolicy(value), `cspPolicy accepted ${value}`).toThrow();
      expect(() => nginxCspBlock(value), `nginxCspBlock accepted ${value}`).toThrow();
    }
  });

  it('the wildcard that started this cannot reach connect-src by any route', () => {
    // Named on its own because it is the finding, not an example of one. Every entry point
    // in the module has to refuse it, including the env reader vite.config.ts actually uses.
    for (const wildcard of ['https://*', 'http://*', 'https://*.example.com']) {
      expect(() => normalizeRelayOrigin(wildcard)).toThrow(/KEYWEAVE_RELAY_ORIGIN/);
      expect(() => cspPolicy(wildcard)).toThrow();
      expect(() => relayOriginFromEnv({ [RELAY_ORIGIN_ENV]: wildcard })).toThrow();
    }
  });
});

describe('normalizeRelayOrigin accepts a real origin and returns it unchanged', () => {
  it.each(ACCEPTED)('accepts %s (%s)', (value) => {
    expect(normalizeRelayOrigin(value)).toBe(value);
    expect(relayOriginFromEnv({ [RELAY_ORIGIN_ENV]: value })).toBe(value);
  });

  it.each(ACCEPTED)('puts %s in connect-src and nowhere else', (value) => {
    const policy = cspPolicy(value);
    // leastpriv: exactly one directive changes, and it grows by exactly one source.
    expect(policy).toBe(cspPolicy(null).replace("connect-src 'self';", `connect-src 'self' ${value};`));
    expect(policy).toContain("'wasm-unsafe-eval'");
    expect(policy.split(';').length).toBe(11);
  });

  it.each(ACCEPTED)('renders %s as an nginx block of short lines', (value) => {
    // The 2026-08-05 rule, checked for every accepted shape rather than for the one origin
    // the document happens to publish: the chunk boundaries move with the length of the host.
    const block = nginxCspBlock(value);
    for (const line of block.split('\n')) {
      expect(line.length, `line over ${MAX_CONFIG_LINE} chars: ${line}`).toBeLessThanOrEqual(
        MAX_CONFIG_LINE,
      );
    }
    // Reassembling the `set` pieces has to give back the policy character for character.
    const pieces = [...block.matchAll(/^set \$csp_[a-z] "(.*)";$/gm)].map((m) => m[1]!);
    expect(pieces.join('')).toBe(cspPolicy(value));
  });
});

describe('unset means same origin, and that path is untouched', () => {
  it.each([undefined, null, ''])('%s is the same-origin default', (value) => {
    expect(normalizeRelayOrigin(value as string | null | undefined)).toBeNull();
  });

  it('the default policy is what shipped before the relay origin was configurable', () => {
    // Duplicated from build-no-external-origin.test.ts on purpose: that file asserts the
    // BUILD output against this literal without importing the generator, this one asserts
    // the generator. Two oracles, one string.
    expect(cspPolicy(null)).toBe(
      "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; " +
        "connect-src 'self'; img-src 'self'; media-src 'self' mediastream:; style-src 'self'; " +
        "font-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    );
  });

  it('an env object with no variable at all is the same-origin default', () => {
    expect(relayOriginFromEnv({})).toBeNull();
    expect(relayOriginFromEnv({ [RELAY_ORIGIN_ENV]: undefined })).toBeNull();
  });
});
