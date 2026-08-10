// The one definition of "where is the relay", and everything derived from it.
//
// WHY THIS FILE EXISTS (anchor `swisscheese`, Reason's Swiss Cheese Model). Three
// independent layers have to agree about the relay origin:
//
//   1. the `<meta http-equiv="Content-Security-Policy">` in client/index.html,
//   2. the Content-Security-Policy RESPONSE HEADER the app host sends,
//   3. the base URL `RelayClient` is constructed with, in client/src/ui/main.ts.
//
// Each of the three is a real defence. The failure mode is not one of them being weak, it
// is their holes LINING UP because a human changed one and not the others: a connect-src
// that permits an origin the client never calls is harmless, a client that calls an origin
// connect-src does not permit is a dead app, and a header that disagrees with the meta tag
// is a policy nobody can reason about. So all three are generated from ONE value, read
// once, here.
//
// WHY BUILD TIME AND NOT RUNTIME (anchor `cd`, Humble and Farley). Configuration that
// varies per environment belongs in the artifact's identity, not in a file the serving host
// can edit. A runtime config fetch would also be a network call before the CSP is known,
// and it would let the host that serves the bundle also choose which origins that bundle
// may talk to. Baking it in means the published artifact hash covers it: see
// docs/REPRODUCIBLE-BUILD.md, where this is now part of what a release attestation must
// state.
//
// Plain ESM, no TypeScript, deliberately: vite.config.ts, the vitest suite and
// client/scripts/print-csp.mjs all import this same file, and a .mjs is the only form all
// three load without a build step of its own.

/** The single environment variable. Unset or empty means SAME ORIGIN. */
export const RELAY_ORIGIN_ENV = 'KEYWEAVE_RELAY_ORIGIN';

/**
 * The token client/index.html carries where the policy goes. Not vite's own `%VAR%` HTML
 * env syntax: that namespace belongs to import.meta.env and a collision there would be
 * resolved silently, in favour of the wrong value.
 */
export const CSP_PLACEHOLDER = '__KEYWEAVE_CSP__';

/** The compile-time constant vite `define`s and client/src/ui/main.ts reads. */
export const RELAY_ORIGIN_DEFINE = '__KEYWEAVE_RELAY_ORIGIN__';

/**
 * Characters that must never reach a policy string, each with the reason it is refused.
 * A semicolon is the whole point of this list: `https://x.example; script-src
 * 'unsafe-inline'` as an env value would append a directive to the meta tag, and the
 * build would happily ship it. The rest are here because a value that contains any of
 * them is not an origin, so refusing is free.
 */
const FORBIDDEN_CHARS = [
  [' ', 'contains a space'],
  [';', "contains ';', which would inject a directive into the policy"],
  [',', "contains ',', which would inject a source into the policy"],
  ["'", 'contains a single quote'],
  ['"', 'contains a double quote'],
  ['`', 'contains a backtick'],
  ['\\', 'contains a backslash'],
  ['<', "contains '<'"],
  ['>', "contains '>'"],
  ['$', "contains '$', which is a variable reference in an nginx config"],
];

/**
 * HOST GRAMMAR. The byte-identity check below (`url.origin === raw`) is necessary and is
 * NOT sufficient, and the gap is the whole reason this section exists.
 *
 * Measured: `new URL('https://*')` parses, `url.hostname` is `*`, and `url.origin` is
 * `https://*` byte for byte. So an env value of `https://*` sailed through every check in
 * this file and produced `connect-src 'self' https://*`, which permits the client to
 * connect to ANY https origin. That is a total defeat of the one directive this module
 * exists to tighten, arriving through the exact input it is built to validate. The WHATWG
 * host parser is permissive on purpose: it forbids a specific set of code points
 * (space, `#`, `/`, `:`, `<`, `>`, `?`, `@`, `[`, `\`, `]`, `^`, `|`) and passes anything
 * else through untouched, so `*`, `_`, a leading `-` and an empty label all survive.
 *
 * The answer is an ALLOWLIST of what a host may look like, checked in addition to
 * byte-identity, never a denylist of characters that happen to be dangerous today. Three
 * shapes are permitted and nothing else:
 *
 *   1. a dotted DNS name of LDH labels (letters, digits, inner hyphens);
 *   2. a dotted-quad IPv4 literal;
 *   3. a bracketed IPv6 literal, so `https://[::1]:8443` keeps working.
 *
 * Punycode is ordinary LDH (`xn--e1afmkfd.xn--p1ai` is letters, digits and hyphens) and so
 * needs no special case. A SINGLE-LABEL host is refused deliberately: `https://localhost`
 * is not a name a public deployment should be pinning a policy to, and the loopback cases
 * that matter are covered by the IPv4 and IPv6 forms above.
 */
const MAX_HOST_CHARS = 253;
const MAX_LABEL_CHARS = 63;

/** One LDH label: alphanumeric at each end, hyphens allowed only inside. */
const LDH_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/** A dotted quad. Range and leading zeros are checked separately, with their own messages. */
const DOTTED_QUAD = /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/;

/** A bracketed IPv6 literal. The URL parser has already rejected a malformed one. */
const IPV6_LITERAL = /^\[[0-9a-f:.]+\]$/;

/** Printable, quotable rendering of a rejected value, so the message names it exactly. */
function show(raw) {
  const escaped = String(raw).replace(/[^\x20-\x7e]/g, (c) => {
    const code = c.codePointAt(0) ?? 0;
    return `\\x${code.toString(16).padStart(2, '0')}`;
  });
  return JSON.stringify(escaped);
}

function reject(raw, reason) {
  throw new Error(`${RELAY_ORIGIN_ENV} ${reason}: ${show(raw)}`);
}

/**
 * Refuse any host that is not one of the three permitted shapes, and any port that is not a
 * number in range. `raw` is carried only so the message names what the operator typed.
 *
 * @param {string} raw the value as written
 * @param {string} host `url.hostname`, so an IPv6 literal still carries its brackets
 * @param {string} port `url.port`, empty when the scheme default applies
 */
function assertHostGrammar(raw, host, port) {
  if (port !== '') {
    // The URL parser is strict about ports already; this is stated anyway so the rule is
    // readable here rather than inferred from another specification.
    if (!/^[0-9]{1,5}$/.test(port)) reject(raw, `has a port that is not digits ("${port}")`);
    const number = Number(port);
    if (number < 1 || number > 65535) reject(raw, `has a port outside 1-65535 ("${port}")`);
  }

  // Named before the shape dispatch, purely so the message is the useful one. `https://*`
  // would otherwise be refused as a single-label host, which is true and unhelpful: the
  // operator's mistake was reaching for CSP wildcard syntax, and the answer is that this
  // variable takes exactly one origin and there is no syntax here for more.
  if (host.includes('*')) {
    reject(raw, `has a wildcard in its host ("${host}"); this takes ONE exact origin`);
  }

  if (host.startsWith('[') || host.endsWith(']')) {
    if (!IPV6_LITERAL.test(host)) reject(raw, `has a malformed IPv6 literal host ("${host}")`);
    return;
  }

  // All digits and dots: judged as an address, never as a name, so `999.1.1.1` cannot fall
  // through to the DNS branch and be accepted as four labels.
  if (/^[0-9.]+$/.test(host)) {
    const quad = DOTTED_QUAD.exec(host);
    if (quad === null) {
      reject(raw, `has an all-numeric host that is not a dotted-quad IPv4 address ("${host}")`);
    }
    for (const octet of quad.slice(1)) {
      if (octet.length > 1 && octet.startsWith('0')) {
        reject(raw, `has an IPv4 octet with a leading zero ("${octet}")`);
      }
      if (Number(octet) > 255) reject(raw, `has an IPv4 octet above 255 ("${octet}")`);
    }
    return;
  }

  if (host.length > MAX_HOST_CHARS) {
    reject(raw, `has a host of ${host.length} characters (the limit is ${MAX_HOST_CHARS})`);
  }
  const labels = host.split('.');
  if (labels.length < 2) {
    reject(raw, `has a single-label host ("${host}"); use a dotted name or an IP literal`);
  }
  for (const label of labels) {
    if (label === '') reject(raw, `has an empty label in its host ("${host}")`);
    if (label.length > MAX_LABEL_CHARS) {
      reject(raw, `has a host label of ${label.length} characters (the limit is ${MAX_LABEL_CHARS})`);
    }
    if (!LDH_LABEL.test(label)) {
      reject(
        raw,
        `has a host label that is not letters, digits and inner hyphens ("${label}")`,
      );
    }
  }
}

/**
 * Validate a raw relay-origin value.
 *
 * @param {string | undefined | null} raw
 * @returns {string | null} the origin, or null for "same origin as the app"
 * @throws {Error} naming exactly what was wrong, so the build aborts loudly
 *
 * leastpriv (Saltzer and Schroeder): the return value grows `connect-src` by EXACTLY one
 * origin. There is no list, no wildcard and no "and also" path, because every one of those
 * is a way for a second origin to end up permitted by a change nobody reviewed.
 */
export function normalizeRelayOrigin(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw !== 'string') reject(raw, 'is not a string');

  for (const [char, reason] of FORBIDDEN_CHARS) {
    if (raw.includes(char)) reject(raw, reason);
  }
  for (const char of raw) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) reject(raw, 'contains a control character');
    if (code > 0x7e) reject(raw, 'contains a non-ASCII character');
  }
  if (raw.endsWith('/')) {
    reject(raw, 'has a trailing slash (an origin has no path, not even the empty one)');
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    reject(raw, 'is not an absolute URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    reject(raw, `uses the scheme "${url.protocol}" (only http and https are origins here)`);
  }
  if (url.username !== '' || url.password !== '') reject(raw, 'carries credentials');
  if (url.search !== '') reject(raw, 'carries a query string');
  if (url.hash !== '') reject(raw, 'carries a fragment');
  if (url.pathname !== '' && url.pathname !== '/') reject(raw, 'carries a path');
  if (url.hostname === '') reject(raw, 'has no host');

  // Anything the URL parser normalised away (an uppercase host, a default port written out,
  // a percent-escape, an internationalised name, a stray userinfo separator) makes the
  // reserialised origin differ from what was typed, and a policy string built from a value
  // that is not what the operator wrote is exactly the drift this module exists to prevent.
  if (url.origin !== raw) {
    reject(raw, `is not byte-identical to its parsed origin (${show(url.origin)})`);
  }

  // Necessary AND sufficient only together. Byte-identity says "the parser agrees with you";
  // it does not say the thing you both agree on is a host. `https://*` passes the line above
  // and is a wildcard in a CSP. See the HOST GRAMMAR note at the top of this file.
  assertHostGrammar(raw, url.hostname, url.port);
  return url.origin;
}

/**
 * Read and validate the relay origin out of a process environment.
 *
 * @param {Record<string, string | undefined>} env
 * @returns {string | null}
 */
export function relayOriginFromEnv(env) {
  return normalizeRelayOrigin(env?.[RELAY_ORIGIN_ENV]);
}

/**
 * The exact, single-line Content-Security-Policy. `relayOrigin` null means same origin,
 * and that case must remain byte-identical to the policy Keyweave shipped before the split
 * relay existed: docs/DEPLOY-CSP.md publishes it and
 * client/test/build-no-external-origin.test.ts asserts it against a hardcoded literal.
 *
 * Every directive here has its justification in docs/DEPLOY-CSP.md. Two of them are worth
 * repeating at the point of generation:
 *   - 'wasm-unsafe-eval' is MANDATORY. Without it WebAssembly.instantiate is blocked, the
 *     zxing QR decoder never starts, and nothing surfaces an error: it presents as a broken
 *     camera. Never drop it.
 *   - frame-ancestors and form-action are ignored in a meta tag by specification. They are
 *     written anyway so the tag and the response header are one string, diffable by eye.
 *
 * @param {string | null} relayOrigin
 * @returns {string}
 */
export function cspPolicy(relayOrigin) {
  const origin = normalizeRelayOrigin(relayOrigin);
  const connect = origin === null ? "'self'" : `'self' ${origin}`;
  return [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "worker-src 'self'",
    `connect-src ${connect}`,
    "img-src 'self'",
    "media-src 'self' mediastream:",
    "style-src 'self'",
    "font-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ');
}

/**
 * The longest SOURCE line any generated config may have. On 2026-08-05 a 270-character
 * nginx add_header line wrapped when pasted into a terminal, the real newline landed inside
 * the quoted string, `nginx -t` ACCEPTED it, and the breakage only appeared at the HTTP
 * layer as `curl: (8) Header without colon`. Long values are therefore assembled from short
 * pieces, and this generator asserts the property rather than trusting the author.
 */
export const MAX_CONFIG_LINE = 100;

/** Value width per `set` line, chosen so the whole line stays well inside the limit. */
const CHUNK = 76;

/**
 * Split `policy` into pieces whose plain concatenation is `policy` again, each at most
 * `limit` characters. Breaks at a space where one is available so the pieces read as
 * directives; hard-splits anything longer than the window, because correctness of the
 * concatenation is the property that matters and a pathologically long host name must not
 * be able to reintroduce a long line.
 */
function splitForConfig(policy, limit) {
  const pieces = [];
  let rest = policy;
  while (rest.length > limit) {
    let cut = rest.lastIndexOf(' ', limit);
    if (cut <= 0) cut = limit;
    pieces.push(rest.slice(0, cut));
    rest = rest.slice(cut);
  }
  pieces.push(rest);
  if (pieces.join('') !== policy) {
    throw new Error('internal: policy chunking is not lossless');
  }
  return pieces;
}

const NGINX_VAR_LETTERS = 'abcdefghijklmnopqrstuvwxyz';

/**
 * Wrap `text` into `# ` comment lines no longer than MAX_CONFIG_LINE.
 *
 * Comments get the same treatment as directives and the reason is not tidiness: if a long
 * comment wraps on paste, the tail lands at column zero as a DIRECTIVE, and the error nginx
 * then reports names the tail rather than the wrap. Same failure family as 2026-08-05, one
 * step further from the cause.
 */
function commentLines(text) {
  const limit = MAX_CONFIG_LINE - 2;
  return splitForConfig(text, limit).map((piece, i) => (i === 0 ? `# ${piece}` : `#${piece}`));
}

/**
 * The nginx response-header block for a given relay origin, as a string of short lines.
 *
 * This is the layer the meta tag cannot be: frame-ancestors and form-action only take
 * effect in a real response header. docs/DEPLOY-CSP.md embeds this verbatim and a test
 * asserts the document matches, so hand-editing the document fails the suite instead of
 * silently disagreeing with the artifact.
 *
 * @param {string | null} relayOrigin
 * @returns {string}
 */
export function nginxCspBlock(relayOrigin) {
  const origin = normalizeRelayOrigin(relayOrigin);
  const policy = cspPolicy(origin);
  const pieces = splitForConfig(policy, CHUNK);
  if (pieces.length > NGINX_VAR_LETTERS.length) {
    throw new Error(`relay origin makes the policy too long to render: ${show(origin)}`);
  }

  const names = pieces.map((_, i) => `$csp_${NGINX_VAR_LETTERS[i]}`);
  const lines = [
    ...commentLines('In the server block for the APP origin. Never the relay: residual R2.'),
    ...commentLines(
      origin === null
        ? `Generated for a SAME-ORIGIN relay (${RELAY_ORIGIN_ENV} unset at build time).`
        : `Generated for ${RELAY_ORIGIN_ENV}=${origin}`,
    ),
    ...commentLines('Generated by client/scripts/print-csp.mjs. Paste it, do not retype it.'),
  ];
  for (const [i, piece] of pieces.entries()) {
    lines.push(`set ${names[i]} "${piece}";`);
  }
  lines.push(`add_header Content-Security-Policy "${names.join('')}" always;`);
  lines.push('');
  lines.push('add_header Referrer-Policy "no-referrer" always;');
  lines.push('add_header X-Content-Type-Options "nosniff" always;');
  lines.push('add_header Cross-Origin-Opener-Policy "same-origin" always;');
  lines.push('add_header Cross-Origin-Resource-Policy "same-origin" always;');
  lines.push('add_header Permissions-Policy "camera=(self), microphone=(), geolocation=()" always;');

  // Assert, then hand it over. The check that caught the 2026-08-05 wrap existed and was
  // handed to the operator as a SEPARATE step, so the reload happened anyway. Here it is
  // inside the thing that produces the text.
  const tooLong = lines.filter((line) => line.length > MAX_CONFIG_LINE);
  if (tooLong.length > 0) {
    throw new Error(
      `generated nginx line over ${MAX_CONFIG_LINE} chars: ${show(tooLong[0])}`,
    );
  }
  return lines.join('\n');
}
