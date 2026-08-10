// The patent firewall, in the test suite.
//
// ENFORCEMENT, stated honestly: this repository has no CI runner yet, so "enforced" means
// `npm test` in client/, run by whoever is touching this code. The checks below are written
// to be runner-agnostic so wiring them into a pipeline later is a config change.
//
// WHY THIS FILE EXISTS: Keyweave's freedom-to-operate posture against the encrypted-QR
// prior art (US 11455616 / US 11720879, Mycashless "Secure Animated Response code")
// rests on a property of the wire, not on an argument. Those independent claims require
// displaying an ENCRYPTED code and DECRYPTING it on receipt. Keyweave's optical hop
// carries the plaintext signed public card, which is why it fails those limitations.
//
// That property is one refactor away from disappearing. Someone tidying the pairing flow
// could reasonably think "the card goes over a camera, we should encrypt it" and place a
// seal between card.ts and the encoder. It would still pair, every other test would still
// pass, and the limitation would be gone silently. So:
//
//   NEVER PLACE A CIPHER BETWEEN CARD SERIALIZATION AND THE OPTICAL ENCODER.
//
// The four arms, and what each one is for. A round trip alone proves nothing here: ANY
// symmetric transform applied on encode and undone on decode reassembles byte-exact, so
// the arms have to look at the wire and at the call site, not only at the output.
//   - dynamic: a receiver holding no key material at all reassembles the card, AND the
//     frame body on the wire is that card verbatim. This arm is DECIDABLE: it executes
//     the chain and reads the bytes, so no textual trick evades it.
//   - REAL CALLER: the same wire assertion, against the entry point the application
//     actually calls (src/pairing-session.ts startCardBroadcast), rather than a chain this
//     file assembles. Also decidable, and this is the arm that closes R14.
//   - static: the guarded files cannot acquire a key or a cipher by import.
//   - call site: every encodeCardFrames( call in src/, at any depth, names a
//     createSignedCard result.
// This is also the leastpriv check: the optical layer sees public bytes only.
//
// R14 IS CLOSED, and this is the note that used to say it was not. The gap was that the
// dynamic arm only ever covered a chain this file built, so a real caller could have
// placed a cipher in the middle and stayed green. The call-site arm was the only thing
// looking at real callers and it is a text rule, which constrains the SHAPE of the binding
// handed to the encoder and never the VALUE that arrives: a Uint8Array is mutable, so a
// caller can pass the exact const the rule blessed and mutate that buffer in place first,
// or pass the encoder around as a value. Both would keep the text rule green.
//
// The fix was to make the question decidable rather than to write a better regex.
// startCardBroadcast() returns the card bytes ALONGSIDE the frame stream, so the
// real-caller arm below executes it, sizes the stream to k=1 and compares frame(0)'s body
// with the card byte for byte, with no key material anywhere in the test. Any transform
// between createSignedCard and the encoder changes the wire, and the wire is what is
// asserted. NEGATIVE CONTROL, run 2026-08-08: a one-line XOR inserted into
// startCardBroadcast between serialization and encodeCardFrames failed this arm on the
// byte comparison AND on importCard, and every other test in this file stayed green.
//
// The call-site arm remains, downgraded to what it is good at: making the honest shape the
// path of least resistance. It is no longer the only thing standing between a future
// caller and a silent loss of the limitation.
//
// It is a POSTURE, not a clearance: three named patents were read, no family or class
// search was run. Owner-run USPTO search plus counsel before any commercial offering.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard, importCard } from '../src/card.js';
import { OpticalReceiver, encodeCardFrames } from '../src/optical.js';
import { startCardBroadcast } from '../src/pairing-session.js';
import { HEADER_LEN } from '../vendor/decimen/frame.js';

const CLIENT_DIR = fileURLToPath(new URL('..', import.meta.url));
const SRC_DIR = join(CLIENT_DIR, 'src');

function read(rel: string): string {
  return readFileSync(join(CLIENT_DIR, rel), 'utf8');
}

/**
 * Every .ts under src/, at any depth. RECURSIVE on purpose: the browser UI put real code
 * in src/ui/, and a rule that only reads the top level would have stopped covering the
 * callers it exists for the moment a subdirectory appeared.
 */
function srcFiles(dir = SRC_DIR, out: string[] = []): string[] {
  for (const name of readdirSync(dir).sort()) {
    const abs = join(dir, name);
    if (statSync(abs).isDirectory()) srcFiles(abs, out);
    else if (name.endsWith('.ts')) out.push(relative(CLIENT_DIR, abs));
  }
  return out;
}

/**
 * Comment lines stripped. Module-scope because BOTH text arms need it: a comment naming a
 * forbidden thing must not be a finding, and a comment must not be able to reshape what a
 * regex sees around a real call.
 */
function codeOnly(source: string): string {
  return source
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//') && !line.trimStart().startsWith('*'))
    .join('\n');
}

describe('optical payload is a plaintext signed card (dynamic arm)', () => {
  it('a receiver with NO key material recovers and verifies the card from raw frames', async () => {
    const alice = await generateKeyManager('noble');
    const signedCardBytes = await createSignedCard(alice.manager, 42);

    const stream = encodeCardFrames(signedCardBytes);
    expect(stream.totalLen).toBe(signedCardBytes.length);

    // Constructed with no arguments: no key manager, no vault, no shared secret. This is
    // exactly what a stranger's camera has.
    const rx = new OpticalReceiver();
    let assembled: Uint8Array | null = null;
    for (let seq = 0; seq < 200 && !assembled; seq++) {
      const status = rx.feed(stream.frame(seq));
      expect(status.kind).not.toBe('refused');
      if (status.kind === 'complete') assembled = status.payload;
    }
    expect(assembled).not.toBeNull();

    // (a) byte-exact: the optical layer transformed nothing.
    expect(Buffer.from(assembled!).equals(Buffer.from(signedCardBytes))).toBe(true);

    // (b) the public card API alone parses and signature-verifies it. If a cipher were
    // introduced anywhere above, these bytes would be an opaque envelope and importCard
    // would throw.
    const card = importCard(assembled!);
    expect(card.version).toBe(1);
    expect(card.serial).toBe(42);
    expect(
      Buffer.from(card.identityPub).equals(Buffer.from(alice.manager.identityPublicKey())),
    ).toBe(true);
    expect(
      Buffer.from(card.encryptionPub).equals(Buffer.from(alice.manager.encryptionPublicKey())),
    ).toBe(true);
  });

  it('the FRAME BODY on the wire is the plaintext card, not just the reassembly', async () => {
    // The test above is satisfied by any symmetric transform: encrypt in encodeCardFrames,
    // decrypt in OpticalReceiver, and the reassembly is still byte-exact while the wire
    // carries ciphertext (payloadFnv is computed over the plaintext, so checksumOk stays
    // true too). The claim in the spec is about the WIRE, so read the wire.
    //
    // At k=1 the single source block IS the whole card and every frame body is that block,
    // so the bytes after the 20-byte header are directly comparable. This is the assertion
    // a cipher placed anywhere between createSignedCard and packFrame cannot survive.
    const alice = await generateKeyManager('noble');
    const cardBytes = await createSignedCard(alice.manager, 42);
    const stream = encodeCardFrames(cardBytes, {
      frameBytes: HEADER_LEN + cardBytes.length,
      sessionId: 9,
    });
    expect(stream.k).toBe(1);
    expect(stream.blockLen).toBe(cardBytes.length);

    for (const seq of [0, 1, 37]) {
      const body = stream.frame(seq).subarray(HEADER_LEN);
      expect(
        Buffer.from(body).equals(Buffer.from(cardBytes)),
        `frame ${seq} body is not the card verbatim`,
      ).toBe(true);
    }

    // And the public card API alone reads it straight off the wire, with no receiver in
    // the picture at all: this is what a stranger's camera gets.
    const offTheWire = importCard(stream.frame(0).subarray(HEADER_LEN));
    expect(offTheWire.serial).toBe(42);
    expect(
      Buffer.from(offTheWire.identityPub).equals(Buffer.from(alice.manager.identityPublicKey())),
    ).toBe(true);
  });

  it('the assembled bytes are the SignedCard wire bytes, not a re-encode', async () => {
    // importCard verifies over the transported bytes. Pin that what came off the optical
    // hop is what the signature covers.
    const alice = await generateKeyManager('noble');
    const signedCardBytes = await createSignedCard(alice.manager, 7);
    const stream = encodeCardFrames(signedCardBytes, { sessionId: 4242 });
    const rx = new OpticalReceiver();
    let assembled: Uint8Array | null = null;
    for (let seq = 0; seq < 200 && !assembled; seq++) {
      const status = rx.feed(stream.frame(seq));
      if (status.kind === 'complete') assembled = status.payload;
    }
    const card = importCard(assembled!);
    expect(Buffer.from(card.signedCardBytes).equals(Buffer.from(signedCardBytes))).toBe(true);
  });
});

describe('R14: the REAL pairing entry point puts the plaintext card on the wire', () => {
  // This arm is the closure. It does not build a chain: it calls the function the
  // application calls, and then reads the bytes that function put on the wire.

  it('startCardBroadcast at k=1 emits the card verbatim, and a stranger can parse it', async () => {
    const alice = await generateKeyManager('noble');

    // Two calls, same keys and same serial. Ed25519 signing is deterministic and the card
    // is deterministic CBOR, so the second call produces the identical bytes; the first
    // exists only to learn the length the frame has to be sized to. Both are real calls
    // through the real entry point.
    const sizing = await startCardBroadcast(alice.manager, 42);
    const broadcast = await startCardBroadcast(alice.manager, 42, {
      frameBytes: HEADER_LEN + sizing.cardBytes.length,
      sessionId: 11,
    });
    expect(Buffer.from(broadcast.cardBytes).equals(Buffer.from(sizing.cardBytes))).toBe(true);

    // k = 1: the single source block IS the whole card, so every frame body is directly
    // comparable to it. This is the assertion a cipher between serialization and the
    // encoder cannot survive.
    expect(broadcast.frames.k).toBe(1);
    expect(broadcast.frames.totalLen).toBe(broadcast.cardBytes.length);

    for (const seq of [0, 1, 97]) {
      const body = broadcast.frames.frame(seq).subarray(HEADER_LEN);
      expect(
        Buffer.from(body).equals(Buffer.from(broadcast.cardBytes)),
        `frame ${seq} body is not the card the entry point returned`,
      ).toBe(true);
    }

    // No key manager, no vault, no shared secret: the public card API alone reads frame 0
    // straight off the wire. This is what a stranger's camera gets.
    const offTheWire = importCard(broadcast.frames.frame(0).subarray(HEADER_LEN));
    expect(offTheWire.serial).toBe(42);
    expect(offTheWire.version).toBe(1);
    expect(
      Buffer.from(offTheWire.identityPub).equals(Buffer.from(alice.manager.identityPublicKey())),
    ).toBe(true);
    expect(
      Buffer.from(offTheWire.encryptionPub).equals(
        Buffer.from(alice.manager.encryptionPublicKey()),
      ),
    ).toBe(true);
  });

  it('the same holds through the production frame sizing, via a keyless receiver', async () => {
    // k=1 is the arm that reads the wire directly; the default sizing is what actually
    // ships (about five source blocks, low symbol density). Cover both.
    const alice = await generateKeyManager('noble');
    const broadcast = await startCardBroadcast(alice.manager, 3);
    expect(broadcast.frames.k).toBeGreaterThan(1);

    const rx = new OpticalReceiver();
    let assembled: Uint8Array | null = null;
    for (let seq = 0; seq < 200 && !assembled; seq++) {
      const status = rx.feed(broadcast.frames.frame(seq));
      expect(status.kind).not.toBe('refused');
      if (status.kind === 'complete') assembled = status.payload;
    }
    expect(assembled).not.toBeNull();
    expect(Buffer.from(assembled!).equals(Buffer.from(broadcast.cardBytes))).toBe(true);
    expect(importCard(assembled!).serial).toBe(3);
  });
});

describe('no cipher on the optical path (static arm)', () => {
  // Only IMPORTS are inspected, not prose: this file and optical.ts both have to be able
  // to name what they forbid.
  const IMPORT_FROM = /(?:^|[\s;}])(?:import|export)\b[^;]*?\bfrom\s*['"]([^'"]+)['"]/g;
  const BARE_IMPORT = /(?:^|[\s;}])import\s*['"]([^'"]+)['"]/g;
  const DYNAMIC = /\b(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

  // Every module specifier the optical path is allowed to reach for.
  const ALLOWED_SPECIFIERS = new Set([
    '../vendor/decimen/frame.js',
    '../vendor/decimen/frame-capacity.js',
    '../vendor/decimen/fountain.js',
    './frame',
    './wasm-url',
    'zxing-wasm/reader',
    'zxing-wasm/reader/zxing_reader.wasm?url',
  ]);

  // Anything that would put key material or an AEAD on this path.
  const FORBIDDEN = /seal|keys|cipher|chacha|poly1305|aead|encrypt|decrypt|noble|vault|pairing/i;

  function opticalPathFiles(): { label: string; source: string }[] {
    const files = [{ label: 'src/optical.ts', source: read('src/optical.ts') }];
    const vendorDir = 'vendor/decimen';
    for (const name of readdirSync(join(CLIENT_DIR, vendorDir)).sort()) {
      if (!name.endsWith('.ts')) continue;
      files.push({ label: `${vendorDir}/${name}`, source: read(`${vendorDir}/${name}`) });
    }
    return files;
  }

  function specifiers(source: string): string[] {
    const found: string[] = [];
    for (const re of [IMPORT_FROM, BARE_IMPORT, DYNAMIC]) {
      re.lastIndex = 0;
      for (const m of source.matchAll(re)) found.push(m[1]!);
    }
    return found;
  }

  /** Whole-line comments dropped, so prose naming the forbidden thing is still allowed. */
  /** Import statements only, so a comment naming the forbidden thing is still allowed. */
  function importStatements(source: string): string[] {
    return codeOnly(source)
      .split(';')
      .filter((chunk) => /(?:^|[\s}])(?:import|require)\b/.test(chunk) && /['"]/.test(chunk));
  }

  /**
   * import()/require() whose specifier is not a SINGLE COMPLETE string literal. Both
   * checks above can only see literals: `const p = ['@nob', 'le/ciphers'].join('/');
   * await import(p)` yields no specifier and no import statement, so both would pass
   * vacuously. A concatenation is the same evasion wearing a quote: `import('@nob' +
   * 'le/ciphers/chacha.js')` starts with a quote, produces no contiguous forbidden
   * token, and its closing quote is not followed by `)`. So the test is the whole
   * argument, not its first character. Anything that is not one bare literal is refused
   * rather than analysed.
   */
  function computedSpecifiers(source: string): string[] {
    const found: string[] = [];
    for (const m of codeOnly(source).matchAll(/\b(?:import|require)\s*\(\s*([^)]*)/g)) {
      const arg = (m[1] ?? '').trim();
      if (!/^(['"])[^'"]*\1$/.test(arg)) found.push(arg === '' ? '<empty>' : arg);
    }
    return found;
  }

  it('finds the files it is supposed to be guarding', () => {
    const labels = opticalPathFiles().map((f) => f.label);
    expect(labels).toContain('src/optical.ts');
    expect(labels).toContain('vendor/decimen/frame.ts');
    expect(labels).toContain('vendor/decimen/fountain.ts');
    expect(labels.length).toBeGreaterThanOrEqual(9);
  });

  it('no file on the optical path imports a cipher or key module', () => {
    for (const { label, source } of opticalPathFiles()) {
      for (const stmt of importStatements(source)) {
        expect(FORBIDDEN.test(stmt), `${label}: forbidden import -> ${stmt.trim()}`).toBe(false);
      }
    }
  });

  it('every module specifier on the optical path is on the allowlist', () => {
    for (const { label, source } of opticalPathFiles()) {
      for (const spec of specifiers(source)) {
        expect(ALLOWED_SPECIFIERS.has(spec), `${label}: unexpected import of ${spec}`).toBe(true);
      }
    }
  });

  it('no computed module specifier can slip past the allowlist', () => {
    for (const { label, source } of opticalPathFiles()) {
      expect(computedSpecifiers(source), `${label}: computed import specifier`).toEqual([]);
    }
  });

  it('the guard actually fires (negative control on the static arm)', () => {
    // Prove the two checks above are load-bearing rather than vacuously true, by running
    // them against a source string that violates each rule.
    const withCipher = "import { seal } from '../src/seal.js';\nexport const x = 1;\n";
    expect(importStatements(withCipher).some((s) => FORBIDDEN.test(s))).toBe(true);
    expect(specifiers(withCipher).some((s) => !ALLOWED_SPECIFIERS.has(s))).toBe(true);

    const dynamicCipher = "const m = await import('@noble/ciphers/chacha.js');\n";
    expect(specifiers(dynamicCipher).some((s) => !ALLOWED_SPECIFIERS.has(s))).toBe(true);

    // A computed specifier is invisible to both checks above, which is why it has its own.
    const computed = "const p = ['@nob', 'le/ciphers'].join('/');\nconst m = await import(p);\n";
    expect(specifiers(computed)).toHaveLength(0);
    expect(importStatements(computed).some((s) => FORBIDDEN.test(s))).toBe(false);
    expect(computedSpecifiers(computed)).toEqual(['p']);

    // A comment naming a cipher is NOT a violation: the checks read imports, not prose.
    const commentOnly = '// never place a cipher here: xchacha, seal, keys\n';
    expect(importStatements(commentOnly)).toHaveLength(0);
    expect(specifiers(commentOnly)).toHaveLength(0);
  });
});

describe('the encoder is called with an unmodified signed card (call-site arm)', () => {
  // WHY A THIRD ARM. The static arm reads src/optical.ts and the vendored codec; the
  // dynamic arm builds its own createSignedCard -> encodeCardFrames chain. Neither one
  // looks at the code that will actually call the encoder, so the exact refactor this
  // file's header predicts:
  //
  //   const cardBytes = await createSignedCard(km, serial);
  //   const envelope = await seal(km, peer, cardBytes);
  //   return encodeCardFrames(envelope);
  //
  // lands in a NEW file, imports nothing the static arm guards, and leaves every other
  // assertion in this suite green. Measured, before this arm existed: typecheck clean,
  // whole suite green, patent firewall green. So: in src/, the argument handed to
  // encodeCardFrames must be a createSignedCard result, either inline or through a const
  // that cannot be rebound. Anything else, including a helper wrapping the card, is a
  // refusal that a human reads rather than a rule the tool tries to reason about.
  //
  // src/ only. Tests legitimately encode arbitrary byte strings (loss patterns, cap
  // boundaries), and src/optical.ts is the definition site, not a call site.

  const ENCODE_CALL = /\bencodeCardFrames\s*\(\s*([^,)]*)/g;
  const DIRECT_CALL = /^(?:await\s+)?createSignedCard\s*\(/;
  const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;

  function encoderCallViolations(rawSource: string): string[] {
    // codeOnly, like the static arm: without it a call written inside a comment is a
    // finding and a comment is enough to reshape what the regex sees around a real call.
    const source = codeOnly(rawSource);
    const bad: string[] = [];
    for (const m of source.matchAll(ENCODE_CALL)) {
      const arg = (m[1] ?? '').trim();
      if (DIRECT_CALL.test(arg)) continue;
      if (IDENTIFIER.test(arg)) {
        // `const` specifically: a `let` binding could be reassigned to an envelope
        // between the declaration and the call, and the regex would never know.
        const bound = new RegExp(
          `\\bconst\\s+${arg}\\s*(?::[^=;]+)?=\\s*(?:await\\s+)?createSignedCard\\s*\\(`,
        );
        if (bound.test(source)) continue;
      }
      bad.push(arg === '' ? '<no argument>' : arg);
    }
    return bad;
  }

  function callerFiles(): { label: string; source: string }[] {
    return srcFiles()
      .filter((rel) => rel !== 'src/optical.ts')
      .map((rel) => ({ label: rel, source: read(rel) }))
      .filter((file) => /\bencodeCardFrames\s*\(/.test(file.source));
  }

  it('walks the whole of src/, subdirectories included', () => {
    const all = srcFiles();
    expect(all).toContain('src/pairing-session.ts');
    expect(all).toContain('src/ui/app.ts');
    expect(all.length).toBeGreaterThan(15);
  });

  it('the real caller is inside the set this arm walks', () => {
    // Without this, "no violations" could mean "no callers were found", which is what the
    // arm looked like for the whole of the work package before this one.
    expect(callerFiles().map((f) => f.label)).toContain('src/pairing-session.ts');
  });

  it('every call site in src/ hands the encoder a signed card and nothing else', () => {
    for (const { label, source } of callerFiles()) {
      const bad = encoderCallViolations(source);
      expect(bad, `${label}: encodeCardFrames called with ${bad.join(', ')}`).toEqual([]);
    }
  });

  it('the encoder is not imported under another name', () => {
    // Honest about what this arm is: a text rule, not an AST analysis. It finds call sites
    // by the encoder's own name, so `import { encodeCardFrames as enc }` would slip the
    // whole check. Renaming it on import is refused rather than followed.
    for (const rel of srcFiles()) {
      if (rel === 'src/optical.ts') continue;
      const aliased = read(rel).match(/\bencodeCardFrames\s+as\s+(\w+)/);
      expect(aliased?.[1], `${rel}: encodeCardFrames imported as ${aliased?.[1]}`).toBeUndefined();
    }
  });

  it('the call-site rule actually fires (negative control)', () => {
    // The caller set is empty until the browser UI work package adds the pairing screen,
    // so without this control the check above passes by walking nothing.
    const sealedCaller = [
      'const cardBytes = await createSignedCard(km, serial);',
      'const envelope = await seal(km, peer, cardBytes);',
      'return encodeCardFrames(envelope);',
    ].join('\n');
    expect(encoderCallViolations(sealedCaller)).toEqual(['envelope']);

    // Wrapped inline, and rebindable, are refusals too.
    expect(encoderCallViolations('encodeCardFrames(await seal(km, peer, cardBytes));')).toEqual([
      'await seal(km',
    ]);
    expect(
      encoderCallViolations(
        'let cardBytes = await createSignedCard(km, 1);\nencodeCardFrames(cardBytes);',
      ),
    ).toEqual(['cardBytes']);

    // The honest shapes pass, so the rule is not simply refusing every call.
    expect(
      encoderCallViolations(
        'const cardBytes = await createSignedCard(km, serial);\n' +
          'const stream = encodeCardFrames(cardBytes, { sessionId: 9 });',
      ),
    ).toEqual([]);
    expect(encoderCallViolations('encodeCardFrames(await createSignedCard(km, serial));')).toEqual(
      [],
    );
  });
});
