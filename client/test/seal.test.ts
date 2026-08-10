import { describe, it, expect } from 'vitest';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard, importCard, type ContactCard } from '../src/card.js';
import {
  seal,
  open,
  deriveMessageKey,
  messageKeyInfo,
  type OpenedMessage,
} from '../src/seal.js';
import { decodeStrict, encodeDeterministic } from '../src/cbor.js';
import { CTX_MSG_HKDF_SALT } from '../src/constants.js';
import { concatBytes } from '../src/bytes.js';

const BACKENDS = ['noble', 'webcrypto'] as const;
const te = (s: string) => new TextEncoder().encode(s);
const td = (b: Uint8Array) => new TextDecoder().decode(b);

async function pair(backend: (typeof BACKENDS)[number]) {
  const A = await generateKeyManager(backend);
  const B = await generateKeyManager(backend);
  const aViewOfB = importCard(await createSignedCard(B.manager, 1));
  const bViewOfA = importCard(await createSignedCard(A.manager, 1));
  return { A: A.manager, B: B.manager, aSeeds: A, bSeeds: B, aViewOfB, bViewOfA };
}

function reencodeEnvelope(env: Uint8Array, mutate: (m: Map<number, unknown>) => void): Uint8Array {
  const m = decodeStrict<Map<number, unknown>>(env);
  const copy = new Map<number, unknown>();
  for (const [k, v] of m) copy.set(k as number, v instanceof Uint8Array ? Uint8Array.from(v) : v);
  mutate(copy);
  return encodeDeterministic(copy);
}

describe('sign-then-encrypt seal / open', () => {
  for (const backend of BACKENDS) {
    it(`[${backend}] round-trips a message A->B`, async () => {
      const { A, aViewOfB, B, bViewOfA } = await pair(backend);
      const env = await seal(A, aViewOfB, te('meet at the old bridge'), { timestampMs: 42 });
      const opened = await open(B, bViewOfA, env);
      expect(td(opened.body)).toBe('meet at the old bridge');
      expect(opened.timestampMs).toBe(42);
      expect(opened.msgId.length).toBe(64);
      expect(Buffer.from(opened.senderId).equals(Buffer.from(A.identityPublicKey()))).toBe(true);
    });
  }

  it('the wire envelope contains NO identity-key material (leastpriv)', async () => {
    const { A, aViewOfB, B } = await pair('noble');
    const env = await seal(A, aViewOfB, te('hidden'), { timestampMs: 1 });
    // Only three keys, all opaque: version, nonce, ciphertext.
    const m = decodeStrict<Map<number, unknown>>(env);
    expect([...m.keys()].sort()).toEqual([0, 1, 2]);
    const contains = (hay: Uint8Array, needle: Uint8Array) => {
      outer: for (let i = 0; i + needle.length <= hay.length; i++) {
        for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
        return true;
      }
      return false;
    };
    for (const k of [
      A.identityPublicKey(),
      aViewOfB.identityPub,
      A.encryptionPublicKey(),
      aViewOfB.encryptionPub,
      B.identityPublicKey(),
    ]) {
      expect(contains(env, k)).toBe(false);
    }
  });

  it('tampering the ciphertext -> AEAD fails', async () => {
    const { A, aViewOfB, B, bViewOfA } = await pair('noble');
    const env = await seal(A, aViewOfB, te('integrity'), { timestampMs: 1 });
    const tampered = reencodeEnvelope(env, (m) => {
      const ct = m.get(2) as Uint8Array;
      ct[ct.length - 1] ^= 0x01;
    });
    await expect(open(B, bViewOfA, tampered)).rejects.toThrow(/AEAD open failed/);
  });

  it('wrong recipient -> no decrypt', async () => {
    const { A, aViewOfB } = await pair('noble');
    const env = await seal(A, aViewOfB, te('for B only'), { timestampMs: 1 });
    // A third party C, with A pinned as a contact, cannot open it.
    const C = await generateKeyManager('noble');
    const cViewOfA = importCard(await createSignedCard(A, 1));
    await expect(open(C.manager, cViewOfA, env)).rejects.toThrow(/AEAD open failed/);
  });

  it('surreptitious forward: B re-seals A\'s inner to C -> rejected (sender mismatch / not for me)', async () => {
    // A -> B legitimately.
    const A = (await generateKeyManager('noble')).manager;
    const B = (await generateKeyManager('noble')).manager;
    const C = (await generateKeyManager('noble')).manager;
    const aViewOfB = importCard(await createSignedCard(B, 1));
    const bViewOfA = importCard(await createSignedCard(A, 1));
    const bViewOfC = importCard(await createSignedCard(C, 1));
    const cViewOfB = importCard(await createSignedCard(B, 1));
    const cViewOfA = importCard(await createSignedCard(A, 1));

    const env1 = await seal(A, aViewOfB, te('secret for B'), { timestampMs: 10 });
    const opened = await open(B, bViewOfA, env1);

    // B (attacker) re-encrypts the UNCHANGED InnerSigned (still signed by A, recipient=B)
    // under K(B,C) and ships it to C.
    const innerSigned = encodeDeterministic(
      new Map<number, unknown>([
        [0, opened.innerBytes],
        [1, opened.sig],
      ]),
    );
    const kBC = await deriveMessageKey(B, bViewOfC);
    const nonce = new Uint8Array(24).fill(3);
    const attackEnv = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1],
        [1, nonce],
        [2, xchacha20poly1305(kBC, nonce, Uint8Array.from([1])).encrypt(innerSigned)],
      ]),
    );

    // C thinks the sender is B (the only key that decrypts) -> inner sender_id is A -> mismatch.
    await expect(open(C, cViewOfB, attackEnv)).rejects.toThrow(/sender_id does not match/);
    // C guessing sender=A cannot even decrypt (K(C,A) != K(B,C)).
    await expect(open(C, cViewOfA, attackEnv)).rejects.toThrow(/AEAD open failed/);
  });

  it('KCI: attacker holding only the recipient\'s X25519 secret cannot forge', async () => {
    // Attacker knows B's encryption seed, and all public keys, but NOT A's identity key.
    const A = await generateKeyManager('noble');
    const B = await generateKeyManager('noble');
    const bViewOfA = importCard(await createSignedCard(A.manager, 1));

    const aIdPub = A.manager.identityPublicKey();
    const aXPub = A.manager.encryptionPublicKey();
    const bIdPub = B.manager.identityPublicKey();
    const bXPub = B.manager.encryptionPublicKey();

    // Attacker derives K(A,B) from B's x-secret + public keys (KCI capability).
    const dh = x25519.getSharedSecret(B.encryptionSeed, aXPub);
    const info = messageKeyInfo(bIdPub, bXPub, aIdPub, aXPub);
    const K = hkdf(sha512, dh, CTX_MSG_HKDF_SALT, info, 32);

    // Attacker fabricates an inner claiming sender=A, but cannot produce A's signature.
    const inner = encodeDeterministic(
      new Map<number, unknown>([
        [0, aIdPub],
        [1, bIdPub],
        [2, 99],
        [3, te('forged: transfer the funds')],
      ]),
    );
    const forgedSig = new Uint8Array(64).fill(0x11); // not A's signature
    const innerSigned = encodeDeterministic(
      new Map<number, unknown>([
        [0, inner],
        [1, forgedSig],
      ]),
    );
    const nonce = new Uint8Array(24).fill(7);
    const attackEnv = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1],
        [1, nonce],
        [2, xchacha20poly1305(K, nonce, Uint8Array.from([1])).encrypt(innerSigned)],
      ]),
    );

    // B decrypts (K is correct) but the identity signature check fails.
    await expect(open(B.manager, bViewOfA, attackEnv)).rejects.toThrow(/signature invalid/);
  });

  it('version out of allowlist is refused BEFORE key derivation', async () => {
    const { A, aViewOfB, B, bViewOfA } = await pair('noble');
    const env = await seal(A, aViewOfB, te('v'), { timestampMs: 1 });
    const badVersion = reencodeEnvelope(env, (m) => m.set(0, 2)); // version 2 not allowlisted
    await expect(open(B, bViewOfA, badVersion)).rejects.toThrow(/unsupported message version 2/);
    // A version that overflows the AAD byte (256) is refused at strict decode (max 255).
    const overflow = reencodeEnvelope(env, (m) => m.set(0, 256));
    await expect(open(B, bViewOfA, overflow)).rejects.toThrow();
  });

  it('rejects unknown map keys / wrong shapes in the envelope', async () => {
    const { A, aViewOfB, B, bViewOfA } = await pair('noble');
    const env = await seal(A, aViewOfB, te('x'), { timestampMs: 1 });
    const extraKey = reencodeEnvelope(env, (m) => m.set(9, 0));
    await expect(open(B, bViewOfA, extraKey)).rejects.toThrow(/unknown map key 9/);
  });

  it('reused static key: two seals use DIFFERENT random nonces', async () => {
    const { A, aViewOfB } = await pair('noble');
    const e1 = await seal(A, aViewOfB, te('same body'), { timestampMs: 1 });
    const e2 = await seal(A, aViewOfB, te('same body'), { timestampMs: 1 });
    const n1 = (decodeStrict<Map<number, unknown>>(e1).get(1)) as Uint8Array;
    const n2 = (decodeStrict<Map<number, unknown>>(e2).get(1)) as Uint8Array;
    expect(Buffer.from(n1).equals(Buffer.from(n2))).toBe(false);
  });

  it('[future-clamp] a far-future inner timestamp is rejected at open() before it can poison replay state', async () => {
    // Must-fix #2: without the clamp, one message dated at ~MAX_SAFE_INTEGER permanently
    // bricks the sender's channel by poisoning the per-sender high-water mark.
    const { A, aViewOfB, B, bViewOfA } = await pair('noble');
    const now = 1_700_000_000_000;
    const env = await seal(A, aViewOfB, te('from the future'), {
      timestampMs: now + 10 * 24 * 60 * 60 * 1000, // 10 days ahead, >> 24h skew
    });
    await expect(open(B, bViewOfA, env, { nowMs: now })).rejects.toThrow(/too far in the future/);
    // A timestamp within the skew allowance still opens normally.
    const ok = await seal(A, aViewOfB, te('ok'), { timestampMs: now + 60_000 });
    const opened = await open(B, bViewOfA, ok, { nowMs: now });
    expect(opened.timestampMs).toBe(now + 60_000);
  });

  it("[transplant] attacker with C's X25519 secret re-seals an A->B message to C -> not addressed to us", async () => {
    // Distinct from wrong-recipient and surreptitious-forward (the sender binding catches
    // those): here the inner sender_id genuinely == the sender C has pinned (A), so ONLY
    // the recipient_id==us binding (must-fix #4 / KCI+transplant) rejects it.
    const A = (await generateKeyManager('noble')).manager;
    const B = (await generateKeyManager('noble')).manager;
    const C = await generateKeyManager('noble'); // attacker holds C's encryption secret
    const aViewOfB = importCard(await createSignedCard(B, 1));
    const bViewOfA = importCard(await createSignedCard(A, 1));
    const cViewOfA = importCard(await createSignedCard(A, 1));

    const env1 = await seal(A, aViewOfB, te('secret for B'), { timestampMs: 10 });
    const opened = await open(B, bViewOfA, env1); // recipient_id inside is B

    // Re-seal the UNMODIFIED InnerSigned (still signed by A, recipient=B) under K(A,C),
    // derivable from C's x-secret + A's public keys.
    const innerSigned = encodeDeterministic(
      new Map<number, unknown>([
        [0, opened.innerBytes],
        [1, opened.sig],
      ]),
    );
    const dh = x25519.getSharedSecret(C.encryptionSeed, A.encryptionPublicKey());
    const info = messageKeyInfo(
      C.manager.identityPublicKey(),
      C.manager.encryptionPublicKey(),
      A.identityPublicKey(),
      A.encryptionPublicKey(),
    );
    const K = hkdf(sha512, dh, CTX_MSG_HKDF_SALT, info, 32);
    const nonce = new Uint8Array(24).fill(5);
    const attackEnv = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1],
        [1, nonce],
        [2, xchacha20poly1305(K, nonce, Uint8Array.from([1])).encrypt(innerSigned)],
      ]),
    );

    // C decrypts (K correct) and the sender binding PASSES (inner sender_id == A == pinned),
    // so the recipient_id==us binding is the only thing standing between C and acceptance.
    await expect(open(C.manager, cViewOfA, attackEnv)).rejects.toThrow(/not addressed to us/);
  });

  it('[domain-sep] an inner signature over RAW inner bytes (no CTX_MSG_SIG label) is rejected', async () => {
    // Must-fix #8: the inner signature MUST cover CTX_MSG_SIG || inner_bytes. A signature
    // over the bare inner bytes must not verify.
    const { A, aViewOfB, B, bViewOfA } = await pair('noble');
    const inner = encodeDeterministic(
      new Map<number, unknown>([
        [0, A.identityPublicKey()],
        [1, B.identityPublicKey()],
        [2, 100],
        [3, te('unlabeled')],
      ]),
    );
    const sigRaw = await A.sign(inner); // signs the bare inner, WITHOUT the domain-sep label
    const innerSigned = encodeDeterministic(
      new Map<number, unknown>([
        [0, inner],
        [1, sigRaw],
      ]),
    );
    const key = await deriveMessageKey(A, aViewOfB);
    const nonce = new Uint8Array(24).fill(4);
    const env = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1],
        [1, nonce],
        [2, xchacha20poly1305(key, nonce, Uint8Array.from([1])).encrypt(innerSigned)],
      ]),
    );
    await expect(open(B, bViewOfA, env)).rejects.toThrow(/signature invalid/);
  });
});

// Keep the OpenedMessage / ContactCard type imports used (documentation of the surface).
export type _Surface = OpenedMessage | ContactCard;
