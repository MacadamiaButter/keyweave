import { describe, it, expect } from 'vitest';
import { argon2id } from '@noble/hashes/argon2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';
import {
  ARGON2_CEILING,
  ARGON2_DEFAULT,
  ARGON2_FLOOR,
  createVaultBlob,
  decryptVaultBlob,
  Vault,
  type VaultData,
} from '../src/vault.js';
import {
  CTX_VAULT,
  KDF_ARGON2ID,
  XCHACHA_KEY_LEN,
  XCHACHA_NONCE_LEN,
} from '../src/constants.js';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard } from '../src/card.js';
import { decodeStrict, encodeDeterministic } from '../src/cbor.js';
import { bytesEqual, utf8 } from '../src/bytes.js';
import { verifyEd25519 } from '../src/validate.js';

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Floor params keep the suite fast while still exercising a real (>= OWASP) derivation.
const TEST_PARAMS = ARGON2_FLOOR;

async function sampleData(): Promise<VaultData & { idPub: Uint8Array }> {
  const me = await generateKeyManager('noble');
  const peer = await generateKeyManager('noble');
  const peerCard = await createSignedCard(peer.manager, 1);
  return {
    identitySeed: me.identitySeed,
    encryptionSeed: me.encryptionSeed,
    contacts: [peerCard],
    highWater: [{ senderId: peer.manager.identityPublicKey(), highWaterMs: 1234 }],
    seen: [
      {
        msgId: new Uint8Array(64).fill(7),
        senderId: peer.manager.identityPublicKey(),
        timestampMs: 1234,
      },
    ],
    messages: [
      {
        peerId: peer.manager.identityPublicKey(),
        direction: 'out',
        timestampMs: 5678,
        body: new TextEncoder().encode('hello vault'),
      },
    ],
    mailboxes: [],
    idPub: me.manager.identityPublicKey(),
  };
}

/** A brand-new vault: no marks, no seen-set. Same shape a first-run install writes. */
async function freshData(): Promise<VaultData & { peerId: Uint8Array }> {
  const me = await generateKeyManager('noble');
  const peer = await generateKeyManager('noble');
  return {
    identitySeed: me.identitySeed,
    encryptionSeed: me.encryptionSeed,
    contacts: [],
    highWater: [],
    seen: [],
    messages: [],
    mailboxes: [],
    peerId: peer.manager.identityPublicKey(),
  };
}

describe('encrypted vault', () => {
  it('round-trips seeds + contacts + messages + high-water marks', async () => {
    const data = await sampleData();
    const blob = createVaultBlob('correct horse battery staple', data, TEST_PARAMS);
    const back = decryptVaultBlob(blob, 'correct horse battery staple');
    expect(bytesEqual(back.identitySeed, data.identitySeed)).toBe(true);
    expect(bytesEqual(back.encryptionSeed, data.encryptionSeed)).toBe(true);
    expect(back.contacts).toHaveLength(1);
    expect(bytesEqual(back.contacts[0]!, data.contacts[0]!)).toBe(true);
    expect(back.highWater[0]!.highWaterMs).toBe(1234);
    // The in-window replay seen-set persists too (must-fix #1: eviction can't resurrect).
    expect(back.seen).toHaveLength(1);
    expect(bytesEqual(back.seen[0]!.msgId, new Uint8Array(64).fill(7))).toBe(true);
    expect(back.seen[0]!.timestampMs).toBe(1234);
    expect(back.messages[0]!.direction).toBe('out');
    expect(new TextDecoder().decode(back.messages[0]!.body)).toBe('hello vault');
  });

  it('[regression #2] a format-1 blob (no seen key) wrapped with the real KDF/AEAD decrypts, seen=[]', () => {
    // Round-0 code wrote VAULT_FORMAT_VERSION=1 with VaultData keys 0..4 (no seen-set at
    // key 5). After the fix-round-1 decoder made key 5 REQUIRED while the version stayed 1,
    // such a blob would AEAD-open and then die in the decoder ("missing required key 5") -
    // seeds unrecoverable. The fix bumps the version to 2 (allowlist [1,2]) and treats key 5
    // as OPTIONAL for a format-1 blob, defaulting seen=[]. Build a real format-1 blob here.
    const idSeed = randomBytes(32);
    const xSeed = randomBytes(32);
    // format-1 VaultData plaintext: keys 0..4 ONLY.
    const plaintext = encodeDeterministic(
      new Map<number, unknown>([
        [0, idSeed], // identity seed
        [1, xSeed], // encryption seed
        [2, []], // contacts
        [3, []], // highWater
        [4, []], // messages   (NO key 5 / seen-set - this is the format-1 shape)
      ]),
    );

    const params = ARGON2_FLOOR;
    const salt = randomBytes(16);
    const nonce = randomBytes(XCHACHA_NONCE_LEN);
    // Reconstruct the production descriptor AAD for format version 1 (authenticated).
    const aad = new Uint8Array(14 + salt.length);
    const dv = new DataView(aad.buffer);
    aad[0] = 1; // format version 1
    aad[1] = KDF_ARGON2ID;
    dv.setUint32(2, params.t, true);
    dv.setUint32(6, params.m, true);
    dv.setUint32(10, params.p, true);
    aad.set(salt, 14);
    // Real KDF (Argon2id -> HKDF-SHA512 subkey) + real XChaCha20-Poly1305, exactly as prod.
    const kWrap = argon2id(utf8('pw'), salt, {
      t: params.t,
      m: params.m,
      p: params.p,
      dkLen: XCHACHA_KEY_LEN,
    });
    const kEnc = hkdf(sha512, kWrap, undefined, CTX_VAULT, XCHACHA_KEY_LEN);
    const ciphertext = xchacha20poly1305(kEnc, nonce, aad).encrypt(plaintext);
    const blob = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1], // B_FORMAT = format version 1
        [1, KDF_ARGON2ID],
        [2, params.t],
        [3, params.m],
        [4, params.p],
        [5, salt],
        [6, nonce],
        [7, ciphertext],
      ]),
    );

    const back = decryptVaultBlob(blob, 'pw');
    expect(back.seen).toEqual([]); // key 5 absent -> defaulted, not a decode failure
    expect(bytesEqual(back.identitySeed, idSeed)).toBe(true);
    expect(bytesEqual(back.encryptionSeed, xSeed)).toBe(true);
  });

  it('wrong passphrase -> no unlock', async () => {
    const data = await sampleData();
    const blob = createVaultBlob('right', data, TEST_PARAMS);
    expect(() => decryptVaultBlob(blob, 'wrong')).toThrow(/unlock failed/);
  });

  it('a KDF-parameter DOWNGRADE in the stored blob is refused by the floor', async () => {
    const data = await sampleData();
    const blob = createVaultBlob('pw', data, TEST_PARAMS);
    // Attacker rewrites m below the floor to make cracking cheap.
    const m = decodeStrict<Map<number, unknown>>(blob);
    m.set(3, 8192); // m (KiB) < ARGON2_FLOOR.m
    const downgraded = encodeDeterministic(m);
    expect(() => decryptVaultBlob(downgraded, 'pw')).toThrow(/below floor/);
  });

  it('the KDF descriptor is AUTHENTICATED (tampering an in-floor param fails the AEAD)', async () => {
    const data = await sampleData();
    const blob = createVaultBlob('pw', data, { t: 2, m: 20_000, p: 1 });
    const m = decodeStrict<Map<number, unknown>>(blob);
    m.set(3, 21_000); // still >= floor, so it passes assertFloor, but AAD no longer matches
    const tampered = encodeDeterministic(m);
    expect(() => decryptVaultBlob(tampered, 'pw')).toThrow(/unlock failed/);
  });

  it('a KDF-parameter blow-up (t/m above the CEILING) is refused BEFORE the KDF runs', async () => {
    // Must-fix #7: without an upper wall a tampered blob claims t/m up to 0xffffffff, and
    // the KDF is spent (unbounded work / multi-TiB alloc) before the AEAD can detect the
    // tamper -> vault unopenable forever. The ceiling asserts BEFORE the KDF.
    const data = await sampleData();
    const blob = createVaultBlob('pw', data, ARGON2_FLOOR);
    // t above the ceiling. (Kept memory at the floor so that, were the guard ABSENT, the
    // KDF would still run cheaply and fail at the AEAD -> proves the ceiling is what fires.)
    const overT = decodeStrict<Map<number, unknown>>(blob);
    overT.set(2, ARGON2_CEILING.t + 1);
    expect(() => decryptVaultBlob(encodeDeterministic(overT), 'pw')).toThrow(/above ceiling/);
    // p above the ceiling is likewise refused.
    const overP = decodeStrict<Map<number, unknown>>(blob);
    overP.set(4, ARGON2_CEILING.p + 1);
    expect(() => decryptVaultBlob(encodeDeterministic(overP), 'pw')).toThrow(/above ceiling/);
    // createVaultBlob refuses an over-ceiling request up front too.
    expect(() =>
      createVaultBlob('pw', data, { t: 2, m: ARGON2_CEILING.m + 1, p: 1 }),
    ).toThrow(/above ceiling/);
  });

  it('rejects an unsupported kdf id / format version', async () => {
    const data = await sampleData();
    const blob = createVaultBlob('pw', data, TEST_PARAMS);
    const bad = decodeStrict<Map<number, unknown>>(blob);
    bad.set(1, 2); // kdf id 2 unknown
    expect(() => decryptVaultBlob(encodeDeterministic(bad), 'pw')).toThrow(/unsupported kdf/);
  });

  it('the production default is stronger than the floor and above the OWASP minimum', () => {
    expect(ARGON2_DEFAULT.m).toBeGreaterThanOrEqual(ARGON2_FLOOR.m);
    expect(ARGON2_DEFAULT.t).toBeGreaterThanOrEqual(ARGON2_FLOOR.t);
    // OWASP argon2id server-login minimum is m=19456 (19 MiB); offline device-theft wants more.
    expect(ARGON2_DEFAULT.m).toBeGreaterThan(19_456);
  });

  it('Vault: open, use keys, explicit lock zeroizes and blocks further use', async () => {
    const data = await sampleData();
    const blob = createVaultBlob('pw', data, TEST_PARAMS);
    const vault = await Vault.open(blob, 'pw', { idleMs: 0, backend: 'noble' });
    expect(vault.isLocked()).toBe(false);
    const km = vault.keys();
    const sig = await km.sign(new TextEncoder().encode('m'));
    expect(verifyEd25519(sig, new TextEncoder().encode('m'), km.identityPublicKey())).toBe(true);
    // Capture the vault's OWN held seed buffer (not the caller's original) to prove wipe.
    const heldSeed = vault.data_().identitySeed;
    expect(bytesEqual(heldSeed, new Uint8Array(32))).toBe(false);
    vault.lock();
    expect(vault.isLocked()).toBe(true);
    expect(() => vault.keys()).toThrow(/locked/);
    // The vault's held seed buffer was best-effort zeroized in place.
    expect(bytesEqual(heldSeed, new Uint8Array(32))).toBe(true);
  });

  it('Vault: idle re-lock fires after the timeout', async () => {
    const data = await sampleData();
    const blob = createVaultBlob('pw', data, TEST_PARAMS);
    let locked = false;
    const vault = await Vault.open(blob, 'pw', {
      idleMs: 30,
      backend: 'noble',
      onLock: () => {
        locked = true;
      },
    });
    expect(vault.isLocked()).toBe(false);
    await delay(80);
    expect(locked).toBe(true);
    expect(vault.isLocked()).toBe(true);
  });
});

// The durable arm of the replay defense. The guard, the export/restore pair and the
// persisted VaultData fields all existed; without the vault holding a guard across
// save/reopen the seen-set was written once and never read back, so a captured
// in-window message replayed after a restart was ACCEPTED.
describe('vault <-> replay guard wiring', () => {
  it('[pinning] an admit made through the vault dedupes after save + reopen', async () => {
    const data = await freshData();
    const v1 = await Vault.open(createVaultBlob('pw', data, TEST_PARAMS), 'pw', {
      idleMs: 0,
      backend: 'noble',
    });
    const ts = Date.now();
    const msgId = new Uint8Array(64).fill(0x11);
    expect(v1.replay().admit(data.peerId, ts, msgId)).toEqual({ accepted: true });
    const saved = v1.save('pw', TEST_PARAMS);

    // Unwired, the reopened guard is empty and the SAME authenticated msg-id is accepted
    // a second time - the restart is the replay window.
    const v2 = await Vault.open(saved, 'pw', { idleMs: 0, backend: 'noble' });
    expect(v2.replay().admit(data.peerId, ts, msgId)).toEqual({
      accepted: false,
      reason: 'duplicate',
    });
  });

  it('high-water marks advanced during the session survive save + reopen', async () => {
    const data = await freshData();
    const v1 = await Vault.open(createVaultBlob('pw', data, TEST_PARAMS), 'pw', {
      idleMs: 0,
      backend: 'noble',
    });
    const ts = Date.now() - 1000;
    expect(v1.replay().admit(data.peerId, ts, new Uint8Array(64).fill(0x22)).accepted).toBe(true);
    expect(v1.replay().highWaterFor(data.peerId)).toBe(ts);

    const v2 = await Vault.open(v1.save('pw', TEST_PARAMS), 'pw', { idleMs: 0, backend: 'noble' });
    expect(v2.replay().highWaterFor(data.peerId)).toBe(ts);
  });

  it('a fresh vault (empty highWater/seen) yields a working empty guard', async () => {
    const data = await freshData();
    const vault = await Vault.open(createVaultBlob('pw', data, TEST_PARAMS), 'pw', {
      idleMs: 0,
      backend: 'noble',
    });
    expect(vault.replay().seenCount()).toBe(0);
    expect(vault.replay().highWaterFor(data.peerId)).toBeUndefined();
    expect(vault.replay().admit(data.peerId, Date.now(), new Uint8Array(64).fill(0x33))).toEqual({
      accepted: true,
    });
  });

  it('replay() restores the persisted seen-set and throws once locked', async () => {
    const data = await sampleData();
    const vault = await Vault.open(createVaultBlob('pw', data, TEST_PARAMS), 'pw', {
      idleMs: 0,
      backend: 'noble',
    });
    expect(vault.replay().seenCount()).toBe(1); // the entry sampleData persisted
    vault.lock();
    // Sender ids are social-graph metadata: the guard must not outlive the unlocked session.
    expect(() => vault.replay()).toThrow(/locked/);
  });

  it('a caller-cached guard is DEACTIVATED at lock(), like a cached KeyManager', async () => {
    const data = await freshData();
    const vault = await Vault.open(createVaultBlob('pw', data, TEST_PARAMS), 'pw', {
      idleMs: 0,
      backend: 'noble',
    });
    // A receive loop that caches the guard at setup must not keep admitting across an
    // idle re-lock: post-lock admits could never become durable (save() throws), so a
    // still-live cached guard means silent data loss at the admit site.
    const cached = vault.replay();
    vault.lock();
    expect(() => cached.admit(data.peerId, Date.now(), new Uint8Array(64).fill(0x55))).toThrow(
      /guard destroyed/,
    );
    expect(() => cached.seenCount()).toThrow(/guard destroyed/);
    expect(() => cached.exportSeen()).toThrow(/guard destroyed/);
  });

  it('[upgrade residual, pinned] a format-1 blob yields a marks-plus-empty-seen guard', async () => {
    // v1 never persisted a seen-set, so after the v1 -> v2 upgrade an in-window message
    // the marks attest to is re-accepted ONCE. Nothing durable is resurrected; the first
    // save() rewrites as format 2 and closes it. Pinned so it reads as the documented
    // residual it is, not a rediscovered vulnerability.
    const peerId = randomBytes(32);
    const hwm = 1234;
    const plaintext = encodeDeterministic(
      new Map<number, unknown>([
        [0, randomBytes(32)],
        [1, randomBytes(32)],
        [2, []],
        [3, [[peerId, hwm]]], // marks WITHOUT a seen-set: the format-1 shape
        [4, []],
      ]),
    );
    const params = ARGON2_FLOOR;
    const salt = randomBytes(16);
    const nonce = randomBytes(XCHACHA_NONCE_LEN);
    const aad = new Uint8Array(14 + salt.length);
    const dv = new DataView(aad.buffer);
    aad[0] = 1; // format version 1
    aad[1] = KDF_ARGON2ID;
    dv.setUint32(2, params.t, true);
    dv.setUint32(6, params.m, true);
    dv.setUint32(10, params.p, true);
    aad.set(salt, 14);
    const kWrap = argon2id(utf8('pw'), salt, {
      t: params.t,
      m: params.m,
      p: params.p,
      dkLen: XCHACHA_KEY_LEN,
    });
    const kEnc = hkdf(sha512, kWrap, undefined, CTX_VAULT, XCHACHA_KEY_LEN);
    const ciphertext = xchacha20poly1305(kEnc, nonce, aad).encrypt(plaintext);
    const blob = encodeDeterministic(
      new Map<number, unknown>([
        [0, 1],
        [1, KDF_ARGON2ID],
        [2, params.t],
        [3, params.m],
        [4, params.p],
        [5, salt],
        [6, nonce],
        [7, ciphertext],
      ]),
    );

    const vault = await Vault.open(blob, 'pw', { idleMs: 0, backend: 'noble' });
    expect(vault.replay().highWaterFor(peerId)).toBe(hwm); // the marks survived
    // The residual, pinned: an in-window admit at the attested mark is accepted.
    expect(vault.replay().admit(peerId, hwm, new Uint8Array(64).fill(0x66))).toEqual({
      accepted: true,
    });
  });

  it('two saves in a row are stable (persisted admit kept, no duplication)', async () => {
    const data = await freshData();
    const vault = await Vault.open(createVaultBlob('pw', data, TEST_PARAMS), 'pw', {
      idleMs: 0,
      backend: 'noble',
    });
    const ts = Date.now();
    const msgId = new Uint8Array(64).fill(0x44);
    expect(vault.replay().admit(data.peerId, ts, msgId).accepted).toBe(true);

    const first = decryptVaultBlob(vault.save('pw', TEST_PARAMS), 'pw');
    const secondBlob = vault.save('pw', TEST_PARAMS);
    const second = decryptVaultBlob(secondBlob, 'pw');
    expect(first.seen).toHaveLength(1);
    expect(second.seen).toHaveLength(1); // refresh REPLACES the arrays, never appends
    expect(bytesEqual(second.seen[0]!.msgId, msgId)).toBe(true);
    expect(second.highWater).toHaveLength(1);
    expect(second.highWater[0]!.highWaterMs).toBe(ts);

    const reopened = await Vault.open(secondBlob, 'pw', { idleMs: 0, backend: 'noble' });
    expect(reopened.replay().admit(data.peerId, ts, msgId)).toEqual({
      accepted: false,
      reason: 'duplicate',
    });
  });
});

describe('format 3: per-pairing mailbox coordinates', () => {
  const CAP = 'aB3-_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz';

  it('round-trips the two coordinates and the outbound message state', async () => {
    const data = await sampleData();
    data.mailboxes = [
      {
        peerId: data.messages[0]!.peerId,
        inboxId: new Uint8Array(16).fill(0x11),
        inboxPullToken: CAP,
        outboxId: new Uint8Array(16).fill(0x22),
        outboxWriteCap: `${CAP.slice(0, -1)}Q`,
      },
    ];
    data.messages[0]!.msgId = new Uint8Array(64).fill(0x33);
    data.messages[0]!.delivery = 'queued';
    data.messages[0]!.wire = new Uint8Array([9, 8, 7]);

    const back = decryptVaultBlob(createVaultBlob('pw', data, TEST_PARAMS), 'pw');
    expect(back.mailboxes).toHaveLength(1);
    expect(back.mailboxes[0]!.inboxPullToken).toBe(CAP);
    expect(bytesEqual(back.mailboxes[0]!.outboxId, new Uint8Array(16).fill(0x22))).toBe(true);
    expect(back.messages[0]!.delivery).toBe('queued');
    expect([...(back.messages[0]!.wire ?? [])]).toEqual([9, 8, 7]);
    expect(bytesEqual(back.messages[0]!.msgId!, new Uint8Array(64).fill(0x33))).toBe(true);
  });

  it('a relayed message keeps no wire bytes, and an inbound one keeps no delivery state', async () => {
    const data = await sampleData();
    data.messages[0]!.delivery = 'relayed';
    data.messages.push({
      peerId: data.messages[0]!.peerId,
      direction: 'in',
      timestampMs: 9999,
      body: utf8('from them'),
      msgId: new Uint8Array(64).fill(0x55),
    });
    const back = decryptVaultBlob(createVaultBlob('pw', data, TEST_PARAMS), 'pw');
    expect(back.messages[0]!.wire).toBeUndefined();
    expect(back.messages[1]!.delivery).toBeUndefined();
    expect(back.messages[1]!.direction).toBe('in');
  });

  it('a format-2 blob (no key 6) opens with no mailboxes rather than dying after the AEAD', () => {
    // The same shape of upgrade the seen-set needed one version earlier: key 6 is OPTIONAL
    // for an older format and REQUIRED for 3, so an existing vault opens instead of taking
    // its seeds down with the decoder.
    const idSeed = randomBytes(32);
    const xSeed = randomBytes(32);
    const plaintext = encodeDeterministic(
      new Map<number, unknown>([
        [0, idSeed],
        [1, xSeed],
        [2, []],
        [3, []],
        [4, []],
        [5, []], // seen-set present, mailboxes (key 6) absent: the format-2 shape
      ]),
    );
    const back = decryptVaultBlob(wrapPlaintext(plaintext, 2, 'pw'), 'pw');
    expect(back.mailboxes).toEqual([]);
    expect(bytesEqual(back.identitySeed, idSeed)).toBe(true);
  });

  it('a stored capability token that is not one is refused on the way back in', async () => {
    // A vault edited outside the app must not be able to smuggle a token into a request
    // header. encodeVaultData refuses to write one, so the check is on the read path too.
    const data = await sampleData();
    const plaintext = encodeDeterministic(
      new Map<number, unknown>([
        [0, data.identitySeed],
        [1, data.encryptionSeed],
        [2, []],
        [3, []],
        [4, []],
        [5, []],
        [
          6,
          [
            [
              data.messages[0]!.peerId,
              new Uint8Array(16).fill(1),
              utf8(`ok${'a'.repeat(20)}`),
              new Uint8Array(16).fill(2),
              utf8('bad\r\nX-Injected: yes'),
            ],
          ],
        ],
      ]),
    );
    expect(() => decryptVaultBlob(wrapPlaintext(plaintext, 3, 'pw'), 'pw')).toThrow(
      /bad capability token/,
    );
  });

  it('refuses to WRITE a malformed capability token', async () => {
    const data = await sampleData();
    data.mailboxes = [
      {
        peerId: data.messages[0]!.peerId,
        inboxId: new Uint8Array(16).fill(1),
        inboxPullToken: 'too short',
        outboxId: new Uint8Array(16).fill(2),
        outboxWriteCap: CAP,
      },
    ];
    expect(() => createVaultBlob('pw', data, TEST_PARAMS)).toThrow(/malformed capability token/);
  });
});

/** Seal an arbitrary VaultData plaintext at a chosen format version, exactly as prod does. */
function wrapPlaintext(plaintext: Uint8Array, format: number, passphrase: string): Uint8Array {
  const params = ARGON2_FLOOR;
  const salt = randomBytes(16);
  const nonce = randomBytes(XCHACHA_NONCE_LEN);
  const aad = new Uint8Array(14 + salt.length);
  const dv = new DataView(aad.buffer);
  aad[0] = format;
  aad[1] = KDF_ARGON2ID;
  dv.setUint32(2, params.t, true);
  dv.setUint32(6, params.m, true);
  dv.setUint32(10, params.p, true);
  aad.set(salt, 14);
  const kWrap = argon2id(utf8(passphrase), salt, {
    t: params.t,
    m: params.m,
    p: params.p,
    dkLen: XCHACHA_KEY_LEN,
  });
  const kEnc = hkdf(sha512, kWrap, undefined, CTX_VAULT, XCHACHA_KEY_LEN);
  const ciphertext = xchacha20poly1305(kEnc, nonce, aad).encrypt(plaintext);
  return encodeDeterministic(
    new Map<number, unknown>([
      [0, format],
      [1, KDF_ARGON2ID],
      [2, params.t],
      [3, params.m],
      [4, params.p],
      [5, salt],
      [6, nonce],
      [7, ciphertext],
    ]),
  );
}
