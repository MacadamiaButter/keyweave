// At-rest vault (must-fix #3). A SINGLE encrypted vault holds the two key seeds, the
// contact store, and the message store - not just the seeds. K_wrap = Argon2id(passphrase),
// a content subkey is HKDF'd from it, and the AEAD covers everything under one nonce.
//
//   K_wrap  = Argon2id(passphrase, salt, {t,m,p})           // tuned for OFFLINE device theft
//   K_enc   = HKDF-SHA512(K_wrap, info=CTX_VAULT)            // subkey of the one K_wrap
//   blob    = { format_version, kdf_id, t, m, p, salt, nonce, ciphertext }
//   AAD     = format_version || kdf_id || t || m || p || salt   // FULL KDF descriptor
//   cipher  = XChaCha20-Poly1305(K_enc, nonce, AAD).encrypt(dCBOR(VaultData))
//
// The descriptor is AUTHENTICATED (in the AAD) so parameters cannot be silently
// downgraded, and a hard MINIMUM-PARAMETER FLOOR is enforced at read time BEFORE the
// KDF runs. Lock model: idle re-lock + best-effort zeroization into one module-scoped
// scratch buffer. NAMED RESIDUAL (R5): JavaScript cannot GUARANTEE zeroization - GC
// copies, immutable strings, and a live/unlocked or non-FDE device are out of scope.

import { argon2id } from '@noble/hashes/argon2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';
import {
  CAP_TOKEN_RE,
  CTX_VAULT,
  ED25519_PUB_LEN,
  KDF_ARGON2ID,
  MAILBOX_ID_LEN,
  SEED_LEN,
  VAULT_FORMAT_ALLOWLIST,
  VAULT_FORMAT_VERSION,
  XCHACHA_KEY_LEN,
  XCHACHA_NONCE_LEN,
  type KeyBackend,
} from './constants.js';
import { assertLength, bytesEqual, utf8, zeroize } from './bytes.js';
import { decodeMapExact, decodeStrict, encodeDeterministic, getBytes, getUint } from './cbor.js';
import { keyManagerFromSeeds, type KeyManager } from './keys.js';
import { ReplayGuard, type HighWaterEntry, type SeenEntry } from './replay.js';

export interface Argon2Params {
  t: number; // iterations
  m: number; // memory in KiB
  p: number; // parallelism
}

// OWASP argon2id server-login minimum used as the ABSOLUTE floor; a stored blob claiming
// anything weaker is refused. This is the downgrade wall, not the tuning target.
export const ARGON2_FLOOR: Readonly<Argon2Params> = { t: 2, m: 19_456, p: 1 };

// Upper wall (must-fix #7). Without a ceiling, a tampered blob can claim t/m/p up to
// 0xffffffff - the KDF is spent (multi-TiB allocation / effectively unbounded work)
// BEFORE the AEAD ever gets a chance to detect the tamper, so the vault becomes
// unopenable forever. Asserted next to the floor, BEFORE the KDF runs.
export const ARGON2_CEILING: Readonly<Argon2Params> = { t: 10, m: 1_048_576, p: 4 }; // m: 1 GiB

// Production default, tuned HIGHER for offline device-theft cracking (256 MiB, 3 passes).
export const ARGON2_DEFAULT: Readonly<Argon2Params> = { t: 3, m: 262_144, p: 1 };

const SALT_LEN = 16;

export type MessageDirection = 'in' | 'out';

/**
 * How far an OUTBOUND message got. There is no third value: delete-on-pull is at-most-once
 * (R9) and v0 has no acknowledgement, so nothing this device can observe distinguishes
 * "the peer has it" from "the relay still holds it". The UI is held to saying only this.
 */
export type MessageDelivery = 'queued' | 'relayed';

export interface MessageRecord {
  peerId: Uint8Array; // Ed25519 identity pub of the peer
  direction: MessageDirection;
  timestampMs: number;
  body: Uint8Array;
  /** Authenticated dedupe id (seal.ts computeMsgId). Absent in a pre-messaging record. */
  msgId?: Uint8Array;
  /**
   * INBOUND ONLY: this device's own clock when the message was admitted. `timestampMs` is
   * the sender's authenticated clock and is what the thread sorts on, so on its own it lets
   * the relay decide where a message lands: hold a blob back and release it days later and
   * it files itself into history the reader has already been through. This is the local
   * fact that makes the gap visible. Absent on a record admitted before it existed.
   */
  receivedAtMs?: number;
  /** Outbound only. */
  delivery?: MessageDelivery;
  /**
   * Outbound and still queued: the sealed envelope, kept so a retry re-PUTs the SAME bytes
   * rather than minting a second message the peer would see twice. Dropped once the relay
   * has accepted it, so a conversation does not carry a second copy of itself forever.
   */
  wire?: Uint8Array;
}

/**
 * One pairing's two mailboxes, one per DIRECTION. R8's property is that nobody outside the
 * pairing holds a cap and no other pairing shares the budget; a single shared mailbox would
 * satisfy that and still be broken, because delete-on-pull means a device polling the shared
 * box pulls and destroys its OWN outbound message before the peer ever sees it, and a blob
 * is opaque so it cannot be filtered without pulling it. Split by direction, every mailbox
 * has exactly one writer and exactly one reader, and each side holds exactly one capability
 * for each of the two (anchor `leastpriv`).
 */
export interface MailboxPairing {
  peerId: Uint8Array; // 32
  /** The mailbox WE read. We hold its pull token; the peer holds its write cap. */
  inboxId: Uint8Array; // 16
  inboxPullToken: string;
  /** The mailbox THEY read. We hold its write cap and cannot read it. */
  outboxId: Uint8Array; // 16
  outboxWriteCap: string;
}

export interface VaultData {
  identitySeed: Uint8Array; // 32
  encryptionSeed: Uint8Array; // 32
  contacts: Uint8Array[]; // signed card wire bytes
  highWater: HighWaterEntry[];
  /** In-window replay seen-set (must-fix #1): persisted so eviction can't resurrect. */
  seen: SeenEntry[];
  messages: MessageRecord[];
  /** Per-pairing mailbox coordinates (format 3). */
  mailboxes: MailboxPairing[];
}

// Vault blob keys.
const B_FORMAT = 0;
const B_KDF = 1;
const B_T = 2;
const B_M = 3;
const B_P = 4;
const B_SALT = 5;
const B_NONCE = 6;
const B_CIPHERTEXT = 7;

// VaultData keys.
const V_ID_SEED = 0;
const V_X_SEED = 1;
const V_CONTACTS = 2;
const V_HIGHWATER = 3;
const V_MESSAGES = 4;
const V_SEEN = 5;
const V_MAILBOXES = 6;

// MessageRecord keys.
const M_PEER = 0;
const M_DIRECTION = 1;
const M_TIMESTAMP = 2;
const M_BODY = 3;
const M_MSGID = 4;
const M_DELIVERY = 5;
const M_WIRE = 6;
const M_RECEIVED = 7;

const MSGID_LEN = 64;

// The single module-scoped scratch region for the most sensitive material (the seeds).
// Best-effort; see the residual note above.
const SCRATCH_SEEDS = new Uint8Array(SEED_LEN * 2);

function descriptorAAD(format: number, kdfId: number, params: Argon2Params, salt: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + 1 + 4 + 4 + 4 + salt.length);
  const dv = new DataView(buf.buffer);
  buf[0] = format;
  buf[1] = kdfId;
  dv.setUint32(2, params.t, true);
  dv.setUint32(6, params.m, true);
  dv.setUint32(10, params.p, true);
  buf.set(salt, 14);
  return buf;
}

function assertFloor(params: Argon2Params): void {
  if (params.t < ARGON2_FLOOR.t || params.m < ARGON2_FLOOR.m || params.p < ARGON2_FLOOR.p) {
    throw new Error(
      `vault: KDF parameters below floor (t${params.t}/m${params.m}/p${params.p} < ` +
        `t${ARGON2_FLOOR.t}/m${ARGON2_FLOOR.m}/p${ARGON2_FLOOR.p}) - refusing downgrade`,
    );
  }
}

function assertCeiling(params: Argon2Params): void {
  if (params.t > ARGON2_CEILING.t || params.m > ARGON2_CEILING.m || params.p > ARGON2_CEILING.p) {
    throw new Error(
      `vault: KDF parameters above ceiling (t${params.t}/m${params.m}/p${params.p} > ` +
        `t${ARGON2_CEILING.t}/m${ARGON2_CEILING.m}/p${ARGON2_CEILING.p}) - refusing to spend the KDF`,
    );
  }
}

function deriveWrapKey(passphrase: string, salt: Uint8Array, params: Argon2Params): Uint8Array {
  const pw = utf8(passphrase);
  const kWrap = argon2id(pw, salt, { t: params.t, m: params.m, p: params.p, dkLen: XCHACHA_KEY_LEN });
  zeroize(pw);
  const kEnc = hkdf(sha512, kWrap, undefined, CTX_VAULT, XCHACHA_KEY_LEN);
  zeroize(kWrap);
  return kEnc;
}

function encodeVaultData(data: VaultData): Uint8Array {
  assertLength(data.identitySeed, SEED_LEN, 'identitySeed');
  assertLength(data.encryptionSeed, SEED_LEN, 'encryptionSeed');
  const messages = data.messages.map((mr) => {
    const rec = new Map<number, unknown>([
      [M_PEER, mr.peerId],
      [M_DIRECTION, mr.direction === 'out' ? 1 : 0],
      [M_TIMESTAMP, mr.timestampMs],
      [M_BODY, mr.body],
    ]);
    // Written only when they carry something. A received message has no delivery state and
    // a relayed one has no wire bytes, so an always-present key would store a placeholder
    // the decoder then has to interpret.
    if (mr.msgId !== undefined) rec.set(M_MSGID, mr.msgId);
    if (mr.delivery !== undefined) rec.set(M_DELIVERY, mr.delivery === 'relayed' ? 1 : 0);
    if (mr.wire !== undefined) rec.set(M_WIRE, mr.wire);
    if (mr.receivedAtMs !== undefined) rec.set(M_RECEIVED, mr.receivedAtMs);
    return rec;
  });
  const highWater = data.highWater.map((h) => [h.senderId, h.highWaterMs]);
  const seen = data.seen.map((s) => [s.msgId, s.senderId, s.timestampMs]);
  const mailboxes = data.mailboxes.map((mb) => {
    if (!CAP_TOKEN_RE.test(mb.inboxPullToken) || !CAP_TOKEN_RE.test(mb.outboxWriteCap)) {
      throw new Error('vault: refusing to store a malformed capability token');
    }
    return [mb.peerId, mb.inboxId, utf8(mb.inboxPullToken), mb.outboxId, utf8(mb.outboxWriteCap)];
  });
  const map = new Map<number, unknown>([
    [V_ID_SEED, data.identitySeed],
    [V_X_SEED, data.encryptionSeed],
    [V_CONTACTS, data.contacts],
    [V_HIGHWATER, highWater],
    [V_MESSAGES, messages],
    [V_SEEN, seen],
    [V_MAILBOXES, mailboxes],
  ]);
  return encodeDeterministic(map);
}

function decodeVaultData(bytes: Uint8Array, format: number): VaultData {
  // The seen-set (key 5) landed in format 2. A format-1 blob (round-0 code) never
  // wrote it, so it is OPTIONAL for v1 and REQUIRED for v2 - a v1 blob defaults
  // seen=[] instead of dying in the decoder after the AEAD has already passed.
  // UPGRADE RESIDUAL: the guard restored from a v1 blob is marks-plus-empty-seen, so
  // an in-window message its marks attest to is re-accepted ONCE (nothing durable is
  // resurrected - v1 never persisted a seen-set). The first save() rewrites format 2.
  const seenRequired = format >= 2;
  // Key 6 landed in format 3 for exactly the same reason key 5 landed in format 2: a v1/v2
  // blob never wrote it, and dying in the decoder after the AEAD has passed would take the
  // seeds with it.
  const mailboxesRequired = format >= 3;
  const m = decodeMapExact(bytes, {
    [V_ID_SEED]: { type: 'bytes', len: SEED_LEN },
    [V_X_SEED]: { type: 'bytes', len: SEED_LEN },
    [V_CONTACTS]: { type: 'array' },
    [V_HIGHWATER]: { type: 'array' },
    [V_MESSAGES]: { type: 'array' },
    [V_SEEN]: { type: 'array', optional: !seenRequired },
    [V_MAILBOXES]: { type: 'array', optional: !mailboxesRequired },
  });
  // IMPORTANT: cbor2 returns byte-strings as VIEWS into the source buffer. We copy
  // every retained byte-string so the caller can safely zeroize the plaintext buffer.
  const contactsRaw = m.get(V_CONTACTS) as unknown[];
  const contacts = contactsRaw.map((c) => {
    if (!(c instanceof Uint8Array)) throw new Error('vault: contact entry not bytes');
    return Uint8Array.from(c);
  });
  const highWater = (m.get(V_HIGHWATER) as unknown[]).map((h) => {
    if (!Array.isArray(h) || h.length !== 2) throw new Error('vault: bad highwater entry');
    const [senderId, hwm] = h as [unknown, unknown];
    if (!(senderId instanceof Uint8Array) || senderId.length !== ED25519_PUB_LEN) {
      throw new Error('vault: bad highwater sender');
    }
    if (typeof hwm !== 'number' || !Number.isInteger(hwm) || hwm < 0) {
      throw new Error('vault: bad highwater value');
    }
    return { senderId: Uint8Array.from(senderId), highWaterMs: hwm } satisfies HighWaterEntry;
  });
  const messages = (m.get(V_MESSAGES) as unknown[]).map((rec) => {
    if (!(rec instanceof Map)) throw new Error('vault: bad message record');
    const peerId = rec.get(M_PEER);
    const dir = rec.get(M_DIRECTION);
    const ts = rec.get(M_TIMESTAMP);
    const body = rec.get(M_BODY);
    if (!(peerId instanceof Uint8Array) || peerId.length !== ED25519_PUB_LEN) {
      throw new Error('vault: bad message peerId');
    }
    if (dir !== 0 && dir !== 1) throw new Error('vault: bad message direction');
    if (typeof ts !== 'number' || !Number.isInteger(ts) || ts < 0) {
      throw new Error('vault: bad message timestamp');
    }
    if (!(body instanceof Uint8Array)) throw new Error('vault: bad message body');
    const out: MessageRecord = {
      peerId: Uint8Array.from(peerId),
      direction: (dir === 1 ? 'out' : 'in') as MessageDirection,
      timestampMs: ts,
      body: Uint8Array.from(body),
    };
    const msgId = rec.get(M_MSGID);
    if (msgId !== undefined) {
      if (!(msgId instanceof Uint8Array) || msgId.length !== MSGID_LEN) {
        throw new Error('vault: bad message msgId');
      }
      out.msgId = Uint8Array.from(msgId);
    }
    const delivery = rec.get(M_DELIVERY);
    if (delivery !== undefined) {
      if (delivery !== 0 && delivery !== 1) throw new Error('vault: bad message delivery');
      out.delivery = delivery === 1 ? 'relayed' : 'queued';
    }
    const wire = rec.get(M_WIRE);
    if (wire !== undefined) {
      if (!(wire instanceof Uint8Array)) throw new Error('vault: bad message wire');
      out.wire = Uint8Array.from(wire);
    }
    const receivedAt = rec.get(M_RECEIVED);
    if (receivedAt !== undefined) {
      if (typeof receivedAt !== 'number' || !Number.isInteger(receivedAt) || receivedAt < 0) {
        throw new Error('vault: bad message receivedAtMs');
      }
      out.receivedAtMs = receivedAt;
    }
    return out;
  });
  const seenRaw = (m.get(V_SEEN) as unknown[] | undefined) ?? []; // absent in a format-1 blob
  const seen = seenRaw.map((s) => {
    if (!Array.isArray(s) || s.length !== 3) throw new Error('vault: bad seen entry');
    const [msgId, senderId, ts] = s as [unknown, unknown, unknown];
    if (!(msgId instanceof Uint8Array) || msgId.length !== 64) {
      throw new Error('vault: bad seen msgId');
    }
    if (!(senderId instanceof Uint8Array) || senderId.length !== ED25519_PUB_LEN) {
      throw new Error('vault: bad seen sender');
    }
    if (typeof ts !== 'number' || !Number.isInteger(ts) || ts < 0) {
      throw new Error('vault: bad seen timestamp');
    }
    return {
      msgId: Uint8Array.from(msgId),
      senderId: Uint8Array.from(senderId),
      timestampMs: ts,
    } satisfies SeenEntry;
  });
  const mailboxRaw = (m.get(V_MAILBOXES) as unknown[] | undefined) ?? []; // absent before v3
  const mailboxes = mailboxRaw.map((entry) => {
    if (!Array.isArray(entry) || entry.length !== 5) throw new Error('vault: bad mailbox entry');
    const [peerId, inboxId, pullToken, outboxId, writeCap] = entry as unknown[];
    if (!(peerId instanceof Uint8Array) || peerId.length !== ED25519_PUB_LEN) {
      throw new Error('vault: bad mailbox peer');
    }
    if (!(inboxId instanceof Uint8Array) || inboxId.length !== MAILBOX_ID_LEN) {
      throw new Error('vault: bad inbox id');
    }
    if (!(outboxId instanceof Uint8Array) || outboxId.length !== MAILBOX_ID_LEN) {
      throw new Error('vault: bad outbox id');
    }
    // Re-validated on the way back in, like every stored card: a vault edited outside the
    // app must not be able to smuggle a token into a request header.
    return {
      peerId: Uint8Array.from(peerId),
      inboxId: Uint8Array.from(inboxId),
      inboxPullToken: decodeCap(pullToken),
      outboxId: Uint8Array.from(outboxId),
      outboxWriteCap: decodeCap(writeCap),
    } satisfies MailboxPairing;
  });
  return {
    identitySeed: Uint8Array.from(getBytes(m, V_ID_SEED)),
    encryptionSeed: Uint8Array.from(getBytes(m, V_X_SEED)),
    contacts,
    highWater,
    seen,
    messages,
    mailboxes,
  };
}

const CAP_DECODER = new TextDecoder('utf-8', { fatal: true });

function decodeCap(value: unknown): string {
  if (!(value instanceof Uint8Array)) throw new Error('vault: bad capability token');
  let text: string;
  try {
    text = CAP_DECODER.decode(value);
  } catch {
    throw new Error('vault: bad capability token');
  }
  if (!CAP_TOKEN_RE.test(text)) throw new Error('vault: bad capability token');
  return text;
}

/** Encrypt `data` into a vault blob. `data` seeds are the caller's to zeroize afterward. */
export function createVaultBlob(
  passphrase: string,
  data: VaultData,
  params: Argon2Params = ARGON2_DEFAULT,
): Uint8Array {
  assertFloor(params);
  assertCeiling(params);
  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(XCHACHA_NONCE_LEN);
  const aad = descriptorAAD(VAULT_FORMAT_VERSION, KDF_ARGON2ID, params, salt);
  const kEnc = deriveWrapKey(passphrase, salt, params);
  const plaintext = encodeVaultData(data);
  const ciphertext = xchacha20poly1305(kEnc, nonce, aad).encrypt(plaintext);
  zeroize(kEnc, plaintext);

  const blob = new Map<number, unknown>([
    [B_FORMAT, VAULT_FORMAT_VERSION],
    [B_KDF, KDF_ARGON2ID],
    [B_T, params.t],
    [B_M, params.m],
    [B_P, params.p],
    [B_SALT, salt],
    [B_NONCE, nonce],
    [B_CIPHERTEXT, ciphertext],
  ]);
  return encodeDeterministic(blob);
}

/** Decrypt a vault blob. Enforces the format allowlist and the KDF floor BEFORE the KDF. */
export function decryptVaultBlob(blob: Uint8Array, passphrase: string): VaultData {
  const m = decodeMapExact(blob, {
    [B_FORMAT]: { type: 'uint', max: 255 },
    [B_KDF]: { type: 'uint', max: 255 },
    [B_T]: { type: 'uint', max: 0xffff_ffff },
    [B_M]: { type: 'uint', max: 0xffff_ffff },
    [B_P]: { type: 'uint', max: 0xffff_ffff },
    [B_SALT]: { type: 'bytes', len: SALT_LEN },
    [B_NONCE]: { type: 'bytes', len: XCHACHA_NONCE_LEN },
    [B_CIPHERTEXT]: { type: 'bytes' },
  });

  const format = getUint(m, B_FORMAT);
  if (!VAULT_FORMAT_ALLOWLIST.includes(format)) throw new Error(`vault: unsupported format ${format}`);
  const kdfId = getUint(m, B_KDF);
  if (kdfId !== KDF_ARGON2ID) throw new Error(`vault: unsupported kdf ${kdfId}`);

  const params: Argon2Params = { t: getUint(m, B_T), m: getUint(m, B_M), p: getUint(m, B_P) };
  assertFloor(params); // downgrade wall, BEFORE spending the KDF
  assertCeiling(params); // upper wall (must-fix #7), also BEFORE spending the KDF

  const salt = getBytes(m, B_SALT);
  const nonce = getBytes(m, B_NONCE);
  const ciphertext = getBytes(m, B_CIPHERTEXT);
  const aad = descriptorAAD(format, kdfId, params, salt);

  const kEnc = deriveWrapKey(passphrase, salt, params);
  let plaintext: Uint8Array;
  try {
    plaintext = xchacha20poly1305(kEnc, nonce, aad).decrypt(ciphertext);
  } catch {
    zeroize(kEnc);
    throw new Error('vault: unlock failed (wrong passphrase or tampered blob)');
  }
  zeroize(kEnc);
  const data = decodeVaultData(plaintext, format);
  zeroize(plaintext);
  return data;
}

export interface VaultOpenOptions {
  idleMs?: number;
  backend?: 'auto' | KeyBackend;
  /** Auto-lock callback (test/observability hook). */
  onLock?: () => void;
}

/** A live, unlocked vault: holds decrypted data + a KeyManager, with idle re-lock. */
export class Vault {
  private data: VaultData | undefined;
  private km: KeyManager | undefined;
  // The session's live replay state. Persisted state alone is inert: the guard is what
  // makes the durable seen-set an actual dedupe layer, so it is constructed EAGERLY at
  // open() (a lazily-built guard leaves a window where a caller admits against nothing).
  private guard: ReplayGuard | undefined;
  private idleTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly idleMs: number;
  private readonly onLock: (() => void) | undefined;

  private constructor(
    data: VaultData,
    km: KeyManager,
    guard: ReplayGuard,
    idleMs: number,
    onLock?: () => void,
  ) {
    this.data = data;
    this.km = km;
    this.guard = guard;
    this.idleMs = idleMs;
    this.onLock = onLock;
    this.touch();
  }

  static async open(blob: Uint8Array, passphrase: string, opts: VaultOpenOptions = {}): Promise<Vault> {
    return Vault.fromData(decryptVaultBlob(blob, passphrase), opts);
  }

  /**
   * Build a live Vault from ALREADY-DECRYPTED data, i.e. open() minus the KDF. It exists
   * because Argon2id at ARGON2_DEFAULT is a multi-second synchronous pass (measured 3.2s
   * on the reference box), and a browser that runs it on the UI thread is frozen for the
   * duration. The browser client runs decryptVaultBlob/createVaultBlob in a worker and
   * builds the session here. Same construction path as open(), including the eager
   * ReplayGuard: there is still no way to get a Vault whose guard is absent.
   */
  static async fromData(data: VaultData, opts: VaultOpenOptions = {}): Promise<Vault> {
    // Copy seeds into the single module-scoped scratch region.
    SCRATCH_SEEDS.set(data.identitySeed, 0);
    SCRATCH_SEEDS.set(data.encryptionSeed, SEED_LEN);
    const km = await keyManagerFromSeeds(
      SCRATCH_SEEDS.subarray(0, SEED_LEN),
      SCRATCH_SEEDS.subarray(SEED_LEN, SEED_LEN * 2),
      opts.backend ?? 'auto',
    );
    // BOTH arms, always (regression #1): marks without the seen-set would accept a
    // captured in-window replay. A fresh vault's empty arrays yield an empty guard
    // through this same path - there is no separate fresh-vault construction.
    const guard = ReplayGuard.restore(data.highWater, data.seen);
    return new Vault(data, km, guard, opts.idleMs ?? 5 * 60_000, opts.onLock);
  }

  private assertUnlocked(): { data: VaultData; km: KeyManager; guard: ReplayGuard } {
    if (!this.data || !this.km || !this.guard) throw new Error('vault: locked');
    this.touch();
    return { data: this.data, km: this.km, guard: this.guard };
  }

  keys(): KeyManager {
    return this.assertUnlocked().km;
  }

  data_(): VaultData {
    return this.assertUnlocked().data;
  }

  /** The unlocked session's replay guard. Its admits become durable at save(). */
  replay(): ReplayGuard {
    return this.assertUnlocked().guard;
  }

  /** The two mailboxes agreed with one peer, or undefined when that pairing has none. */
  mailboxFor(peerId: Uint8Array): MailboxPairing | undefined {
    const { data } = this.assertUnlocked();
    return data.mailboxes.find((mb) => bytesEqual(mb.peerId, peerId));
  }

  /**
   * Record (or replace) one pairing's mailboxes. Replacement is the supersede path: a fresh
   * ceremony mints fresh mailboxes, and keeping the old pair would leave this device reading
   * a box the peer no longer writes. Durable only once the caller saves.
   */
  putMailbox(pairing: MailboxPairing): void {
    const { data } = this.assertUnlocked();
    const at = data.mailboxes.findIndex((mb) => bytesEqual(mb.peerId, pairing.peerId));
    if (at >= 0) data.mailboxes[at] = pairing;
    else data.mailboxes.push(pairing);
  }

  /**
   * Put the mailbox table back to an image taken before a putMailbox. The INVERSE of the
   * call above, for the one caller that mutates and then awaits a write that can fail
   * (ui/session.ts commit()): a mailbox that survives a failed write belongs to a pairing
   * the app has just said was not saved.
   *
   * A whole image rather than a peer id to drop, because putMailbox either REPLACES an
   * entry or APPENDS one and only the first has a previous value; one inverse is correct
   * for both without the caller having to remember which happened. In place rather than by
   * reassignment, so a caller holding data_() sees the same array afterwards.
   */
  restoreMailboxes(mailboxes: readonly MailboxPairing[]): void {
    const { data } = this.assertUnlocked();
    data.mailboxes.splice(0, data.mailboxes.length, ...mailboxes);
  }

  isLocked(): boolean {
    return this.data === undefined;
  }

  /** Reset the idle re-lock timer. */
  touch(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    if (this.idleMs > 0 && this.idleMs !== Infinity) {
      this.idleTimer = setTimeout(() => this.lock(), this.idleMs);
      // Do not keep the process alive just for the idle timer.
      (this.idleTimer as { unref?: () => void }).unref?.();
    }
  }

  /** Best-effort lock: zeroize scratch + seeds + destroy the KeyManager. */
  lock(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
    }
    if (this.data) {
      zeroize(this.data.identitySeed, this.data.encryptionSeed);
    }
    zeroize(SCRATCH_SEEDS);
    this.km?.destroy();
    this.km = undefined;
    this.data = undefined;
    // destroy(), not just a dropped reference: a caller-cached guard would otherwise
    // keep accepting admits after lock - silently, since save() throws 'vault: locked'
    // and those admits could never become durable. destroy() also clears the seen-set
    // (sender-identity metadata that must not outlive the unlocked session). RESIDUAL:
    // an UNSAVED admit is simply gone - an in-window replay of it IS re-accepted after
    // reopen (the window only hard-rejects far-past timestamps; the seen-set is the
    // in-window wall and it covers only what reached disk). Callers must save()
    // promptly after admitting.
    this.guard?.destroy();
    this.guard = undefined;
    this.onLock?.();
  }

  /**
   * The LIVE VaultData with replay state refreshed from the guard, ready for an encryptor
   * that runs somewhere else (the browser client's KDF worker). Not a copy: mutating the
   * returned object mutates the session.
   *
   * A caller that uses this INSTEAD of save() takes on save()'s obligation unchanged: an
   * admit that never reaches a blob is lost at lock, and an in-window replay of it is
   * accepted again after reopen. Encrypt and persist promptly.
   */
  snapshot(): VaultData {
    const { data, guard } = this.assertUnlocked();
    // Refresh from the live guard BEFORE encoding, or admits made since open() never
    // reach the blob. exportSeen() prunes on the way out: this call IS the "on save"
    // arm of the guard's bounded prune schedule, so persisted state stays window-bounded.
    data.highWater = guard.exportHighWater();
    data.seen = guard.exportSeen();
    return data;
  }

  /** Re-encrypt current data to a fresh blob (e.g. after adding a contact/message). */
  save(passphrase: string, params: Argon2Params = ARGON2_DEFAULT): Uint8Array {
    return createVaultBlob(passphrase, this.snapshot(), params);
  }
}
