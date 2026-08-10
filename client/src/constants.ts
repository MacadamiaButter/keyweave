// Protocol constants and domain-separation labels. Everything here is PUBLIC
// (Kerckhoffs): none of these values is a secret, and none of the protocol's
// security may rest on an attacker not knowing them.

import { utf8 } from './bytes.js';

// Byte sizes (verified against the primitives at build time).
export const ED25519_PUB_LEN = 32;
export const ED25519_SIG_LEN = 64;
export const X25519_PUB_LEN = 32;
export const SEED_LEN = 32;
export const XCHACHA_NONCE_LEN = 24;
export const XCHACHA_KEY_LEN = 32;

// Wire/protocol versions. Each layer has an allowlist checked BEFORE any key
// derivation, so an out-of-range version can never reach a KDF.
export const CARD_VERSION = 1;
export const MESSAGE_VERSION = 1; // envelope `version` field
// v2 (fix-round-2): adds the persisted replay seen-set (VaultData key 5). A v1 blob
// written by round-0 code has no key 5, so key 5 is OPTIONAL when decoding a v1 blob
// and REQUIRED for v2 - see decodeVaultData. Bumping the version + allowlist keeps
// existing (format-1) vaults openable instead of dying in the decoder.
// v3 (messaging): adds the per-pairing mailbox coordinates (VaultData key 6). Same rule
// as key 5 one version down: OPTIONAL for a v1/v2 blob, REQUIRED for v3, so an older
// vault opens with no mailboxes instead of dying after the AEAD has already passed.
export const VAULT_FORMAT_VERSION = 3;

export const CARD_VERSION_ALLOWLIST: readonly number[] = [1];
export const MESSAGE_VERSION_ALLOWLIST: readonly number[] = [1];
export const VAULT_FORMAT_ALLOWLIST: readonly number[] = [1, 2, 3];

// Domain-separation strings (context/info labels). Kept distinct per use so a
// signature or key from one context can never be replayed into another.
export const CTX_CARD = utf8('keyweave-card-v1'); // signed over ctx || card_bytes
export const CTX_PAIR = utf8('keyweave-pair-v1'); // signed over ctx || sorted(cards) || sorted(nonces)
export const CTX_SAS = utf8('keyweave-sas-v1'); // hashed for the displayed safety number
export const CTX_MSG = utf8('keyweave-msg-v1'); // HKDF info prefix for the message key
export const CTX_MSG_SIG = utf8('keyweave-msgsig-v1'); // domain-sep label for the inner Ed25519 signature
export const CTX_MSGID = utf8('keyweave-msgid-v1'); // dedupe id over authenticated bytes
export const CTX_VAULT = utf8('keyweave-vault-v1'); // HKDF info for the vault content subkey
export const CTX_MSG_HKDF_SALT = utf8('keyweave-msg-hkdf-salt-v1');
// Signed over ctx || mailbox_id || write_cap. The mailbox coordinate is exchanged inside
// the ceremony but is NOT part of the pairing transcript, so it carries its own signature
// (src/mailbox.ts explains what that buys).
export const CTX_MAILBOX = utf8('keyweave-mailbox-v1');

// Clock-skew allowance for inner message timestamps (must-fix #2). An inner timestamp
// more than this far AHEAD of local time is rejected at open() BEFORE it can reach the
// per-sender high-water mark, so one future-dated message cannot brick a channel.
export const CLOCK_SKEW_MS = 24 * 60 * 60 * 1000; // 24h

// SAS safety-number sizing: 66 bits -> six 11-bit BIP-39 indices -> six words.
export const SAS_WORD_COUNT = 6;
export const SAS_BITS = SAS_WORD_COUNT * 11; // 66

// Pairing per-session nonce length.
export const PAIR_NONCE_LEN = 32;

// A relay mailbox id is 128 random bits; the relay routes on its 32 lowercase hex form.
export const MAILBOX_ID_LEN = 16;

// Relay capability tokens (write_cap, pull_token) are opaque to us: the relay mints them
// and we hand them back verbatim. The bound and the character set are a WALL against a
// relay-supplied string reaching a URL or a header, not a claim about how the relay
// generates them (43 characters of URL-safe base64 today). One definition, because the
// pairing layer, the relay client and the vault all have to agree on it.
export const CAP_TOKEN_RE = /^[A-Za-z0-9_-]{16,128}$/;

// KDF ids for the vault descriptor.
export const KDF_ARGON2ID = 1;

// Backend labels for the key layer (defense-in-depth / honesty about which path ran).
export type KeyBackend = 'webcrypto' | 'noble';
