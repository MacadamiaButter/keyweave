// The mailbox coordinate: its codec, its signature, and the two properties that made it a
// payload inside the ceremony rather than a field in the card.

import { describe, it, expect } from 'vitest';
import { generateKeyManager } from '../src/keys.js';
import { createSignedCard, importCard } from '../src/card.js';
import {
  CAP_TOKEN_RE,
  ED25519_SIG_LEN,
  MAILBOX_ID_LEN,
  PAIR_NONCE_LEN,
} from '../src/constants.js';
import {
  PAIRING_INFO_MAGIC,
  decodePairingInfo,
  encodePairingInfo,
  fromRelayMailboxId,
  looksLikePairingInfo,
  mailboxSignatureValid,
  signMailboxCoordinate,
  toRelayMailboxId,
  type MailboxCoordinate,
} from '../src/mailbox.js';
import { decodeStrict, encodeDeterministic } from '../src/cbor.js';

const NONCE = new Uint8Array(PAIR_NONCE_LEN).fill(0x5a);
const COORD: MailboxCoordinate = {
  id: new Uint8Array(MAILBOX_ID_LEN).fill(0xab),
  writeCap: 'aB3-_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
};

describe('the coordinate codec', () => {
  it('round-trips a nonce with no mailbox', () => {
    const payload = encodePairingInfo(NONCE);
    const back = decodePairingInfo(payload);
    expect([...back.nonce]).toEqual([...NONCE]);
    expect(back.mailbox).toBeUndefined();
    expect(back.mailboxSig).toBeUndefined();
  });

  it('round-trips a nonce with a signed mailbox', async () => {
    const km = (await generateKeyManager('noble')).manager;
    const sig = await signMailboxCoordinate(km, COORD);
    const back = decodePairingInfo(encodePairingInfo(NONCE, COORD, sig));
    expect(back.mailbox?.writeCap).toBe(COORD.writeCap);
    expect([...(back.mailbox?.id ?? [])]).toEqual([...COORD.id]);
    expect(mailboxSignatureValid(back.mailbox!, back.mailboxSig!, km.identityPublicKey())).toBe(
      true,
    );
  });

  it('is plaintext on the wire, which is the patent limitation this transport keeps', () => {
    // Not "decodes to the same thing", which any reversible transform would satisfy. The
    // bytes after the tag ARE the CBOR map, readable by a decoder holding no key at all.
    const payload = encodePairingInfo(NONCE);
    expect(looksLikePairingInfo(payload)).toBe(true);
    const map = decodeStrict<Map<number, unknown>>(payload.subarray(PAIRING_INFO_MAGIC.length));
    expect(map.get(0)).toBeInstanceOf(Uint8Array);
    expect([...(map.get(0) as Uint8Array)]).toEqual([...NONCE]);
  });

  it('refuses a half-present coordinate, in every direction', () => {
    const full = new Map<number, unknown>([
      [0, NONCE],
      [1, COORD.id],
      [2, new TextEncoder().encode(COORD.writeCap)],
      [3, new Uint8Array(ED25519_SIG_LEN)],
    ]);
    for (const drop of [1, 2, 3]) {
      const partial = new Map(full);
      partial.delete(drop);
      const bytes = concat(PAIRING_INFO_MAGIC, encodeDeterministic(partial));
      expect(() => decodePairingInfo(bytes), `dropped key ${drop}`).toThrow(
        /must carry id, cap and signature/,
      );
    }
    // And the whole thing still decodes when nothing is dropped, so the rule is not simply
    // refusing every coordinate.
    expect(decodePairingInfo(concat(PAIRING_INFO_MAGIC, encodeDeterministic(full))).mailbox)
      .toBeDefined();
  });

  it('refuses a capability token that is not one', () => {
    for (const bad of ['short', 'a'.repeat(200), 'has spaces in it aaaaaaaaaaaaaaa', 'semi;colon;aaaaaaaaaaaa']) {
      const map = new Map<number, unknown>([
        [0, NONCE],
        [1, COORD.id],
        [2, new TextEncoder().encode(bad)],
        [3, new Uint8Array(ED25519_SIG_LEN)],
      ]);
      let threw = false;
      try {
        decodePairingInfo(concat(PAIRING_INFO_MAGIC, encodeDeterministic(map)));
      } catch {
        threw = true;
      }
      expect(threw, bad).toBe(true);
    }
    expect(CAP_TOKEN_RE.test(COORD.writeCap)).toBe(true);
  });

  it('refuses bytes that are not a pairing-info payload at all', () => {
    expect(() => decodePairingInfo(new Uint8Array(0))).toThrow(/not a pairing-info/);
    expect(() => decodePairingInfo(NONCE)).toThrow(/not a pairing-info/);
    expect(() => decodePairingInfo(concat(PAIRING_INFO_MAGIC, new Uint8Array([0xff])))).toThrow();
  });

  it('refuses trailing junk after the map, because the decoder is strict', () => {
    const good = encodePairingInfo(NONCE);
    expect(() => decodePairingInfo(concat(good, new Uint8Array([0x00])))).toThrow();
  });
});

describe('the signature is what stops a redirect', () => {
  it('a coordinate signed by a different key does not verify against the card', async () => {
    // The scenario: a second screen in the camera's view, showing a real-looking payload
    // whose mailbox belongs to whoever is holding it. They could not read anything, but they
    // could stop the messages arriving, which is why this is a refusal and not a shrug.
    const honest = (await generateKeyManager('noble')).manager;
    const attacker = (await generateKeyManager('noble')).manager;
    const sig = await signMailboxCoordinate(attacker, COORD);
    expect(mailboxSignatureValid(COORD, sig, honest.identityPublicKey())).toBe(false);
    // Positive control: the same coordinate signed by the honest key does verify.
    expect(
      mailboxSignatureValid(COORD, await signMailboxCoordinate(honest, COORD), honest.identityPublicKey()),
    ).toBe(true);
  });

  it('a coordinate whose id or cap was edited after signing does not verify', async () => {
    const km = (await generateKeyManager('noble')).manager;
    const sig = await signMailboxCoordinate(km, COORD);
    const movedId: MailboxCoordinate = { id: flip(COORD.id), writeCap: COORD.writeCap };
    const movedCap: MailboxCoordinate = { id: COORD.id, writeCap: `${COORD.writeCap.slice(0, -1)}Q` };
    expect(mailboxSignatureValid(movedId, sig, km.identityPublicKey())).toBe(false);
    expect(mailboxSignatureValid(movedCap, sig, km.identityPublicKey())).toBe(false);
  });

  it('the signature is domain-separated from a card signature', async () => {
    // Same key, different context label, so a card signature can never be presented as a
    // coordinate signature or the reverse.
    const km = (await generateKeyManager('noble')).manager;
    const card = importCard(await createSignedCard(km, 1));
    const cardSig = decodeStrict<Map<number, unknown>>(card.signedCardBytes).get(1) as Uint8Array;
    expect(mailboxSignatureValid(COORD, cardSig, km.identityPublicKey())).toBe(false);
  });
});

describe('relay id conversion', () => {
  it('16 bytes becomes 32 lowercase hex and back', () => {
    const hex = toRelayMailboxId(COORD.id);
    expect(hex).toMatch(/^[0-9a-f]{32}$/);
    expect([...fromRelayMailboxId(hex)]).toEqual([...COORD.id]);
  });

  it('refuses an id the relay got wrong, rather than passing it along', () => {
    expect(() => fromRelayMailboxId('NOTHEX'.padEnd(32, 'a'))).toThrow(/32 lowercase hex/);
    expect(() => fromRelayMailboxId('0'.repeat(31))).toThrow(/32 lowercase hex/);
    expect(() => fromRelayMailboxId('../../x'.padEnd(32, 'a'))).toThrow(/32 lowercase hex/);
    expect(() => toRelayMailboxId(new Uint8Array(15))).toThrow(/not 16 bytes/);
  });
});

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function flip(bytes: Uint8Array): Uint8Array {
  const out = Uint8Array.from(bytes);
  out[0] ^= 0x01;
  return out;
}
