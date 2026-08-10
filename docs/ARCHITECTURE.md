# Architecture

Keyweave splits the hard problem of end-to-end encryption in two:

- **Pairing (in person, once, optical):** the trust anchor. Two devices exchange
  signed contact cards as animated QR codes. Physical proximity means there is no
  network path for a machine-in-the-middle. Verification is **SAS-with-DH**: the
  displayed safety number folds in the X25519 Diffie-Hellman shared secret and fresh
  signed nonces, so confirming the number proves each side holds the secret for both
  its keys - not merely that two public keys exist.

- **Messaging (clearnet, anytime):** sealed ciphertext through a dumb store-and-forward
  mailbox relay. The relay stores opaque blobs against opaque mailbox ids; it holds no
  private key and no plaintext, and never decodes a blob.

```
  PAIRING (in person)                    MESSAGING (clearnet)
  A screen ->(animated QR)-> B camera     A --seal--> [ relay mailbox ] --pull--> B
  B screen ->(animated QR)-> A camera         ciphertext + opaque tag only
  both confirm SAS-with-DH safety number      relay never sees a key or plaintext
```

The full, adversarially-hardened decisions (key types, contact-card CBOR layout,
sign-then-encrypt seal, replay defense, at-rest vault, relay hardening) are in
`keyweave-v0-hardened-spec.md`. That spec is the build contract; this file is the map.

## Components

- `client/` - TypeScript browser client. Key management (Ed25519 + X25519 imported
  into non-extractable WebCrypto CryptoKeys where available, @noble fallback; the
  seeds themselves are the stored secret, see R20 in `NAMED-RESIDUALS.md`),
  deterministic-CBOR contact cards with strict validation, SAS-with-DH pairing,
  sign-then-encrypt message seal, strict CBOR decode + replay high-water-mark, and
  an encrypted local vault. The relay client (`src/relay-client.ts`) and the
  messaging layer (`src/messaging.ts`) sit on top, both written against a relay
  that lies.
- Mailbox coordinates are exchanged OPTICALLY, inside the ceremony, one mailbox per
  pairing per direction, signed by the identity key that ceremony pins. The card
  stays what it was: one artifact per identity, with no per-pairing state in it.
  `src/mailbox.ts` is the whole of it, and it says why.
- `relay/` - Python standard-library mailbox relay. Opaque-blob store, split
  write/pull tokens, per-mailbox locking with bounded purge, GC'd rate/failure
  limiters, forked from the adversarially-hardened EdgeDancer ingest relay.
- `vendor/decimen/` - (later) the pinned optical transport, wrapped: our signed CBOR
  card is encoded to fountain frames; the payload is never encrypted (a patent-posture
  invariant).
