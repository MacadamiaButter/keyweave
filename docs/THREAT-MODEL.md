# Threat model

Security rests on the keys and the physical pairing channel, not on any secret in the
protocol (Kerckhoffs): the whole protocol is public.

| Attacker | Outcome | Why |
| --- | --- | --- |
| Machine-in-the-middle at pairing | Defeated | Optical + in person; no network to interpose. SAS-with-DH proves possession of both keys, so a replayed/substituted card fails the safety-number compare. |
| Compromise the relay **application** | Ciphertext only | The relay holds no private key and no plaintext; blobs are signed so it cannot forge; mailbox ids are random so it cannot build an address book. |
| Compromise the relay **host (root)** | Metadata + availability, **not** message content | The client bundle is served from a distinct trust domain (residual R2), so relay-host root does not become served-code compromise. |
| Malicious served client code | **Top residual, not solved by optics** | Web trust base (residual R1). Mitigated by strict CSP, non-extractable key handles (R20 states what that does and does not cover), out-of-band published build hashes, and later an extension. |
| Steal an unlocked / live-session device | Out of scope (v0) | Residual R5. The at-rest vault helps only against a powered-off, locked, full-disk-encrypted device. |
| Traffic-metadata analysis | Residual | Residual R3. The relay sees who-pulls-what-when and can link talking mailboxes by timing/IP. |
| Later key compromise vs past messages | Known v0 limitation | No forward secrecy in v0 (residual R4); a ratchet is v1. |

Defense in depth: optical authentication, sealed AEAD messaging, and a hardened relay
are independent layers. The holes (R1 served code, R3 metadata) are named, not patched
over. See `NAMED-RESIDUALS.md` for each residual in full.

Notes:
- Physical co-presence is not enforced by the protocol; the client copy must tell users
  the safety-number compare only means something when done face to face.
- Key imports are strictly validated: canonical encoding, small-order rejection, strict
  RFC 8032 signature verification. An unvalidated import is a universal forgery.
