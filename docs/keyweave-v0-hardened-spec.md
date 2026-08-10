# Keyweave v0 - hardened design spec (post adversarial review)

Provenance: a design-hardening pass run on 2026-08-08, in which five independent design lanes
were each attacked by a separate adversarial verification lane, with no lane reviewing its own
work. This document is the synthesis, written from the findings themselves rather than from the
reviewers' summaries of them, by the person who ran the pass rather than by any of the lanes.

**Headline: 3 critical + 12 high + 19 medium findings.** Architecture holds; 4/5 dimensions
verified `design_holds_for_v0 = true`. The exception is **crypto (holds = false)** - the first
draft is forgeable as written. All fixes are specified below and are cheap; none change the
product shape. Nothing here is a reason not to build - it is the reason to build from THIS spec
rather than the plan sketch.

---

## Must-fix-before-build register (the 15 critical/high)

### Crypto (1 critical, 4 high) - this is why crypto `holds = false`

1. **[CRITICAL] Validate imported public keys, or a signed card can be forged that nobody holds a
   key for.** noble's default Ed25519 verify uses `zip215:true`, which accepts small-order /
   non-canonical points; a card with `identity_pub` = the neutral element `0x01000..00` and
   `sig = pk || 0x00*32` VERIFIES. This defeats card authenticity, identity uniqueness, and the
   KCI negative control at once. **Fix:** on every card import require (a) canonical re-encode
   equality (`Point.fromBytes(pk).toBytes() === pk`), (b) `isSmallOrder() === false` (note
   `isTorsionFree()` alone passes the neutral element - insufficient), (c) `!= our own key`;
   verify ALL signatures with `{zip215:false}` (strict RFC 8032); require the same for
   `encryption_pub` (don't inherit x25519 low-order rejection from one library version).
   Repro: the agent's `attack3.mjs` prints `spec card verify() = true` then a fully-accepted
   forged message.

2. **[HIGH] Pairing has no proof-of-possession or liveness → "physical presence IS auth" secretly
   rests on the user.** A `SignedCard` is a static, replayable artifact; the safety number is a
   pure function of two *public* keys. A recorded/filmed/screenshotted card can be presented by an
   attacker; both screens show a matching number; nobody proved they hold a secret. **Fix (also
   fixes #4 and the both-keys binding):** SAS-style pairing - after cards exchange, fold the
   X25519 DH shared secret into the *displayed* safety number and exchange fresh signed nonces in
   the same optical session: `FP = SHA-512(ctx || min/max(id_pub) || min/max(x_pub) || DH)`, with
   each side signing `'keyweave-pair-v1' || sort(cardA,cardB) || sort(nonceA,nonceB)`. This proves
   possession of BOTH key types in one round trip. **← OWNER DECISION 1 (see below).**

3. **[HIGH] At-rest wrap protects only the two key seeds - contacts and message history are in the
   clear.** An IndexedDB dump hands an attacker the whole social graph + every plaintext message,
   which is exactly what the product exists to protect. Also: wrap AEAD uses empty AAD, so the KDF
   params are unauthenticated + downgradeable, and there is no lock-state spec. **Fix:** wrap a
   single encrypted VAULT (seeds + contact store + message store under HKDF subkeys of one
   `K_wrap`); put the full KDF descriptor `version||kdf||t||m||p||salt` in the AAD with a hard
   minimum-parameter floor at read time; specify an idle re-lock timeout + best-effort
   zeroization + a named residual that JS cannot guarantee zeroization and a live-session or
   non-FDE device is out of scope.

4. **[HIGH] Safety number binds only identity keys; no card pinning / supersession / expiry /
   revocation.** A card can advertise an `encryption_pub` whose secret the owner doesn't hold, or
   an old card can roll the encryption key backward - displayed words unchanged. Subsumed by the
   SAS-with-DH fix in #2, PLUS an explicit written rule: a pinned identity accepts exactly one
   card; a later card triggers a full re-pair ceremony; add a monotonic `card_serial`, reject
   `serial <= pinned`; state plainly **v0 has no revocation**.

5. **[HIGH] Replay dedupe (msg-id = hash of the wire envelope) is bypassable by the relay with no
   keys.** Permissive CBOR decode lets the relay re-encode the same authenticated blob into
   unlimited distinct wire forms (unknown map key survives even strict dcbor), each a new msg-id,
   same accepted plaintext; the bounded seen-set is also evictable. **Fix:** decode ALL untrusted
   CBOR with `{dcbor:true}` AND reject unknown keys / wrong types / out-of-range lengths at BOTH
   the envelope and the (attacker-controlled) inner layer; compute the dedupe id over the
   *authenticated* bytes `SHA-512('keyweave-msgid-v1' || inner_bytes || sig)`; add a per-sender
   monotone timestamp high-water mark (recipient-side state only, degrades safely).

### Web-delivery TCB (2 critical, 3 high) - load-bearing honesty for a public security product

6. **[CRITICAL] The PWA/service-worker story overclaims defense against a compromised origin.**
   `sw.js` is a per-user same-origin fetch - the server can serve poison to ONE victim by
   IP/cookie (no CT-equivalent for SW scripts, so "hits all users, more visible" is false);
   `skipWaiting()+clients.claim()` + any post-activation lazy module = same-load poisoning (our
   own LFL site uses a 45KB lazy-pool, so this is realistic); and a `Clear-Site-Data: "storage"`
   response unregisters the SW instantly. **Fix:** rewrite the rationale - the SW buys offline +
   at-most-one-visit delay under favorable conditions, NOT targeted-swap defeat; load all
   executable code up-front (no lazy modules); real update transparency needs an out-of-band
   monitor (which per-user discrimination also evades - say so).

7. **[CRITICAL] The reproducible-build "honesty keystone" has an in-band anchor and no closed
   loop - the same flaw it correctly skewers in SRI.** If the hash/recipe lives on the same
   origin/VPS as the bundle, `cp evil.js bundle.js && sed hash-page.html` defeats it; and a
   third-party checker gets whatever the server serves *them*, not the victim. **Fix:** publish
   the hash OUT-OF-BAND in a trust domain independent of the VPS - signed git tag + GitHub
   release on the public repo (GitHub is already in the story, not served by the VPS; the key
   the tag is signed with, and the command that checks the signature, are named in
   `REPRODUCIBLE-BUILD.md`); document a received-bytes verification procedure (DevTools →
   sha256 the exact bytes your browser got → compare the tag) and state that only the victim's
   own browser can run it; drop any in-app "verify hash" affordance (self-attestation:
   malicious code reports the honest hash).

8. **[HIGH] Co-location collapse.** App origin + relay + hash all behind one nginx under one root
   on one VPS ⇒ the plan's "compromise the relay → ciphertext only" and "three independent
   layers" claims are FALSE: one host root = malicious served JS = keys + plaintext, total break.
   **Fix:** split trust domains (serve the static bundle from a host/operator distinct from the
   relay) OR, minimally, correct the threat table to distinguish relay-APPLICATION compromise
   (ciphertext only) from relay-HOST compromise (total break), name it in NAMED-RESIDUALS.md, and
   add one honest sentence to the UI. **← OWNER DECISION 2 (see below).**

9. **[HIGH] Use non-extractable WebCrypto keys - the design missed this on a stale fact.** Secure
   Curves (Ed25519 + X25519) shipped in all major browsers by mid-2025 (Safari 17, Firefox 130,
   Chrome 133/137). Generating long-term keys as `extractable:false` CryptoKeys means a
   later-served malicious bundle can only *oracle* while resident, not exfiltrate raw key bytes -
   which, since v0 has NO forward secrecy, closes the "steal once, decrypt everything forever
   offline" branch. **Fix:** generate Ed25519/X25519 as non-extractable CryptoKeys where
   supported; use @noble only for XChaCha20-Poly1305 sealing and as a labeled degraded fallback.
   Honest caveat: a malicious bundle at *generation* time still wins (TOFU), and a resident
   bundle can still oracle-decrypt.

   **Outcome, corrected 2026-08-10.** As built, this fix was applied to the key HANDLES and not
   to the key MATERIAL. Seeds are generated by `randomBytes` and imported with
   `extractable: false`; `crypto.subtle.generateKey` is never called. The stated payoff, closing
   the "steal once, decrypt everything forever offline" branch, therefore does not hold: the seed
   is the durable secret and it is in reachable memory whenever the vault is unlocked. Residual
   R20 records this and the tradeoff that produced it.

10. **[HIGH] Delete the false metadata copy.** The draft UI says the relay "cannot tell that two
    mailboxes belong to people who know each other" - but its own access log links them by
    IP/timing (one client PUTs B, GETs A). **Fix:** delete from "what Keyweave protects"; move
    linkage honestly into the metadata residual bullet.

### Relay (3 high)

11. **[HIGH] The global 1 GiB byte-cap has no specified enforcement** and at Keyweave scale it's
    the binding constraint. **Fix:** a single durable, locked total-bytes ledger updated in the
    same critical section as add/delete + a startup reconciliation sweep - OR drop the global cap
    for v0 and rely on `max_mailboxes × per-mailbox` caps as the wall (and stop calling it an
    independent layer).

12. **[HIGH] Don't carry EdgeDancer's whole-store single-lock purge into an N-mailbox layout.**
    The parent's flat 500-item dir under one `_FileLock` becomes a multi-second global-lock stall
    over up to 2M nested blob files, on-demand lengthenable by an attacker. **Fix:** per-mailbox
    lock + purge only the touched mailbox, or a background purge thread with a bounded per-tick
    file budget.

13. **[HIGH] GC the limiter state files.** `rate-*.json` / `authfail-*.json` are never unlinked;
    Keyweave re-keys write-limits per mailbox (10k files) and exposes the auth-fail budget to the
    public internet keyed on IP - an IPv6 /64 mints millions of files → inode exhaustion breaks
    the very budget meant to contain the flood. **Fix:** unlink a state file when its window
    empties + periodic mtime sweep; bucket the IPv6 auth-fail key to /64.

---

## Corrected decisions that hold (fold straight into the build)

- **Keys:** two independent keypairs - Ed25519 identity (RFC 8032) + X25519 encryption (RFC 7748),
  from separate 32-byte seeds. Reject XEdDSA / single-seed-derived (couples signature+DH failure
  modes, blocks encryption-key rotation). Sizes verified live: 32/32/64.
- **Message seal = SIGN-THEN-ENCRYPT** (the plan's implied encrypt-then-sign leaked the social
  graph). Inner = `dCBOR{sender_id, recipient_id, timestamp_ms, body}`, Ed25519-signed, then
  AEAD-encrypted; wire envelope carries only `{version, nonce, ciphertext}` - verified to contain
  zero identity-key material. `K = HKDF-SHA512(X25519(...), info='keyweave-msg-v1'||both_ids||both_x_pubs)`,
  seal = XChaCha20-Poly1305, AAD = version byte only. All four negative controls pass
  (tamper→bad tag, wrong-recipient→no-decrypt, forward→bad-sig, KCI→bad-sig).
- **Nonce:** fresh 24-byte random per message (XChaCha's 192-bit nonce makes random safe under
  the static per-pair key: P(collision) ≈ 2^-33 even at 2^80 msgs/pair). Reject counters
  (rollback under a static key = catastrophic keystream reuse). BUT add a version allowlist
  before KDF (the AAD uint truncates mod 256 as written) and tune Argon2id for OFFLINE
  device-theft cracking, not the OWASP server-login minimum.
- **Contact card:** deterministic CBOR (RFC 8949 §4.2) integer-keyed map, version byte,
  `SignedCard = {card_bytes(bstr), sig(64)}`, sig over `'keyweave-card-v1' || card_bytes`, verified
  over the transported bytes, never re-encoded.
- **Optical:** vendor decimen (raw-bytes mode, wrap-before-encode) at pinned commit `f0c49e9`;
  card is tiny (~138 B + prekeys) so pairing is near-instant. **Cap the fountain header k /
  blockLen / totalLen** (all attacker-controlled) and confirm the forked `protocol.ts` EXCLUDES
  the gzip surface (decompression-bomb path is one copy-paste away). **Drop the responder-echo**
  from v0 - it provides zero protection against the two-sided interposer and is dead complexity
  (Second-System discipline); the SAS over fresh-nonce cards is the SOLE cryptographic backstop.
  **Carry the served-JS residual into the ceremony threat-model and copy** - the safety-word
  compare assumes the code computing it is honest; a compromised bundle defeats pairing silently.
- **Relay:** dumb mailbox, opaque ciphertext blobs, never decoded/decrypted (avoids the
  decompression-bomb class by construction) + hard max blob size; pull model; token split
  (write-cap can't read, pull-token can't write, `hmac.compare_digest`); persist-before-delete;
  `\z` anchors not `$`; rate-limit-before-auth; distrust XFF. Deploy: systemd DynamicUser +
  IPAddressDeny, loopback behind nginx, fail2ban, owner-run install. NOTE the parent's assurance
  does NOT transfer to the new/rewritten auth + nested-store paths - they get their own tests.
  Also: `nginx error_log` records the full request line incl. mailbox id (turning off access_log
  is insufficient); a mailbox-existence timing oracle needs constant-time handling; and
  `trust_forwarded_for=0` behind nginx makes `_client()` return 127.0.0.1 for everyone → a single
  abuser self-bans the whole relay via fail2ban. All addressed in the relay work package.

---

## Prior art / FTO / licensing / naming (dimension holds; framing corrected)

- **Patents assessed NOT reading on Keyweave**, with claims extracted from the grant PDFs:
  US 11455616 / US 11720879 (Mycashless "Secure Animated Response code") require displaying and
  *decrypting* an ENCRYPTED QR and generating a second encrypted code *in response* - Keyweave's
  optical payload is a plaintext-readable signed public-key card, generated independently of the
  peer, with no event/transaction data; fails ≥3 limitations per independent claim. US 11784908
  (IBM QR routing) needs a device cluster + multi-level routing - Keyweave is two devices, one
  optical hop. **Design invariant (suite-enforced; no CI runner in the repo yet): never place a cipher between card serialization and
  the decimen encoder** - a raw camera decode of pairing frames must yield the parseable public
  card. HONESTY CORRECTION: only 3 named patents were read, no family/class search was run, so
  present this as a **posture, not a clearance**; and "non-commercial lowers risk" is legally
  wrong (35 U.S.C. §271(a) has no commercial-use element; Madey v. Duke narrows experimental use).
  **Owner-run USPTO search + counsel before ANY commercial offering.**
- **Licensing:** mostly MIT (decimen, @noble/*, our repo) BUT decimen's decode path bundles
  `zxing-wasm` embedding `zxing-cpp` (**Apache-2.0**) - ships in our bidirectional-scan bundle, so
  add Apache-2.0 attribution/NOTICE. Vendor decimen with full-history review (the shallow depth-1
  clone can't review its 9 days of history) + audit its transitive deps. "Audited libraries"
  claims must be version-precise: noble's last EXTERNAL audit is Cure53 Sep 2024 @ v1.6.0; the
  working pin is 2.3.0 (self-audited lineage) - word the claim precisely or pin to the audited
  line.
- **Naming:** keep "Keyweave" as codename; public wordmark **"Keyweave by LocalFirstLab"** at
  `keyweave.localfirstlab.org` (subdomain of the existing property, no new domain); USPTO search +
  counsel before any commercial use.

---

## Two owner decisions this review surfaced

**DECISION 1 - pairing hardening (recommended: SAS-with-DH).** Adopt the SAS-with-DH-PoP fix
(fold the X25519 shared secret into the displayed safety number + fresh signed nonces): one round
trip that proves possession of both keys and closes the replayable-static-card MITM. Alternative
is identity-only SAS + strict one-card-per-identity pinning + `card_serial`. The first is strictly
stronger for the same effort; I'll bake it in unless told otherwise.

**DECISION 2 - trust-domain split.** For a public security product, serving the app bundle from a
host/operator distinct from the relay removes the single-point-of-failure that finding #8 exposes
(one VPS root = total break). It adds that second host to the TCB and a bit of setup. The honest
alternative is co-locate on the one VPS and name the residual loudly. Recommend the split for the
public launch; co-location is acceptable only for a private/internal preview.

---

## Status

Feasibility: CONFIRMED - the architecture is sound and the hard problems have concrete, verified
solutions. The crypto layer is buildable from THIS spec (not the plan sketch). Next step is to
build the crypto + relay core (offline, testable, no attended slot) with these fixes baked in,
and to run an adversarial verification pass at each checkpoint. Public deploy remains gated per
the build-host condition (clean-room artifact + out-of-band hashes, or close that condition).

---

## Build outcome (2026-08-08) - this section supersedes the sketch above where they differ

The v0 crypto core (`client/`) and mailbox relay (`relay/`) were BUILT and verified. Owner
decisions from this session are baked in: **SAS-with-DH** pairing, **split app-from-relay** trust
domains, and separate author and verifier lanes for the build. Final state: **client 81/81 tests,
relay 75/75, both green with typecheck clean**, confirmed by re-running both suites directly
rather than by trusting the build reports.

Three adversarial rounds ran on the code (build → verify → fix → re-verify → fix again). Round 1
found a **critical** relay defect (mailbox GC keyed on creation time destroyed every mailbox the
first time it was empty) and a **high** crypto data-loss (the monotone replay gate dropped
out-of-order relay batches); both fixed. Round 2 caught the regressions those fixes introduced
(the second-system signature); fixed. A final surgical pass closed two relay medium regressions in
the default proxy config. Residual LOWs are named honestly in `NAMED-RESIDUALS.md` (R8–R12), not
chased.

**Design change from the sketch, worth flagging:** must-fix #5's "per-sender monotone timestamp
high-water mark" was WRONG - it silently dropped legitimate out-of-order messages, which is
unacceptable for a messenger. The shipped design is **an authenticated message-id dedupe + a
bounded acceptance window + a per-sender seen-set persisted in the vault**. Its bounded edges
(seen-set cap eviction; empty seen-set on vault upgrade; a >24h clock-behind self-outage) are in
`NAMED-RESIDUALS.md` R11–R12.

**Not yet built (later work packages):** the optical layer (vendoring decimen after a full-history
review + the never-encrypt-the-optical-payload invariant), the browser UI, and the deploy
(owner-run, gated on the build-host condition). The durable-state wiring that connects the client
`Vault` to the `ReplayGuard` on unlock/save is future integration work; the API for it exists.
