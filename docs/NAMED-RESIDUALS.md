# Named residuals

Honest, standing limitations of Keyweave. These are not bugs to be fixed silently;
they are boundaries of what the design can and cannot promise. Every one of them
was surfaced by adversarial review (see `keyweave-v0-hardened-spec.md`).

## R1 - Served-code integrity (the top residual)

Keyweave is web software. A browser re-fetches its JavaScript from a server on every
load, so a compromised or malicious origin can serve key-exfiltrating code, and the
optical pairing does nothing to prevent it. The safety-word compare during pairing
**assumes the code computing it is honest**; a compromised bundle can display
identical fabricated safety words on both screens and defeat pairing with no visible
symptom.

Mitigations (defense in depth, none a full solution): a strict Content-Security-Policy
with no external origins and no inline script; long-term keys are held as
non-extractable WebCrypto CryptoKeys where the runtime provides Secure Curves, which
denies a later-served bundle the live key handle but **not** the seed that handle was
imported from, so this narrows the attack rather than closing it (see R20); build
artifacts published with hashes **out of band** (on a trust domain independent of
the serving host, and from v0.1.1 inside a signed tag message rather than only in an
editable release body; `docs/REPRODUCIBLE-BUILD.md` names the key, where to fetch it,
and the command that checks it) so a diligent user can compare the exact bytes their
browser received; and,
later, a browser extension that installs reviewed code rather than re-fetching it per
load. Real update transparency requires an out-of-band monitor, which a server that
discriminates per user can still evade.

The chosen app host also carries the `localfirstlab.org` static site and a second web
application behind a reverse-proxy vhost on the same machine. R1's trust base is therefore
that machine as a whole rather than the app's own vhost; `docs/DEPLOY-APP.md` records this
as an accepted decision in the section listing what it was built on.

## R2 - Host co-location

The app bundle and the relay must not share a single host/root, or one compromise is
a total break (malicious served code + the relay together). Keyweave serves the client
from a trust domain distinct from the relay. The relay host is still trusted for
availability and metadata; only message and identity confidentiality are held away
from it.

**Client note (v0, what actually ships).** The split topology is now a supported build,
selected by one environment variable read at build time:

    KEYWEAVE_RELAY_ORIGIN=https://relay.example    # split trust domains
    KEYWEAVE_RELAY_ORIGIN unset                    # same origin (the default)

`client/build-config.mjs` derives all three consumers from that single value: the
`connect-src` in the page's `<meta>` CSP, the nginx response-header block published in
`docs/DEPLOY-CSP.md`, and the compile-time constant `client/src/ui/main.ts` uses for the
`RelayClient` base URL (falling back to `location.origin` when it is empty). They cannot
drift apart by a human editing one of them, because there is only one of them.

`client/test/build-no-external-origin.test.ts` builds BOTH configurations and asserts that
the only `http(s)` origin anywhere in `dist/` is the configured relay, compared by exact
string equality rather than by prefix. The prefix version of that rule would accept
`https://relay.example.evil.net`, so the distinction is the check. An origin that cannot be
safely interpolated into a policy string, `https://x.example; script-src 'unsafe-inline'`
being the case that matters, ABORTS the build.

Four things remain open, and none of them is a code change:

- **The default is still same-origin.** A build that forgets the variable produces exactly
  the arrangement this residual names as the one to avoid. `docs/DEPLOY.md` step 5 carries a
  `grep` on the built page as the gate; it is a gate a person has to run.
- **The relay host is still trusted for availability and metadata.** Splitting the origins
  removes the "one compromise is a total break" property. It removes nothing from R3.
- **The artifact hash now depends on this value** (`docs/REPRODUCIBLE-BUILD.md`). A release
  that publishes hashes without stating the origin it built with cannot be verified out of
  band, which is a new way for the R1 mitigation to be quietly useless.
- **On an app host that cannot send response headers, part of the policy does not exist.**
  `frame-ancestors` and `form-action` are ignored in a `<meta>` tag by specification, so on
  such a host there is no clickjacking protection: any site may frame the app, including its
  pairing ceremony. Everything else in the policy, `connect-src` and the relay-origin
  tightening included, still applies from the meta tag, so this is a partial loss and not a
  total one. GitHub Pages is the concrete case: it has no header configuration at all, and
  `docs/DEPLOY.md` recommended it while also handing the operator an nginx block and a
  `curl -sI` assertion, which is not a runbook anybody can follow. That contradiction is now
  an explicit OWNER DECISION in `DEPLOY.md`: move the app to a host that can send headers, or
  accept this residual by name. **The owner picked the first on 2026-08-09**, which `DEPLOY.md`
  records above its own steps: step 5b is REQUIRED for that deployment rather than optional,
  and this paragraph does not describe it. It stays because it is what any other host still
  costs.

## R3 - Traffic metadata

The relay unavoidably observes which mailbox is written and pulled, when, and blob
sizes, and can link mailboxes that talk to each other by timing and network address.
Mailbox numbers carry no names, but this is metadata Keyweave does not claim to hide in
v0.

Two consequences carried into the client rather than left in this file. The sentence
naming this is on the paired screen and on the conversation screen, in the product, and
`client/test/ui-shell.test.ts` refuses the phrasings that would contradict it. And there
is no background sync, no service worker and no push subscription: a conversation polls
only while its screen is open, including open in a background tab, because a background
fetch of a mailbox is traffic the relay sees and the person does not.

Open means open and not visible, which is worth saying because the short version invites the
other reading: nothing in `client/src` reads `document.hidden` or listens for
`visibilitychange`, and the poll loop in `src/ui/app.ts` asks only whether the vault is
locked, so a tab left behind another window goes on talking to the relay. A browser that
throttles background timers stretches the interval to about a minute, which is still well
inside the five minute idle window, so by R17's mechanism the vault in that tab does not lock
either; a tab frozen outright stops polling and freezes the lock timer with it, which arrives
at the same place by the other road. R17, R18 and this are one arrangement rather than three,
so anyone who changes the poll or the idle lock has to read all three before deciding.

**The relay also controls TIMING, which is a residual of its own.** It can hold a blob for
as long as the acceptance window and hand it over whenever it likes, and it can pace its
answers. Two places that reaches, both bounded rather than removed:

- WHERE A MESSAGE LANDS IN THE THREAD. The order is the sender's authenticated timestamp,
  because arrival order is the relay's to choose and sorting on it would hand the relay the
  thread. A withheld message therefore still appears where its sender wrote it, which can
  be days above the last thing the reader saw. What closes the silent half is
  `MessageRecord.receivedAtMs`, this device's own clock at admission: a message whose two
  clocks disagree by more than the grouping window is rendered as its own run and says when
  it reached this device as well as when it claims to have been sent. What is NOT built is
  a "new since your last visit" divider, so a reader scrolling an old part of a long thread
  can still pass one without noticing.
- HOW LONG A REFRESH TAKES. A refresh is a flush and then a receive, and the composer is
  disabled for the whole of it, so an unbounded pass would let the relay choose when a
  person may write. BOTH HALVES ARE BUDGETED, each under a single elapsed-time budget spent
  across every request it makes and measured on the monotonic clock so a time sync cannot
  move it: `FLUSH_BUDGET_MS` for the pushes and `RECEIVE_BUDGET_MS` for the list and every
  pull. The residual is what a stalling relay can still cost, which is the sum of those two
  plus at most half of `MIN_PULL_DEADLINE_MS` on the one path that may overrun (a first pull
  spending a reservation the list overran into), per refresh, and it can leave messages
  uncollected and unsent for as long as it keeps stalling. Neither half goes quiet about it:
  the reports carry how many were not collected and how many are still queued here, rather
  than an empty mailbox and a clean send.
- WHETHER A MESSAGE SURVIVED A FAILED PULL. Delete-on-pull means the relay removes a blob
  before the bytes reach the wire, so a pull that ends without an answer may or may not have
  destroyed the message, and this client cannot tell which. It is not silent about it: the
  pass counts it (`ReceiveReport.interrupted`) and the screen says the message may be gone
  and to ask the sender to send it again, rather than the reassurance it prints when nothing
  was pulled at all. The count is the undecidable cases only: no answer at all, or a 5xx,
  which the relay's own catch-all can emit after the delete. A 401 or a 429 is decided
  before the relay reaches its delete, so those are reported as themselves and the blob is
  collected on the next refresh. A relay that deletes and then lies about it is not covered
  by any of this, and gains nothing from it: a 404 destroys the same message with no warning
  at all. R9 is the underlying at-most-once property; this is what the person is told about
  it. THE SEND HALF IS NOT SYMMETRIC and that is why it needs no floor: a push that is
  abandoned leaves the record queued with its bytes, so the cost is a repeat offer the
  peer's replay guard eats, never a destroyed message.

## R4 - No forward secrecy (v0)

v0 seals with static per-pair keys. A later compromise of an identity/encryption key
can decrypt past messages. A ratchet is planned for v1. Because there is no ratchet, a
seed that leaks once decrypts everything that pair ever sent. R20 explains why
non-extractable key handles do not prevent that leak, which makes the absence of
forward secrecy sharper in v0 rather than softer.

Said in the product, on the screen that holds the messages, rather than only here.

## R5 - Device compromise

A stolen unlocked device, a device with a live unlocked session, or a device without
full-disk encryption (swap/hibernation images) is out of scope. The local vault is
encrypted at rest, but JavaScript cannot guarantee key zeroization.

## R6 - No revocation (v0)

v0 has no key revocation. A pinned identity accepts exactly one card; a later card
forces a full re-pair ceremony. There is no way to announce "this key is now dead".

## R7 - Patent posture, not clearance

Three named patents were read and assessed not to read on Keyweave (the optical payload
is never encrypted, which is a required limitation of the encrypted-QR patents). No
patent family/class search was run. This is a posture, not a legal clearance; counsel
and a USPTO search are required before any commercial offering.

## R8 - A mailbox's budgets are shared by every holder of its write_cap

A mailbox has two capabilities (write_cap, pull_token). Its per-mailbox walls (blob
count, byte budget) are properties of the mailbox, so they are shared by everyone who
holds that write_cap. The client contract is therefore **one mailbox per pairing**: the
budgets belong to the two paired peers, and no third party holds the cap **unless the
ceremony was observed** (see below). If a deployment instead uses one mailbox per user
(many senders to one recipient mailbox), one noisy sender can starve the others; that
model would need a per-write-cap sub-quota.

**What a filmed ceremony costs, and it is not confidentiality.** The write_cap is handed to
the peer on the optical channel, in the clear, because nothing may sit between card
serialization and the optical encoder. A bystander's phone, a shop camera or a housemate
across the room therefore ends up holding a working write capability for one of the two
boxes.

That observer cannot read anything. The pull token never leaves the device that reserved the
box, so a read attempt is refused, and every blob is sealed to a key the observer does not
have. What the observer can do is write. Measured against the shipped relay on its default
configuration, a filmed write_cap fills its mailbox to the blob ceiling in under a second,
after which the real sender's messages are refused with `mailbox full` and the recipient's
screen reports nothing waiting. Neither person is told that a third party did this, and the
sender's current copy attributes the refusal to relay capacity.

v0 has no cap rotation (R6), so the pairing cannot be repaired remotely: the two people have
to meet and pair again. The mitigation this calls for is the per-write-cap sub-quota that the
paragraph above says is only needed for the many-senders model. That reasoning was wrong,
because it assumed the capability stays with the two peers. It is planned relay work that has
not shipped in any release: no published `relay/keyweave_relay.py` carries a per-write-cap
sub-quota, which is a `grep` a stranger can run, and the sender-side copy is corrected in the
same change that adds one.

Stated plainly, because the short version misleads in both directions: filming the ceremony
does not let anyone read a message, and it does let anyone stop one.

**As implemented (WP3b): one mailbox per pairing DIRECTION, which is two.** Each device
reserves the box it will READ, keeps that box's pull_token, and hands the peer the id plus
the write_cap optically during the ceremony. Every mailbox then has exactly one *intended*
writer and exactly one reader, no other pairing shares the budget, and each side holds
exactly one capability per box.

The reason it is two and not one is delete-on-pull (R9). A single shared box is READ by
both peers, and a pull deletes; a blob is opaque, so it cannot be told from another blob
without pulling it. A device polling a shared box would therefore pull and destroy its own
outbound message before the peer ever saw it, silently. Splitting by direction removes the
case rather than working around it.

A fresh pair of boxes per pairing is what stops one peer spending another's budget. The relay
reclaims an empty mailbox that has been idle past `mailbox_idle_days`, thirty days by
default, and that is not only about abandoned ceremonies: delete-on-pull leaves a HEALTHY
inbox empty in steady state, so what keeps a box alive is activity and not contents. `add`,
`list` and `pull` each touch the mailbox and a conversation nobody opens does none of them,
so a quiet but perfectly healthy pairing loses both of its boxes after thirty days in which
neither side opened it. The product already says this rather than leaving it to this file:
the relay-refusal copy tells the person the box may have been reclaimed after a long silence
and that it needs a fresh pairing in person.

Reserving a box needs the relay, and pairing does not: a device that cannot reach the relay
pairs anyway, with no coordinate in its optical payload, and that pairing gets NO messaging
until a fresh ceremony connects one. Both halves or nothing, and the paired screen says so.

## R9 - Delete-on-pull is at-most-once

A pull reads the bytes, deletes the blob, then returns them. If the network send fails
after the delete, the blob is gone: delivery is at-most-once, never at-least-once. The
client contract is sender retry-until-acked (the recipient acknowledges out of band; the
sender re-sends unacknowledged messages). The relay keeps no post-delete copy by design.

**As implemented (WP3b), and the honest limit of it.** An outbound message is sealed,
recorded as `queued` WITH its wire bytes, and PERSISTED before the relay is called; it is
re-offered on every flush until the relay accepts it, and only then is it marked `relayed`
and its wire bytes dropped. That order means a crash between the write and the PUT costs a
duplicate delivery, which the recipient's replay guard eats, rather than a message the
relay took and this device forgot.

What v0 does NOT have is the acknowledgement half. There is no receipt and no ack channel,
and the sender holds only the write_cap for the peer's box, so it cannot list it either.
"Retry until acked" is therefore implemented as "retry until the RELAY accepts", and the
interface says exactly that: `Handed to the relay`, never `Delivered`, with a sentence next
to it explaining the difference. `client/test/ui-shell.test.ts` fails on the word
"delivered" anywhere in the UI copy.

## R10 - The global byte cap is an availability boundary, not a security one

The global `max_total_bytes` ceiling bounds total disk but does not stop the store from
filling and returning 507 to every tenant for a TTL. The per-source (per-real-client, in
the coherent deploy) byte rate caps the fill rate per source; it is deliberately not
sized so one source cannot fill the global cap over a full TTL, and it does not evict.
**Named residual:** a distributed flood across many sources, or one patient source over a
full TTL, can fill the cap and 507 every tenant. Mitigations shipped: the 14-day TTL +
delete-on-pull continuously reclaim space. Full oldest-first eviction is deferred past v0.
Treat "the relay is full" as an availability event, never a confidentiality/integrity one.

**There is a second ceiling of the same class and it lands on different people.**
`max_mailboxes`, 10000 by default, is enforced inside `create_mailbox` under the index lock,
so a relay full of mailboxes rather than of bytes refuses every NEW pairing with a 507 while
every conversation that already holds its boxes keeps sending and pulling normally. The two
people it stops are the ones standing in front of each other trying to reserve a box, and
nothing on their screen distinguishes a full relay from a broken one. Reclamation is the same
shape as it is for the bytes and is bounded the same way: an empty mailbox idle past
`mailbox_idle_days` is collected (R8), and a mailbox in use is never evicted to make room.

## R11 - Replay defense is a bounded window + seen-set, with two documented edges

Replay is deduplicated by an authenticated message id (hash over the signed inner bytes,
not the malleable wire) plus a bounded acceptance window and a per-sender seen-set
persisted in the vault. This replaced an earlier per-sender monotone timestamp gate,
which silently dropped legitimate messages whenever the untrusted relay returned a batch
out of timestamp order. Two bounded edges remain, both accepted for v0:
- **Seen-set caps.** Under a flood of more distinct in-window messages than the hard cap
  (per-sender and global), the oldest in-window seen-entries are evicted, so a replay of
  one specific evicted id could be accepted once within the window. This is a
  bounded-memory tradeoff; the messages are still authentic (dedupe loss, not forgery).
- **Vault upgrade.** A vault written before the seen-set existed migrates with an empty
  seen-set, so the first session after upgrading such a vault may accept a one-time
  duplicate redelivery of in-window messages. Bounded and one-time.

## R12 - Clock skew can cause a temporary self-inflicted outage

Messages carry a sender timestamp; a recipient rejects any message dated more than 24h
ahead of its own clock (to stop a future-dated message from poisoning replay state). A
recipient whose local clock is more than 24h **behind** therefore rejects every current
message until the clock is corrected. Nothing is persisted on rejection, so a retry after
a clock fix succeeds; it is a recoverable availability failure, not data loss.

## R13 - CLOSED. The compiled-in CDN origin is stripped, and the build asserts it

**Status: closed 2026-08-08 by the browser work package.** The residual is kept here rather
than deleted because the two failure modes it names are silent, and the next person to
upgrade `zxing-wasm` needs to know why the machinery exists.

The decode path uses `zxing-wasm`, whose default `locateFile` resolves the WebAssembly
binary from a `jsdelivr` CDN. Keyweave overrides it at worker module scope before the first
decode, so nothing reached that origin even before this, but the string was compiled into
the bundle: a library upgrade or a reordered init would have turned a pairing ceremony into
a third-party fetch. Both obligations are now discharged and enforced:

- **The CSP includes `'wasm-unsafe-eval'`.** Without it `WebAssembly.instantiate` is
  blocked and the decoder never starts, with no error a UI would surface. The full policy,
  its per-directive justification, and the equivalent nginx response header are in
  `docs/DEPLOY-CSP.md`. It ships as a `<meta http-equiv>` in `client/index.html`, filled in
  at build time from `client/build-config.mjs`, and
  `client/test/build-no-external-origin.test.ts` asserts the built page carries that exact
  string, so the meta tag and the documented header cannot drift.
- **No `http(s)://` origin survives in any build except the configured relay.**
  `client/vite.config.ts` rewrites the CDN prefix to a same-origin path that cannot resolve,
  and the same test shells `npm run build` and scans every emitted byte, binaries included.
  For the default build the result is zero occurrences, not a list of accepted ones. For a
  split-relay build it is exactly one origin, matched by string equality: see R2.

Two things learned while closing it, both worth keeping:

- A production **worker bundle is a separate rollup build that does not inherit `plugins`**.
  The first attempt logged a successful strip while shipping the jsdelivr URL in
  `dist/assets/receive-worker-*.js`, because the decoder lives only in the worker. This is
  why the dist scan, not the plugin, is the gate. A tripwire in the same test asserts the
  strip left exactly one marker in `dist/`, so "zero origins" for the wrong reason still
  fails.
- `qrcode`'s package entry drags in its SVG renderer, which embeds the w3.org namespace
  URL. It would never be fetched, but the import moved to `qrcode/lib/core/qrcode.js` so the
  rule stays "no origins" with no exceptions to remember.

The CSP is a mitigation for R1, not an answer to it: a compromised origin serves its own
CSP alongside its own JavaScript.

**Not yet verified:** a browser smoke test of the ceremony under this exact policy. The
tightenings past the starting draft (no `blob:` in `script-src`/`worker-src`, no `data:`
anywhere) each rest on a checked property of the emitted bundle rather than on a run in a
browser.

## R14 - CLOSED. The real pairing entry point is pinned by execution, not by a regex

**Status: closed 2026-08-08 by the browser work package.**

`client/test/optical-patent-invariant.test.ts` protects the design invariant that no cipher
sits between card serialization and the optical encoder. Its call-site arm is a regex over
`src/`, so it constrains the shape of the binding handed to the encoder and never the value
that arrives: a caller could mutate the blessed buffer in place, or pass the encoder around
as a value, and stay green. Until this work package there was no real caller in `src/` at
all, so that arm's coverage of a future one was the residual.

**How it was closed.** `client/src/pairing-session.ts` `startCardBroadcast()` is the entry
point the application actually calls, and it returns the card bytes ALONGSIDE the frame
stream. The new "real-caller arm" executes that exact function, sizes the stream to k=1
where the single source block is the whole card, and asserts that `frame(0)`'s body is
byte-identical to the returned card and that `importCard()` parses it with no key material
in the test. A second case runs the production frame sizing through a keyless
`OpticalReceiver`. Executing the caller ends the whole class of textual evasions, because
any transform between serialization and the encoder changes the wire and the wire is what
is asserted.

**Negative control, run 2026-08-08.** Two byte transforms were inserted into
`startCardBroadcast` between `createSignedCard` and `encodeCardFrames`, one at a time:

- XOR applied in place to the returned buffer (the mutation the call-site arm cannot see):
  the arm failed on `importCard` with `Invalid simple value: simple(90)`.
- XOR applied to a copy handed only to the encoder: the arm failed on the byte comparison
  (`frame 0 body is not the card the entry point returned`) and on the keyless-receiver
  reassembly, and the call-site arm failed too.

Both were reverted and the suite is green. The call-site arm was also made recursive over
`src/`, since the UI put real code in `src/ui/`, and it now asserts that the real caller is
inside the set it walks, so "no violations" cannot quietly mean "no callers found".

Related: this repository has no CI runner, so "enforced" means `npm test` run by whoever
touches the code.

Still a posture and not a clearance: three named patents were read, no family or class
search was run (residual R7).

## R15 - The browser UI, CLOSED 2026-08-10 except for what only two people can close

**Status.** The headline of this residual is closed. On 2026-08-09 a full three-turn ceremony
ran on two physical devices (iPhone Safari and Mac Firefox) over HTTPS: the animated symbol
decoded across a table, six safety words were compared aloud and matched, ciphertext went both
ways, a reload restored identity, contact and conversation, and the idle lock was verified to
RELEASE the camera at five minutes. Agent-side beforehand, the optical hop was completed
BROWSER TO BROWSER with no human at all, and the decode worker and its WebAssembly were
observed loading under the shipped CSP, which closes R13's silent-failure branch by
observation rather than by inference.

**All three named arms RAN on 2026-08-10.** Headless, on the build host, against a real V4L2
virtual camera. Each was watched RED under a mutation before being believed, and a second agent
rebuilt from source on its own ports and reproduced all of it with new identities.

- **The mismatch path.** Three real instances, one camera. The control first, because it is load
  bearing: two honest instances produce the SAME six words, since a harness that cannot produce
  agreement has no standing to claim divergence. Then A against M, and B against the SAME M,
  produce different words. The repeatability control is what makes that mean something: the same
  two identities with a fresh nonce reproduce the words exactly, because the safety number takes
  only the sorted ids, the sorted x25519 keys and the DH. Feeding an instance its own frames
  gets `REFUSAL_SELF`, which proves the pixel relay is bound to the instance it is thought to be.
  The refusal releases the camera and pins nothing, checked after a reload and unlock of the
  same vault rather than only in memory.
  **Stated precisely, because the short version is wrong: Keyweave does not compare the words.**
  The human does, and the button press is the whole mechanism. What ran is (a) divergent words
  genuinely arising from a third identity and (b) "They do not match" refusing DURABLY. It is
  not the product detecting a mismatch, and it is not meant to be.
- **The camera-denial path.** Run headlessly after all, without an iPhone: CDP
  `Browser.setPermission` with name "camera" produces a real `NotAllowedError` and can be
  flipped at runtime, so denied, retry visible, still denied, granted, retry-starts-the-camera
  all run in one instance. The retry handler's comment about not leaving the previous attempt
  holding the camera had never executed; it does now, and the old track reads `ended`. What
  remains iOS-only is Safari's user-gesture requirement, WebKit's error naming, and
  `requestVideoFrameCallback` availability.
- **The insecure-context control.** Driven with `--host-resolver-rules`, so the ORIGIN is
  insecure while the server stays loopback bound and nothing is exposed. `isSecureContext` false,
  `navigator.mediaDevices` undefined, the error text equal to `CAMERA_COPY.insecureContext`, and
  the retry button correctly HIDDEN because only a denial earns one. It also produced the first
  browser execution of the DEGRADED KEY BACKEND in this project's history, since `crypto.subtle`
  is undefined on such an origin: with no WebCrypto the key layer falls back to @noble keys that
  stay extractable in JavaScript memory, which `client/src/keys.ts` labels a degraded fallback in
  its own comments and which nothing on screen mentions, so a person on an insecure origin runs
  the weaker path without being told.

**What is still unrun, and it is the part only people can close: TWO HUMANS.** The 2026-08-09
run was across a table, and the symbol did decode across it, but it was one person holding both
devices; the divergence arm above is proven across two sequential ceremonies and two
screenshots, not across two people comparing six words to each other in one sitting. What is
missing is the second human, not the table. Also untouched by any of this: focus, glare,
motion blur, panel tearing, and any camera that is not a synthetic 640x480 30 fps one.

**The structural gap that no device test closes is now itself closed:** `src/ui/app.ts` had no
executable coverage when this was written. It has had it since 2026-08-09, and the residual
gaps that survived that work were closed on 2026-08-10.

The original text of this residual follows, because the parts of it that are still true are
still true.

The pairing ceremony's logic is driven headless against real crypto objects, its markup is
machine-checked against the templates the app actually clones, and the emitted bundle is
scanned byte by byte. None of that is a run. There is no browser and no DOM harness in the
build environment, so every claim about what a user SEES is an inference from source.

What that leaves genuinely unverified:

- The ceremony end to end on two real devices: camera focus and framing at conversational
  distance, whether the animated symbol decodes across a table, and whether the frame
  pacing holds on a phone.
- The tightened CSP under a real engine. If the decoder never starts, suspect
  `script-src`/`worker-src` first (relax `blob:` on those two and nothing else), then a
  `Permissions-Policy` on the serving host, which can deny the camera without the page
  knowing why.
- Screen-level behaviour of the lock, refusal and error paths, including one known cosmetic
  edge: an idle lock landing while the camera permission prompt is still open can leave one
  stale sentence in the live region for a screen-reader user.
- The conversation screen, added in the messaging work package: whether the alignment and
  grouping actually read as a conversation, whether the 20 second poll feels right or
  wrong, and whether a long message wraps sensibly inside a bubble. All three are
  judgements about a rendered page, which is precisely what a headless suite cannot make.
  The messaging LAYER is not part of that gap: `src/messaging.ts` and `src/relay-client.ts`
  are driven end to end against a relay stub that reorders, duplicates, truncates,
  corrupts, over-serves, redirects, stalls and lies about its own answers. The SCREEN that
  drives it is part of the gap, and more of it than the wording above suggested:
  `src/ui/app.ts` has NO executable coverage at all. Nothing in `client/test/` imports it,
  no test constructs `KeyweaveApp` or calls `renderConversation`, and the one occurrence of
  the string `ui/app` in the suite is a filename inside a source-text scan. So the busy
  latch and its disabled buttons, the poll teardown, the sync wording, the failure mapping
  and the thread grouping are all checked as TEXT and have never run. That seam is where a
  defect found in review actually lived: an unbounded pull loop is only a freeze because
  app.ts holds the composer disabled for the whole of a sync, and no test in this suite
  could have caught it, because one half of it is text-checked only. Closing this properly
  means a DOM harness, which is a work package, not a paragraph.
- iOS Safari specifically, which is the platform the vendored camera quirk handling exists
  for and the one most likely to differ.

This is the top open item for the browser work package. It needs an owner with two devices,
not another agent round: the thing being tested is whether two humans can complete the
ceremony, which is exactly what a headless suite cannot answer.

## R16 - The sync status line can print two true sentences that read as one contradiction

A refresh does two things: it flushes queued outbound messages, then it collects waiting
inbound ones. Either half can fail, and the single status line the user reads does not label
which half a sentence belongs to.

The case that matters: a flush timeout occurring in the SAME refresh as a pull that died
mid-body renders both "The relay did not answer in time. Nothing was lost; try again in a
moment." and "A message was being collected when the transfer failed ... that one may be gone:
ask your contact to send it again."

Both sentences are true. The first is about the send half, where the record genuinely stays
queued with its bytes and really is safe. The second is about the receive half, where the relay
deletes a blob as it hands it over, so an aborted transfer really can destroy a message. Read
as one line by a person who does not know the refresh has two halves, they contradict.

This was reached by trying both of the obvious rules and finding each wrong in its own way.
Suppressing the reassurance whenever anything was lost makes it disappear on the send path
where it is true and actionable. Keying it to the phase that produced the failure, which is
what ships, keeps each sentence true but allows this pairing. The remaining fix is to attribute
the phases on screen, which means new user-facing copy, and inventing copy in a closing round
on a public security product is how a fix becomes the next finding. It is named here instead.

Reproduce it by executing the real renderer rather than reading it:

    cd client && npx esbuild src/ui/copy.ts --bundle --format=esm --outfile=/tmp/kw-copy.mjs

then call `syncSummary` with a flush failure of `timeout` and a receive report carrying
`interrupted: 1`.

Two smaller things in the same layer, both recorded rather than fixed for the same reason:

- **`ReceiveReport.unread` is documented as meaning "the pass ran out of its budget",** and it
  also counts ids stranded when the pass stopped early on a relay failure with the budget
  nearly untouched. The string built from it ("N still waiting at the relay") is true on every
  path, so this is a comment that is narrower than the field, not a false user-facing claim.
- **When BOTH halves fail, the flush failure masks the receive failure** in the rendered line,
  because the renderer takes the first one that exists. The case that costs something is a
  reclaimed inbox: its advice is "pair again in person", and it is replaced by the flush's
  "try again in a moment", which cannot work for the receive half. This behaviour predates the
  work in this round and was relocated verbatim, not introduced by it.

**One class where a destroyed message is reported with no loss sentence at all, and, in one
shape, with a false reassurance:** a pull whose answer is oversize or malformed is counted as
`defective`, and the `defective++; continue` that counts it never assigns `report.failure`. So
`relayFailureMessage('oversize')` and `relayFailureMessage('malformed')` are UNREACHABLE from a
pull defect: those two strings render only from the `listBlobs` catch, which is a failure of the
LIST, where nothing was pulled and therefore nothing was deleted. The sentence about an answer
being dropped unread is never printed about the pull that destroyed something.

What is printed instead was measured by executing the real receive() over the real relay client
against a relay that routes the pull, so its delete-on-pull genuinely fires, and only then hands
back an answer declaring more than `MAX_RESPONSE_BYTES`:

- a LONE defective pull renders exactly `0 new messages.` and nothing else. The blob is gone
  (an unhurried pass over the same mailbox afterwards lists nothing), and the line carries no
  hint that anything was lost;
- a defective pull FOLLOWED BY the budget refusing the next id renders `0 new messages. 2 still
  waiting at the relay. The relay did not answer in time. Nothing was lost; try again in a
  moment.` That last clause is a reassurance about a pass in which a message really was
  destroyed, which is worse than the missing warning above rather than milder than it.

It is named rather than fixed for two reasons, and both are load bearing. It is PRE-EXISTING:
run against the revision immediately BEFORE this round's messaging work, the identical scenario
renders the byte-identical reassurance line, and the lone-defect line differs from it only by
the terminating stop this round's renderer adds to every summary. That revision is not reachable
from the public history, which begins at the squashed `v0.1.0` commit, so a reader outside this
repository cannot re-run that comparison and has this record for it and nothing else. What such
a reader can run is the measurement described above, against the shipped code, which is the half
that decides whether the line is wrong today rather than who made it wrong. And it requires a
NONCONFORMING relay: the ceiling is 256 KiB
(`MAX_RESPONSE_BYTES`) while the relay's own write path caps a blob at 64 KiB
(`max_blob_bytes`, and the shipped nginx refuses a request body over 128 KiB before it reaches
the relay at all), so an honest relay has no way to answer a pull with an oversize body. A
correct fix is to carry the defect count into the rendered line, which is new user-facing copy,
and inventing copy in a closing round is how a fix becomes the next finding. Hence here.

## R17 - The idle lock does not fire while a conversation screen is open, and that is a decision

The vault re-locks itself after `IDLE_LOCK_MS` (five minutes) of not being read. An open
conversation polls the relay every `POLL_INTERVAL_MS` (twenty seconds), and each poll reads
the vault: `messaging.sync` calls `flush`, `flush` calls `require()`, `require()` reads the
mailbox, and every unlocked read goes through `Vault.assertUnlocked()`, which calls
`touch()`. Twenty seconds is shorter than five minutes, so the timer is rearmed before it
can ever expire. On the one screen a person is most likely to leave open, the idle lock does
not run.

**It arrived as an accident and it is kept on purpose.** That is the whole content of this
entry: an undeclared exception and a decided one behave identically and are worth completely
different amounts, and the difference is whether the next person to read the code has to
work out whether anybody noticed.

**Why it is accepted.** The threat an idle lock answers on this screen is a live unlocked
session on a device somebody else has, which is out of scope by name in two places already:
the threat model's "Steal an unlocked / live-session device" row, and R5. No published claim
is falsified by it, and the client copy has been corrected so that none is made in the
product either (see below). The half of the idle lock that is load bearing is the CAMERA
RELEASE, verified on hardware (R15), and the camera is not on this screen at all:
`renderConversation` tears the optics down before it renders.

**Why it is not fixed.** Every fix is a judgement about presence that the app does not have
the evidence for. Exempting the poll from `touch()` means a vault that locks under somebody
who is reading a long thread, which is a worse outcome than the one being prevented and
arrives on a timer with no warning. Tracking real interaction means input listeners on a
screen that deliberately has no background machinery. Both are new behaviour on a public
security product in a closing round, which is how a fix becomes the next finding.

**What the product says about it.** `lockNotice` used to say the vault "locked itself after
N minutes with nothing happening", which was false twice over on this screen: the timer
measures time since the last unlocked READ rather than since the person last did anything,
so it can expire mid refresh, and "Nothing was saved" is untrue of a screen whose outbound
messages are written before the relay is called. The shipped sentence now says "with nothing
on this device reading the keys" and attaches "Nothing was saved from it" to the dropped
pairing, then says what does survive. One string is rendered on every screen, so a clause
that is only true of the ceremony is a false clause somewhere else.

**Where it is pinned.** `client/test/app-conversation.test.ts`, the test titled DECIDED
EXCEPTION (residual R17). It keeps its negative control, on the same app and the same clock:
leaving for the ready screen stops the poll, and there the idle lock fires within the same
window and announces itself. Without that half the test would also pass on a vault whose
idle timer was never armed.

**What reopens it:** any claim that Keyweave locks itself after a period of inactivity
regardless of which screen is up, or any change that puts key material on the conversation
screen which the camera-release argument does not cover.

**And one operational condition that is easy to miss, because it runs the other way.** Keeping
R17 is currently what holds R18 shut. While the poll rearms the timer, a lock essentially never
lands in the middle of a receive on this screen, and R18's loss of already-accepted messages
stays exotic. FIXING R17 MAKES R18 ORDINARY: the shipped budgets are a 15 s flush plus a 20 s
receive against a 20 s poll, so on a slow but answering relay a pass is almost always in
flight, and a five minute idle lock would then land inside one routinely. So R17 and R18 must
be read together, and R18 should be closed FIRST. Recorded here because two mitigations whose
holes line up on the same input are one mitigation, and this pair only looks like two.

## R18 - A lock landing mid receive destroys the messages that pass had already accepted

`receive()` pulls a blob, opens it, verifies it, admits it through the replay guard, and
pushes the record into the live vault array. Those records become DURABLE at a single
`persist()` after the loop. So a vault that locks part way through a pass loses every message
that pass had already accepted, not just the one in flight: `MAX_PULLS_PER_RECEIVE` is 32, so
the window is up to 31 messages. The relay deleted each of those blobs when it served them
(delete-on-pull, R9), so there is no second copy anywhere and the next refresh will not find
them. The sender is never told, because a message handed to the relay and collected looks
identical to one handed over and collected successfully.

**What has been done.** `receive()` now asks `host.isLocked()` before issuing each pull, which
removes the much larger case where the vault was ALREADY locked and every subsequent pull
destroyed a message on arrival. Measured: in the same scenario, the code before that check
pulled and destroyed a third blob which now stays in the mailbox. After the loop the same
question becomes a `MessagingError('locked')` throw, so the UI stops repainting a conversation
out of an emptied vault instead of crashing in a discarded promise.

**What has NOT been done, and why it is a residual rather than a fix.** Closing the remaining
window means making each accepted message durable as it arrives, and `persist()` re-seals and
rewrites the WHOLE vault, so a persist per accept is quadratic in history length. The honest
options are a per-message durable write, an append-only inbox log replayed into the vault, or a
receive that does not delete at the relay until the message is safely stored, and the last one
is a protocol change that trades at-most-once for at-least-once. All three are design work.
Doing any of them inside the commit that fixed the pull ordering would have been exactly the
"a fix is the likeliest source of the next finding" pattern this project has already paid for
twice.

**Severity today, stated honestly.** Reaching it needs a pass stalled for about five minutes,
which `messaging.ts` names as possible for a suspended machine. It is rare because R17 keeps
the idle lock from firing on the conversation screen at all. That is a mitigation nobody chose
for this purpose and it disappears the moment R17 is fixed, which is why R17 now carries a
pointer back here.

**What reopens it as urgent:** fixing R17, shortening `IDLE_LOCK_MS`, raising
`MAX_PULLS_PER_RECEIVE`, or any claim that Keyweave does not lose messages it has collected.

## R19 - The relay learns a pairing began before anyone decides to trust anyone

`beginCeremony` reserves a drop box on the relay BEFORE the ceremony starts:
`await this.reserveInbox()` precedes `PairingSession.begin`. So the relay receives a
`POST /v1/mailboxes` from this network address at the moment a person presses Show or Scan,
which is before any card has been exchanged, before the six words exist, and before anybody has
decided anything. **Including the ceremonies that end in a refusal.**

Measured while running R15's mismatch arm, which is the only reason it was found: 10 ceremonies
begun produced 10 mailbox reservations against 3 actual pairings, and one session left 33
mailbox directories on the relay.

**The ordering is forced, not careless.** The mailbox coordinate has to ride inside the turn-1
`info` payload, and that payload is built before the peer's card has even been seen. Reserving
later would mean a second optical turn or a coordinate sent over the relay itself, and the
second option hands the relay the very linkage the optical channel exists to keep away from it.

**What it means, stated exactly.** The refusal screen says nothing was saved, and that is TRUE of
this device. It is not true of the relay, which was told that this address started a pairing at
time T even though the humans then decided not to trust each other. An observer of the relay
therefore sees attempted pairings, not just successful ones, and can count them and time them.
The blobs stay opaque and no identity is disclosed; what leaks is the fact and the timing of an
attempt.

**Why it is not R3 or R8.** R3 covers metadata the relay observes about MESSAGING between paired
devices. R8 covers the STORAGE consequence of an empty box left idle past `mailbox_idle_days`,
whether it was abandoned at a ceremony or simply never opened again. Neither says that a
REFUSED pairing has already been announced to a third
party, and the refusal copy reads as though nothing left the device at all.

**What reopens it:** any claim that a refused pairing is invisible outside the two devices, or
any change that puts identity material rather than an opaque coordinate into the reservation.

## R20 - Non-extractable key handles do not protect the seed

R1 names non-extractable WebCrypto keys as a mitigation. Until 2026-08-10 its wording credited
them with denying a later-served bundle the ability to exfiltrate long-term keys. That is true
of the `CryptoKey` handle and false of the thing that actually matters, which is why R1 now
points here.

Keyweave generates two 32-byte seeds in JavaScript from the platform CSPRNG, stores them in the
passphrase-sealed vault, and imports them into non-extractable `CryptoKey`s on every unlock.
The entropy is fine; the reachability is the problem. `generateKey` is never called, so the key
material exists in JavaScript memory before the import, during it, and for as long as the vault
stays unlocked. A malicious bundle that can run in the page can read a seed and rebuild the
identity offline, at leisure, forever. Sixty-four bytes are enough.

The fact was half-recorded in the source: `client/src/keys.ts` says the seeds are the only
serialized secret and that they live encrypted in the vault. The same comment block used to
state the payoff this residual refutes, that a later-served bundle "cannot exfiltrate raw key
bytes and decrypt forever offline" - the code carried the same overclaim as the documents.
That comment was corrected in the first release after v0.1.1, and it now names this residual
instead of contradicting it.

This is a deliberate tradeoff and not an oversight, but it was never written down. Keys that are
generated inside WebCrypto and never leave it would close this branch, and browsers can persist
such a key by structured-cloning it into IndexedDB. The cost is that the vault stops being
portable: it becomes bound to one browser profile on one device, and a lost device is a lost
identity with no passphrase recovery. v0 chose a portable, passphrase-recoverable vault. A
device-bound key option is v1 work and is the right way to close this.

**Portable describes the FORMAT and not anything that ships**, so the tradeoff above is
narrower than it sounds: v0 has no export, no backup and no second device, the vault lives in
one browser profile and nothing in the code moves it to another, and clearing site data
destroys the identity with it - which the product does say, and the only remedy it offers is
a new identity and a fresh pairing in person.

What the non-extractable handles still buy is narrow and real: a bundle that gets only the handle
can sign and decrypt while it is resident, and cannot walk away with the key. That is the
difference between an online oracle and an offline archive, and it is worth having. It is not
what R1 claimed.

**What reopens it:** any claim, in the documents or in the product, that a compromised bundle
cannot obtain long-term key material.

## R21 - An idle lock during a ceremony discards the ceremony, and nothing is kept

`IDLE_LOCK_MS` is five minutes and the pairing ceremony has no exemption from it. R17 is about
the screen where the timer never expires; this is the screen where it does, because a ceremony
runs on camera frames and optical decoding and none of that reads the vault, so nothing rearms
the timer while two people are working the phones. A ceremony left standing for five minutes,
a phone put down between turn one and turn two or a person walking off to fetch the other
device, fires the lock under whatever is on screen: `onLock` tears down the optics and clears
BOTH the ceremony and the session, the keys leave memory, the passphrase is forgotten and the
half-exchanged pairing is gone. It was verified on hardware at five minutes when the camera
release was checked (R15).

**It is announced rather than silent.** `lockNotice` is the string that renders, and it says
that any pairing that was running has been dropped and the camera released, that nothing was
saved from it, and what does survive. So the behaviour is disclosed in the product; what was
missing until now is a number in this register for it.

**Why it is kept.** A half-done ceremony is holding the peer's card and this device's own
ephemeral state, and a lock that preserved either would have to write key material somewhere
the lock does not reach, which is the one promise the vault exists to make. Discarding is the
only behaviour consistent with what a lock claims to do. The cost is bounded by the same
property the product is built on: the two people are in the same room, because that is what
pairing means here, so starting again costs a ceremony and nothing else.

**Where it came from.** This was raised in review as F1 and carried no number, which is why
nothing in this repository referenced it: `git grep -nw F1` found the identifier nowhere at
all while the copy for it shipped in `src/ui/copy.ts`. A behaviour that is announced to users
and absent from the register is exactly the gap this file exists to close.

**What reopens it:** any claim that a ceremony survives a lock or can be resumed after one, or
a change to `IDLE_LOCK_MS` short enough that the window lands inside a ceremony two people are
actually running rather than inside one they walked away from.

## R22 - A send costs two whole vault re-seals, which is about six seconds

`send()` saves the vault TWICE on the success path: once after the outbox record is written
and before the relay is called, and once inside `flush()` when the relay accepted anything.
Every save re-seals the WHOLE vault, and the seal derives its wrap key with Argon2id at
`ARGON2_DEFAULT`, three passes over 256 MiB, against a FRESH SALT each time. Nothing from the
first derivation can be reused by the second, so the second costs exactly what the first did.

**Measured twice, agreeing inside one percent:** 3193 ms plus 3146 ms on a Ryzen desktop,
about 6.3 seconds of key derivation inside one successful send. The press-to-summary time
was not measured end to end; the two derivations are what dominate it. A push the relay refuses
costs one of them, about 3.2 seconds, because the second save happens only when something was
relayed. The per-seal half reproduces without the app, from `client/`:

    node --input-type=module -e "
    import { argon2id } from '@noble/hashes/argon2.js';
    const t = performance.now();
    argon2id(new Uint8Array(8), new Uint8Array(16), { t: 3, m: 262144, p: 1, dkLen: 32 });
    console.log(Math.round(performance.now() - t));
    "

which read 3183 and 3164 ms on the machine this entry was written on. Double it for a send.

**What the person sees while it runs.** The textarea stays typable and the tab stays alive,
because the derivation happens in the vault worker and not on the UI thread. Send, Refresh
and the twenty second poll are all held off for the whole of it by the busy latch in
`src/ui/app.ts`, so the screen answers and the app does not.

**Why it is this way rather than an oversight.** The order of writes is the point, and
`src/messaging.ts` records it at the top of the file: the outbox entry is persisted BEFORE
the relay is called and never after, because the other order costs a message the relay
accepted and this device forgot (R9). What that discipline costs in v0 is a whole-vault
re-seal, which is the same property R18 names, seen from the sending side instead.

**What would close it,** and none of it is a wording change: caching the wrap key for the
life of an unlocked session, or sealing once per send rather than twice, or both. The first
trades a measured delay for a derived key kept resident while the vault is unlocked, which is
an argument about R5 and R20 rather than about latency, so it belongs to a version that can
make that argument properly. This is v0.2 design work.

**It was known and unpublished, which is the part worth recording.**
`client/src/ui/vault-crypto.ts` states the 3.2 second measurement in its opening comment, so
the number sat in the source the whole time. No user-facing document carried it until this
entry.

**What reopens it:** any claim that sending is fast or immediate, or any change to
`ARGON2_DEFAULT`, which moves this number in either direction and moves nothing else.
