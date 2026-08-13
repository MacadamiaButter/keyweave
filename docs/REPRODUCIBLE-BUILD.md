# Reproducible build and out-of-band integrity

This document exists because of R1, the top named residual: Keyweave is web software, and
the server that delivers the JavaScript is inside the trust base of everyone who uses it.
Optical pairing does nothing about that. A compromised origin can serve a bundle that shows
two people matching safety words which mean nothing.

Nothing here removes R1. What it does is make a lie about the code **detectable by someone
outside the serving host**, which is the only kind of check worth building.

## The build is a function of the commit AND one environment variable

This is the part that is easy to forget and silently breaks out-of-band verification.

`KEYWEAVE_RELAY_ORIGIN` chooses whether the relay lives on the app's own origin or on its
own (residual R2). It is a BUILD input, not a runtime one, and it is baked into two of the
emitted files: the `connect-src` in the page's Content-Security-Policy, and the relay base
URL compiled into the client bundle. Two builds of the same commit with different values
therefore produce different hashes. Legitimately.

Which means:

> **A release attestation that publishes hashes without naming the
> `KEYWEAVE_RELAY_ORIGIN` they were built with is not verifiable.**

Not "harder to verify". Not verifiable. A reproducer who guesses the wrong value gets a
mismatch on every file and has no way to distinguish that from a tampered release, so the
only two outcomes are a false alarm and a shrug. Both destroy the property this document
exists to provide.

`scripts/reproduce.sh` prints the value it built with in its output block, next to the
commit and the node and npm versions. Quote the WHOLE block into the release body.

## What is proven today

A clean clone of this repository, installed from the committed lockfile and built, produces
byte-identical artifacts to a build in the working tree.

    KEYWEAVE_RELAY_ORIGIN=https://relay.example scripts/reproduce.sh [git-ref] [output-dir]
    KEYWEAVE_SAME_ORIGIN=1                      scripts/reproduce.sh [git-ref] [output-dir]

One of those two is required. The script refuses if neither is set, because the relay origin
changes the bytes: omitting it silently produces a bundle in which four of the six artifacts
still match the release, which reads exactly like two files having been tampered with.

Measured 2026-08-08 on a pre-release revision that is not part of this repository's published
history, with node v22.22.1 and npm 9.2.0: two consecutive
working-tree builds agreed, and a fresh `git clone` plus `npm ci` plus `npm run build` agreed
with both, across all six emitted files including the wasm. So the build does not depend on
uncommitted edits, stray files, or a warm `node_modules`. Nobody has to take that on trust:
the same measurement at a tag you can check out is two runs of `scripts/reproduce.sh v0.1.2`
with the same `KEYWEAVE_RELAY_ORIGIN`, compared.

Re-measured 2026-08-09 for the split configuration: two consecutive working-tree builds with
`KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org` produced byte-identical
hashes across all six files. Diffed against the default build: four of the six (the
stylesheet, both workers, the wasm) are byte-identical, and two differ, `index.html` and the
entry chunk, whose filename changes too because its content hash does. Those two are the
value appearing in the artifact, and they are the whole reason it has to be published.

That is a real property and it is also a modest one. Read the next section before quoting it.

## Cross-machine corroboration (WP8), measured 2026-08-09 at a pre-release revision

Determinism on one host proves the build ignores uncommitted edits and warm caches. It does
not prove the artifact is independent of the host. Two machines sharing no operating system,
no CPU architecture and no administrative domain built the same source and agreed on all six
hashes.

Both ran `scripts/reproduce.sh` at the same revision with
`KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org`. Build host A is Linux on
x86_64 and hashes with `sha256sum`; build host B is macOS on arm64 (Apple Silicon) and hashes
with `shasum -a 256`. Both pinned node v22.22.1 and npm 9.2.0, host B down from the 10.9.4
that node bundles.

**That run was made on a pre-release revision, and its hashes are deliberately not published
here.** They belong to a commit that is not part of this repository's published history, so no
reader can check it out and no reader could ever verify them. Digests nobody can reproduce,
printed next to digests anybody can, are worse than no digests at all: they read as a
disagreement about the released artifact rather than as a measurement of something else. At
`v0.1.0` only build host A has attested, which is what that release body already says. For
`v0.1.0` the release body is the only published record of that tag's hashes; from `v0.1.1` the
record is the signed tag message, and the release body repeats it as a readable copy.

**THE TRAP: the build log reports DIFFERENT numbers for an IDENTICAL artifact.** vite prints a
gzip size next to each file and those differ between the two machines: `index.html` 5.06 vs
5.09 kB, the wasm 402.52 vs 400.45 kB. That is the local zlib compressing for a report. It is
not part of the artifact and it is not hashed. Anyone eyeballing two build logs side by side
will see mismatched numbers and conclude the builds disagree. They do not. Compare the hash
block, never the size column.

How the second machine was staged, since a corroboration you cannot audit is worth little:
node was downloaded from nodejs.org and verified against the official `SHASUMS256.txt` BEFORE
extraction; npm was pinned down to match, because `npm ci` is what materialises the dependency
tree and pinning node alone leaves npm uncontrolled; everything lived in one removable
directory with no system-wide install. Build host B could not reach the source repository
directly, so it cloned from build host A at a pinned commit, which does not weaken the result:
git object ids are self-verifying, so the source is pinned by hash regardless of which host
served the bytes. The variables that matter here are OS, architecture and admin domain, and
all three differ.

**This MUST be re-run at the actual release tag**, and until it is, a release names one
attesting host and not two. `docs/DEPLOY.md` tracks that as outstanding work. When it is done,
both attestation blocks belong in the release body, and both must carry
`KEYWEAVE_RELAY_ORIGIN`, because the artifact hash depends on it.

## What is NOT proven, stated plainly

- **Cross-machine reproducibility is measured for ONE pair of machines, at ONE pre-release
  revision, and that is a narrower claim than "reproducible".** The WP8 section records two
  independent machines, different operating systems and different architectures, agreeing on
  all six artifact hashes. That retires the older statement here, which said cross-machine
  reproducibility was untested and survived, uncorrected, in the same file as the section
  disproving it. What is still NOT established is reproducibility across arbitrary node and
  npm versions: both attestations pinned the same major toolchain, so a different one may
  well produce different bytes, and nothing here has tested that. Anyone reproducing should
  publish the toolchain they used alongside the hashes, exactly as the WP8 section above does.
- **`npm ci` trusts the registry.** The lockfile pins versions and integrity hashes, so a
  silent substitution would have to break those hashes, but the first resolution of any
  dependency trusted the registry and the audit that produced this tree.
- **A reproducible build says nothing about what a given visitor received.** It compares the
  source to a hash. It cannot see the bytes a particular browser was served, which is the
  whole point of the per-user attack R1 describes.
- **Nothing forces a release to state its `KEYWEAVE_RELAY_ORIGIN`.** `scripts/reproduce.sh`
  prints it, and the procedure below says to copy the whole block, but the procedure is
  owner-run prose and a person can skip a line. A release that omits it looks exactly like
  one that includes it until somebody tries to reproduce, which is the wrong moment to find
  out. Making this machine-checkable needs a release step nothing in this repository has
  today, so it is named here rather than claimed as closed.
- **For a ref older than work package 7 the variable is not an input at all**, because
  `client/build-config.mjs` did not exist and the build never read the environment. The
  script detects that from the checked-out tree and prints
  `KEYWEAVE_RELAY_ORIGIN : NOT AN INPUT to this ref`, plus a line naming the value that was
  set and ignored. It used to print the requested value in the `build inputs:` block
  regardless, which is a false attestation in exactly the block people are told to quote: it
  claims a value shaped bytes it had no effect on, and it sends a reproducer hunting for
  tampering in a mismatch that cannot happen.

## Where the hash is published, and why not here

**Out of band, in a trust domain independent of the host serving the app: a signed git tag
and a GitHub release on the public repository.** Never on the VPS, never in the app, never
on the page.

The reasoning is the same one that makes Subresource Integrity useless for a first-party
bundle. If the hash lives on the origin that serves the bundle, an attacker who can replace
`bundle.js` can also edit the page that names its hash. Two artifacts under one root are one
artifact. GitHub is already in the story as the source host, is operated by someone other
than the VPS operator, and records a publication timestamp that it controls rather than we
do, so it is a genuinely separate administrative domain and not a second copy of the same
one. It does not sign anything: the release body is protected by account control, and anyone
who takes that account can edit it.

A signed tag does not fix that on its own, and it is worth being exact about why, because the
distinction is easy to state wrongly and this document has done so before. `git verify-tag`
checks a signature over the tag OBJECT, which names a commit and carries a message. It says
nothing whatever about a GitHub release body, which is a separate and mutable field: that body
can be rewritten while the tag signature keeps verifying perfectly. GitHub's own API reports
`"immutable": false` for a release. So the hashes go INSIDE the signed tag message, where the
signature actually covers them, and the release body is a convenience copy for people reading
in a browser. **Where the two disagree, the tag message is the one to believe.** The next
section says how to check it, and what is true for the tag that predates the key.

For the same reason there is **no in-app "verify integrity" button**. Malicious code asked to
report its own hash reports the honest one. Self-attestation is not evidence.

## Verifying the tag signature

Two commands, and they are the difference between trusting a key and trusting an account.

The release signing key's fingerprint is:

    D78D89413752779209479B9ACF5C8AB3DB4A56EB

It is `Keyweave Release Signing <hello@localfirstlab.org>`, an Ed25519 key created on
2026-08-10 for this purpose and for nothing else. It is deliberately not the maintainer's
personal key.

Fetch the key from `https://localfirstlab.org/keyweave-release-key.asc`, which is on
`localfirstlab.org` and **not** on GitHub. A key served by the same host that serves the tag
proves nothing, because whoever can replace the tag can replace the key that matches it. That
is the same argument that keeps the hashes off the VPS, applied one level up. The same
fingerprint is served on its own at
`https://localfirstlab.org/keyweave-release-key.fpr`, so you can check it without importing
anything.

    curl -fsSL https://localfirstlab.org/keyweave-release-key.asc | gpg --import
    git verify-tag <tag>
    git cat-file -p <tag>

The second command prints the signed tag message, which is where the artifact hashes and the
build inputs live. Read them from there rather than from the release body: that is the whole
point of signing.

**GitHub will show a signed tag as "Unverified", and that is expected.** Its API reports
`"reason": "unknown_key"`. The signing key is deliberately not registered with the GitHub
account, so GitHub genuinely cannot check it and says so. A badge GitHub controls would be the
same account-anchored trust this whole section exists to move away from. The consequence worth
knowing: `verified: false` appears both on a tag that is unsigned and on one signed by a key
GitHub does not hold, so that field alone cannot distinguish them. `git verify-tag` can.

A good result names the key and reports a good signature. gpg will also warn that the key is
not certified with a trusted signature unless you have signed it yourself; that is expected
and is not a failure. What matters is that the fingerprint gpg reports is character for
character the one above, and that you obtained that fingerprint from somewhere other than the
repository you are checking.

**`v0.1.0` is unsigned and will stay unsigned.** Signing it now would mean moving a published
tag, which is the one thing a verifier is entitled to assume did not happen. So a verifier
working from `v0.1.0` has account control as the only anchor: the hashes in that release body
are held in place by whoever holds the account, and by nothing else.

From `v0.1.1` onward the signed tag message carries the artifact hashes and the build inputs
as well as the commit, so what anchors them is a key rather than an account. The release body
for those tags stays account-protected and stays editable. It is a copy, and the tag message
is what to check it against.

## How a user verifies the bytes they actually received

Only the visitor's own browser can do this, which is the uncomfortable but honest shape of
the problem.

1. Open developer tools, Network tab, and reload the page.
2. For each script and the page itself, save the response body exactly as received.
3. `sha256sum` each file.
4. Pick the tag you intend to be running and compare with the hashes in ITS signed tag
   message, having first checked that tag's signature ("Verifying the tag signature" above).
   The page does not tell you which version it is, and is not asked to: a bundle reporting
   its own version is the self-attestation refused above, so the verifier names the tag and
   the bytes either match it or they do not. An unverified release body is a web page like
   any other. A tag message can carry more than one labelled hash block, one per build
   configuration: `v0.1.2` carries the deployed-origin block first and the same-origin block
   second. Compare against the block whose stated build inputs match the configuration you are
   checking, because a disagreement with the OTHER block is a different build input and not
   tampering.

A mismatch means the served bytes are not the released bytes. A match means they were, for
that visit, on that machine. It says nothing about the next visit, which is why this is a
spot check a motivated user can perform, not a guarantee the product provides.

Reproducing from source rather than comparing to the release means matching the build inputs
too, `KEYWEAVE_RELAY_ORIGIN` included. If a release does not state it, stop: the comparison
cannot be made, and a mismatch would say nothing.

## The release procedure

Owner-run, always. The agent lane stages; a person publishes.

1. Decide the relay topology and export it, then run the script at the reviewed commit and
   capture the WHOLE output block, build inputs included:

   ```bash
   export KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org
   scripts/reproduce.sh <commit>
   ```

   Set `KEYWEAVE_SAME_ORIGIN=1` instead for a same-origin release, and say so in the block:
   same-origin is a value, not a missing one. The script refuses if neither is set, so an
   operator who meets that refusal has met a designed behaviour and not a fault. The tag
   does not exist yet; the commit is what it will point at, and a build at the commit and a
   build at a tag naming that commit check out the same tree.
2. Put the whole block into the ANNOTATED TAG MESSAGE: commit, node, npm, the relay origin,
   and the hashes. That is what the signature covers. Hashes without the build inputs are not
   a verifiable claim. Then sign the tag with the release signing key, which is the key whose
   fingerprint is published under "Verifying the tag signature" and not a personal key, and
   check your own work with `git verify-tag <tag>` before going further. The block goes in
   before signing because a signed tag message cannot be edited afterwards: changing it means
   moving the tag, which is the one thing a verifier assumes did not happen.
3. Create the GitHub release for that tag and copy the same block into the body, as a
   convenience for people reading in a browser. The body is editable by whoever holds the
   account, so it is a copy and never the record.
4. Deploy the built artifact to the app host, and send the response header generated for the
   SAME origin (`node client/scripts/print-csp.mjs <origin>`, and `docs/DEPLOY.md` step 5b).
5. Verify from outside: fetch the deployed files over the public URL, hash them, and compare
   with the release. Do this from a machine that is not the build host.
   `docs/DEPLOY-APP.md` step 8 carries this as a runnable block.

Step 5 is the one that is easy to skip and is the only step that checks the deploy rather
than the build.

## The build-host condition

**RESOLVED 2026-08-09 via (b). What follows is kept because it states why the condition
existed and what would re-open it, not because it is still outstanding.** The build user is
out of the container-daemon groups, and the closure evidence is a live negative control rather
than a file edit: after a reboot, `docker info` is refused permission on the socket and
`sudo -n true` fails. See `DEPLOY.md` for the three commands. If anyone ever re-adds that
group membership, this condition re-opens and the reasoning below applies again unchanged.

The build-host condition was this: the build user was in the `sudo` group and in the
container-daemon groups, `docker` and `lxd`. `sudo` is hardware-key gated; the other two were
**unattended root**. A poisoned build-time dependency running as that user could reach root
and tamper with an artifact before it is ever hashed, which put the build host inside this
product's trust base.

Design and build were granted a named override, since they need no attended slot and
delaying them clears nothing. **The public deploy is conditioned** on either:

- **(a)** building the released artifact in a clean, isolated environment that does not have
  to trust the current build host, and publishing the hashes for external verification, or
- **(b)** closing the build-host condition first. **This is the branch that was taken.**

One honest note on (a): running a container **on the same host** does not satisfy it. The
container daemon runs as root on that host and membership in its group is the very hole the
condition names, so a local container inherits what it is supposed to exclude. Satisfying (a)
means a different machine, or a build environment the operator of the current host cannot
reach. Anything less is theatre, and calling it a clean room would be exactly the kind of
claim this project refuses to make elsewhere.
