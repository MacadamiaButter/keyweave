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

    scripts/reproduce.sh [git-ref] [output-dir]
    KEYWEAVE_RELAY_ORIGIN=https://relay.example scripts/reproduce.sh v0.1.0

Measured with node v22.22.1 and npm 9.2.0: two consecutive
working-tree builds agreed, and a fresh `git clone` plus `npm ci` plus `npm run build` agreed
with both, across all six emitted files including the wasm. So the build does not depend on
uncommitted edits, stray files, or a warm `node_modules`.

Re-measured 2026-08-09 for the split configuration: two consecutive working-tree builds with
`KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org` produced byte-identical
hashes across all six files. Diffed against the default build: four of the six (the
stylesheet, both workers, the wasm) are byte-identical, and two differ, `index.html` and the
entry chunk, whose filename changes too because its content hash does. Those two are the
value appearing in the artifact, and they are the whole reason it has to be published.

That is a real property and it is also a modest one. Read the next section before quoting it.

## Cross-machine corroboration (WP8), measured 2026-08-09

Determinism on one host proves the build ignores uncommitted edits and warm caches. It does
not prove the artifact is independent of the host. Two machines sharing no operating system,
no CPU architecture and no administrative domain built the same commit and agreed on all six
hashes.

Both ran `scripts/reproduce.sh v0.1.0` with
`KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org`.

| | build host A | build host B |
|---|---|---|
| OS | Ubuntu, kernel 7.0.0-28 | macOS 26.5.1 |
| arch | x86_64 | arm64 (Apple Silicon) |
| node | v22.22.1 | v22.22.1 (pinned) |
| npm | 9.2.0 | 9.2.0 (pinned down from the bundled 10.9.4) |
| hasher | `sha256sum` | `shasum -a 256` |

Identical on both, at `v0.1.0`:

    2048c6379b5c41e7ce451e3edb508054c6fb57bdfe0939e17994dc60e3896c93  assets/index-CRbjoUn9.css
    7d8bfa8772e57debcae86ee15ddea24790f2d8bdaf70dd27e1a7d3bbef1ab3c6  assets/index-YBMGRTmk.js
    d05926e87642361e7a10b9b2ee377efabb2bbde590a020ed8df6a3f42c368c06  assets/receive-worker-Ci5FvgN9.js
    d684b21f785a9383fb1af58727b10b3a60ad6e4fc7e8a69c5a0e931e7f4ed3eb  assets/vault-worker-537G4wD3.js
    85d46f55d7c86a4d09bb04273367408b19c324f582d040d018aecb25a9a82942  assets/zxing_reader-EOacYbLr.wasm
    f75151fe4e2e18fbe6247cfd0ced78306f3c54631f97818b328f573cf71b3764  index.html

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
directory with no system-wide install. Host B cannot reach the private origin, so it cloned
from host A at a pinned commit, which does not weaken the result: git object ids are
self-verifying, so the source is pinned by hash regardless of which host served the bytes. The
variables that matter here are OS, architecture and admin domain, and all three differ.

**This MUST be re-run at the actual release tag.** The numbers above predate `v0.1.0`, and
predates the pull-deadline fix. Both attestation blocks belong in the release body, and both
must carry `KEYWEAVE_RELAY_ORIGIN`, because the artifact hash depends on it.

## What is NOT proven, stated plainly

- **Cross-machine reproducibility is measured for ONE pair of machines, at ONE commit, and
  that is a narrower claim than "reproducible".** The WP8 section above records two
  independent machines, different operating systems and different architectures, agreeing on
  all six artifact hashes. That retires the older statement here, which said cross-machine
  reproducibility was untested and survived, uncorrected, in the same file as the section
  disproving it. What is still NOT established is reproducibility across arbitrary node and
  npm versions: both attestations pinned the same major toolchain, so a different one may
  well produce different bytes, and nothing here has tested that. Anyone reproducing should
  publish the toolchain they used alongside the hashes, exactly as the WP8 table does.
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
than the VPS operator, and signs and timestamps releases, so it is a genuinely separate
domain rather than a second copy of the same one.

For the same reason there is **no in-app "verify integrity" button**. Malicious code asked to
report its own hash reports the honest one. Self-attestation is not evidence.

## How a user verifies the bytes they actually received

Only the visitor's own browser can do this, which is the uncomfortable but honest shape of
the problem.

1. Open developer tools, Network tab, and reload the page.
2. For each script and the page itself, save the response body exactly as received.
3. `sha256sum` each file.
4. Compare with the signed release for the version the page claims.

A mismatch means the served bytes are not the released bytes. A match means they were, for
that visit, on that machine. It says nothing about the next visit, which is why this is a
spot check a motivated user can perform, not a guarantee the product provides.

Reproducing from source rather than comparing to the release means matching the build inputs
too, `KEYWEAVE_RELAY_ORIGIN` included. If a release does not state it, stop: the comparison
cannot be made, and a mismatch would say nothing.

## The release procedure

Owner-run, always. The agent lane stages; a person publishes.

1. Tag the reviewed commit and sign the tag.
2. Decide the relay topology and export it, then run the script and capture the WHOLE output
   block, build inputs included:

   ```bash
   export KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org
   scripts/reproduce.sh <tag>
   ```

   Unset it instead for a same-origin release, and say so in the block: "unset" is a value,
   not a missing one.
3. Create the GitHub release for that tag with the whole block in the body: commit, node,
   npm, `KEYWEAVE_RELAY_ORIGIN`, and the hashes. Hashes without the build inputs are not a
   verifiable claim.
4. Deploy the built artifact to the app host, and send the response header generated for the
   SAME origin (`node client/scripts/print-csp.mjs <origin>`, and `docs/DEPLOY.md` step 5b).
5. Verify from outside: fetch the deployed files over the public URL, hash them, and compare
   with the release. Do this from a machine that is not the build host.

Step 5 is the one that is easy to skip and is the only step that checks the deploy rather
than the build.

## The build-host condition

**SATISFIED via (b). What follows is kept because it states why the condition existed and
what would re-open it, not because it is still outstanding.** The build user is out of the
container-daemon groups, and the closure evidence is a live negative control rather than a
file edit: after a reboot, `docker info` is refused permission on the socket and
`sudo -n true` fails. See `DEPLOY.md` for the three commands. If anyone ever re-adds that group membership,
this condition re-opens and the reasoning below applies again unchanged.

The estate ledger recorded H1: uid1000 on the build host was in the `sudo`, `docker` and `lxd`
groups. `sudo` is hardware-key gated; `docker` and `lxd` were **unattended root**. A poisoned
build-time dependency running as that user could reach root and tamper with an artifact
before it is ever hashed, which put the build host inside this product's trust base.

Design and build were granted a named override, since they need no attended slot and
delaying them clears nothing. **The public deploy is conditioned** on either:

- **(a)** building the released artifact in a clean, isolated environment that does not have
  to trust the current build host, and publishing the hashes for external verification, or
- **(b)** closing H1 first. **This is the branch that was taken.**

One honest note on (a): running a container **on the same host** does not satisfy it. The
container daemon runs as root on that host and membership in its group is the very hole H1
names, so a local container inherits the thing it is supposed to exclude. Satisfying (a)
means a different machine, or a build environment the operator of the current host cannot
reach. Anything less is theatre, and calling it a clean room would be exactly the kind of
claim this project refuses to make elsewhere.
