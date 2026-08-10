#!/usr/bin/env bash
# Rebuild the Keyweave web client from a git ref and print the artifact hashes.
#
# The point is not that this script is trustworthy. It is that anyone can run it, on their
# own machine, against the public source, and compare what comes out with the hashes in the
# published release for that ref. If those disagree, either the release is not built from the
# source it claims, or their toolchain differs. Both are worth knowing and neither is
# discoverable by reading the served page. A release body is protected by account control
# alone, so where a ref's tag is signed that signature is the stronger anchor;
# docs/REPRODUCIBLE-BUILD.md names the command that checks one and which refs carry one.
#
# Usage:  KEYWEAVE_RELAY_ORIGIN=https://relay.example scripts/reproduce.sh [ref] [out-dir]
#         KEYWEAVE_SAME_ORIGIN=1 scripts/reproduce.sh [ref] [out-dir]
#
# One of those two is required, and the refusal below says why. The release body for a ref
# names the value its own hashes were built with. KEYWEAVE_SAME_ORIGIN takes 1, true or yes
# and nothing else; any other value is refused by name rather than interpreted.
#
# Requires: git, node, npm, and either sha256sum or shasum. Network access to the npm
# registry for `npm ci`.
#
# THE HASHER IS RESOLVED, NOT ASSUMED, and that is not portability pedantry. The whole point
# of this script is that a SECOND machine can run it and compare, and the second machine here
# is a Mac. macOS ships `shasum`, not `sha256sum`, so under `set -euo pipefail` the original
# died at the hashing step after doing all the work: the cross-machine corroboration that
# answers "do you have to trust the build host" could not run at all on the only other host
# available to run it.
#
# THE BUILD IS NOT A PURE FUNCTION OF THE SOURCE REF. It also depends on
# KEYWEAVE_RELAY_ORIGIN, which chooses whether the relay lives on the app's own origin or on
# its own (residual R2). That value is baked into the artifact: it appears in the page's
# Content-Security-Policy and in the client's relay base URL, so two builds of the same
# commit with different values produce DIFFERENT hashes, legitimately.
#
# That dependency starts at work package 7. For any earlier ref the variable is not an input
# at all, and this script says so rather than printing it in the attestation block as though
# it were: an input line naming a value the build never read is a false attestation, and it
# sends a reproducer looking for tampering in a mismatch that cannot exist.
#
# Which means a hash published without the value it was built with is not verifiable. A
# reproducer who guesses wrong gets a mismatch and has no way to tell that apart from
# tampering, which is the exact question this script exists to answer. So the value is
# echoed in the output block below, and docs/REPRODUCIBLE-BUILD.md requires it in the
# release body.

set -euo pipefail

REF="${1:-HEAD}"
OUT="${2:-$(mktemp -d)}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_ORIGIN="${KEYWEAVE_RELAY_ORIGIN:-}"

# Resolved up front, so a missing hasher fails here rather than after a clone, an `npm ci`
# and a build. Both tools print "<hex>  <name>"; only the hex is wanted.
if command -v sha256sum >/dev/null 2>&1; then
  hash256() { sha256sum "$1" | cut -d' ' -f1; }
  HASHER="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  hash256() { shasum -a 256 "$1" | cut -d' ' -f1; }
  HASHER="shasum -a 256"
else
  echo "STOP: neither sha256sum nor shasum is on PATH; cannot hash the artifacts" >&2
  exit 1
fi

# THE VALUE IS READ, NOT MERELY COUNTED. The first version of this asked only whether
# KEYWEAVE_SAME_ORIGIN was non-empty, which means somebody who set it to 0 meaning "no" got a
# same-origin bundle: the exact opposite of what they asked for, silently, and then a hash
# mismatch they would read as tampering. So the accepted values are named, and anything else
# is refused BY NAME rather than guessed at in either direction. `tr` rather than bash 4's
# ${var,,} because the second machine this has to run on is a Mac, where bash is 3.2.
SAME_ORIGIN_RAW="${KEYWEAVE_SAME_ORIGIN:-}"
SAME_ORIGIN=no
if [ -n "${SAME_ORIGIN_RAW}" ]; then
  case "$(printf '%s' "${SAME_ORIGIN_RAW}" | tr '[:upper:]' '[:lower:]')" in
    1 | true | yes) SAME_ORIGIN=yes ;;
    *)
      echo "STOP: KEYWEAVE_SAME_ORIGIN is set to '${SAME_ORIGIN_RAW}', which this script does" >&2
      echo "      not accept. It takes 1, true or yes, in any case, and nothing else." >&2
      echo "      To ask for a relay on its own origin, unset KEYWEAVE_SAME_ORIGIN entirely" >&2
      echo "      and set KEYWEAVE_RELAY_ORIGIN instead. A value like 0 is refused here rather" >&2
      echo "      than read as a yes or dropped as a no, because either reading silently" >&2
      echo "      builds a bundle you did not ask for and the hashes are what tell you." >&2
      exit 2
      ;;
  esac
fi

# THE SAME-ORIGIN CHOICE IS THE CALLER'S, NEVER A DEFAULT. Omitting the variable built a
# DIFFERENT bundle and exited 0. Four of the six hashes still matched the release, because
# four of the files do not carry the relay location, so the run presented as "two files were
# tampered with": the one conclusion this script exists to keep anybody from reaching by
# accident. A trailing slash in the value already fails loudly further down, and this is the
# same refusal one step earlier, for the case where nothing was said at all.
if [ -n "${RELAY_ORIGIN}" ] && [ "${SAME_ORIGIN}" = yes ]; then
  echo "STOP: KEYWEAVE_RELAY_ORIGIN and KEYWEAVE_SAME_ORIGIN are both set and they ask for" >&2
  echo "      different bundles. Unset one." >&2
  exit 2
fi
if [ -z "${RELAY_ORIGIN}" ] && [ "${SAME_ORIGIN}" = no ]; then
  cat >&2 <<'CHOOSE'
STOP: no relay location was chosen, and the artifact hashes depend on it.

  KEYWEAVE_RELAY_ORIGIN=https://relay.example  builds against a relay on its own origin. A
                                               release names the value its hashes were built
                                               with; pass that value to compare against it.
  KEYWEAVE_SAME_ORIGIN=1                       builds a same-origin bundle on purpose. Its
                                               hashes will not match a release that names an
                                               origin, and that is a different build input
                                               rather than a modified source.

Either is accepted on a ref that predates the variable: the build-inputs block then reports
that it was not an input at all.
CHOOSE
  exit 2
fi

echo "keyweave reproduce"
echo "  source ref : ${REF}"
echo "  work dir   : ${OUT}"
echo "  node       : $(node --version)"
echo "  npm        : $(npm --version)"
# Named because two machines corroborating each other may hash with different tools, and
# seeing that in both blocks is evidence the agreement is not an artifact of one of them.
echo "  hasher     : ${HASHER}"
if [ -n "${RELAY_ORIGIN}" ]; then
  echo "  relay      : KEYWEAVE_RELAY_ORIGIN=${RELAY_ORIGIN} (requested)"
else
  echo "  relay      : same-origin build, chosen with KEYWEAVE_SAME_ORIGIN"
fi
echo

# A CLONE, not the working tree. Building in place would let uncommitted edits, stray files
# and a warm node_modules into the artifact, which is exactly the difference this is meant
# to detect. Note -n N, never -N: this box's coreutils are uutils and the legacy numeric
# shorthand combined with -- is rejected there.
git clone --quiet --no-local "${REPO_ROOT}" "${OUT}/src"
git -C "${OUT}/src" checkout --quiet "${REF}"
COMMIT="$(git -C "${OUT}/src" rev-parse HEAD)"
echo "  commit     : ${COMMIT}"

# DOES THIS REF EVEN READ THE VARIABLE? KEYWEAVE_RELAY_ORIGIN arrived in work package 7. For
# any ref before that, the build ignores it completely, and a block that prints it under
# "build inputs" claims something false: it says the value shaped these bytes when it had no
# effect at all. Somebody reproducing an older tag would then chase a hash mismatch that
# never existed, or, worse, believe two different values gave the same hash and conclude the
# variable does not matter.
#
# The test is a property of the CHECKED-OUT TREE, not of this script's own version:
# client/build-config.mjs is the file the feature lives in, and it exists in exactly the refs
# that consume the variable.
if [ -f "${OUT}/src/client/build-config.mjs" ]; then
  RELAY_IS_INPUT=yes
else
  RELAY_IS_INPUT=no
fi
echo "  relay var  : $([ "${RELAY_IS_INPUT}" = yes ] && echo "read by this ref" \
  || echo "NOT read by this ref (predates client/build-config.mjs)")"
echo

cd "${OUT}/src/client"

# `npm ci`, never `npm install`: ci installs exactly the committed lockfile and fails if
# package.json and the lockfile disagree, which is the property being relied on here.
#
# NOT `--silent`, and that is measured rather than argued: with no reachable registry the
# silent form exited 1 having printed nothing beyond this script's own header, naming no
# cause and not even mentioning the debug log npm had just written. A verifier who cannot see
# why the install failed cannot tell a blocked network from a lockfile that disagrees with
# package.json, and one of those two is a finding about the release. `npm run build` below
# keeps its flag: there the failure comes from a child process that writes its own errors.
npm ci --no-audit --no-fund
# Exported explicitly rather than inherited, so the value in the block below is provably the
# value the build saw. An invalid one aborts here, before anything is emitted.
KEYWEAVE_RELAY_ORIGIN="${RELAY_ORIGIN}" npm run build --silent

echo
echo "build inputs:"
echo "  commit                : ${COMMIT}"
echo "  node                  : $(node --version)"
echo "  npm                   : $(npm --version)"
if [ "${RELAY_IS_INPUT}" = yes ]; then
  echo "  KEYWEAVE_RELAY_ORIGIN : ${RELAY_ORIGIN:-(unset: same-origin relay)}"
else
  # Say what happened, not what was asked for. An input line that lists a value the build
  # never read is worse than no line: it is a false attestation in the block people quote.
  echo "  KEYWEAVE_RELAY_ORIGIN : NOT AN INPUT to this ref (no client/build-config.mjs)"
  if [ -n "${RELAY_ORIGIN}" ]; then
    echo "                          ${RELAY_ORIGIN} was set and was IGNORED by this build"
  fi
fi
echo
echo "artifact hashes (sha256):"
cd dist
find . -type f | sort | while read -r f; do
  printf '  %s  %s\n' "$(hash256 "$f")" "${f#./}"
done

echo
echo "Compare these against the published release for this ref, and verify that ref's tag"
echo "signature where the ref carries one. Tags before v0.1.1 are unsigned and stay unsigned,"
echo "so on those git verify-tag exits 1 reporting no signature found: that is the expected"
echo "absence and not a finding. The release hashes are published OUT OF BAND, never by the"
echo "host that serves the app: a server that can serve you a modified bundle can serve you a"
echo "matching hash beside it. docs/REPRODUCIBLE-BUILD.md names the command that checks a tag"
echo "signature, the key to check it against, and which refs carry one."
echo
echo "Quote the WHOLE block. The hashes are a function of the commit AND the build inputs"
echo "above; a release that publishes hashes without KEYWEAVE_RELAY_ORIGIN cannot be"
echo "checked, because a mismatch is then indistinguishable from a different build input."
