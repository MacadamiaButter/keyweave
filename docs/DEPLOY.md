# Deploy runbook (owner-run)

## STOP: this is gated. Status as of 2026-08-09, both conditions now CLOSED

Two conditions before any of this runs against a public host. Both are now met; what remains
is not a gate but a build, named at the bottom of this section.

1. **The build-host condition.** The released artifact must be built in
   a clean environment that does not have to trust the current build host, OR that condition
   must be closed first. A container on the same host does not count: its daemon is root on
   the very machine whose group membership is the hole. Status, in two parts:
   - **Independent corroboration: DONE at a pre-release revision, NOT yet re-run at the
     tag.** The same source was built on an x86_64 Linux host and on an arm64 macOS host,
     sharing no operating system, no CPU architecture and no administrative domain, and all
     six artifact hashes agreed byte for byte. So the artifact is demonstrably not a
     function of one build host. That run predates `v0.1.0`: at the tag only build host A
     has attested, which is what the published release body says, and re-running host B at
     the tag is the remaining work named at the end of this section. See
     `REPRODUCIBLE-BUILD.md`.
   - **The build-host condition itself: CLOSED 2026-08-09, negative control OBSERVED.** The
     build user was removed from the container-daemon groups in `/etc/group` (both member
     lists now empty). Because a login session keeps the group set it started with, the file
     edit alone was NOT closure; the machine has since rebooted, and in a fresh session all
     three checks pass:

     ```
     id -nG | tr ' ' '\n' | grep -E '^(docker|lxd)$'  -> no match
     docker info                                       -> permission denied on the socket
     sudo -n true                                      -> fails, so sudo still needs the key
     ```

     The second line is the closure evidence: not that the group is gone from a file, but that
     the capability is gone from a live session. Root on the build host is now attended.
     `sudo` membership is retained deliberately, because it is hardware-key gated.
     Re-run those three lines before the release build if any doubt exists; they are cheap and
     they are the only statement of this that cannot go stale by being written down.
2. **The browser smoke test (R15). CLOSED 2026-08-09.** A full three-turn ceremony ran on two
   physical devices (iPhone Safari and Mac Firefox) over HTTPS: safety words compared aloud
   and matching, ciphertext both ways, reload persistence, and the idle lock verified to
   RELEASE the camera at five minutes. Beforehand, headlessly, the optical hop was completed
   browser to browser with no human at all.

So no gate remains. What remains is building the release at the ACTUAL tag rather than at
whatever was current when this paragraph was written, and re-running WP8's cross-machine hash
comparison at that tag. WP8 has changed character: while the build-host condition was open it
was the only defensible answer to "can you trust this build host", and now it is corroboration
on top of a host with no unattended root path. Everything below was staged ahead of this moment
so the work is reading and pasting rather than designing under pressure.

**Why every paste block asserts before it acts.** On 2026-08-05 a long nginx header line
wrapped when pasted into a terminal, `nginx -t` accepted the multi-line quoted string, and
the breakage only surfaced as `curl: (8) Header without colon` on the live site. The check
that would have caught it existed and was handed over as a separate step, so the reload
happened anyway. Hence: no source line over about 100 characters, long values built from
short pieces, and the verification lives inside the same block as the action.

## Topology: two trust domains, deliberately

    app bundle   keyweave.localfirstlab.org        the EXISTING VPS 178.104.41.74
    relay        relay.keyweave.localfirstlab.org  a NEW, separate box (same provider, other region)

They must not share a host. Finding 8 of the design review: one root over both makes
"compromise the relay gives you ciphertext only" false, because the same root serves the
JavaScript that holds the keys. Co-locating is acceptable only for a private preview, and
then the threat model has to say so out loud.

**The separation is of hosts and roots, not of providers.** Both boxes are rented from the same
company, in different regions, so a party who can compel or compromise that provider reaches
both. That is a weaker claim than "two trust domains" sounds, and it is stated here rather than
left for a reader to work out. What the split does buy is real: a root on either machine does
not become a root on the other, which is the failure finding 8 names. Moving the relay to an
unrelated provider would close the rest and is worth doing before this is relied on.

**Which way round, and why, because an earlier version of this table had it backwards.** The
RELAY is the LOW-value target: it holds opaque ciphertext, it is assumed hostile by the design,
and it runs sealed (`DynamicUser`, `ProtectSystem=strict`, `IPAddressDeny=any`). So it belongs
on the cheap, disposable, newly built box. The APP host is R1's target, because it serves the
JavaScript that holds the keys, so it belongs on the machine with the drilled publish flow and
the rsync dry-run discipline. Installing the relay onto 178.104.41.74 would produce exactly the
co-location break this section forbids.

## The app host: DECIDED 2026-08-09 by the owner. Not GitHub Pages, and here is why

**Decision: option 1 below. The app is served by nginx on the existing VPS 178.104.41.74, which
can send response headers, so step 5b runs exactly as written and nothing in this policy is
lost.** The reasoning is kept rather than deleted, because the rejected option was the earlier
recommendation and the next person will otherwise re-propose it.

Two things killed Pages. It cannot send any response header, so part of the policy simply does
not exist there (detailed below). And serving the app from GitHub while the verification hashes
live in a GitHub release collapses them into ONE root, which is precisely what
`REPRODUCIBLE-BUILD.md` forbids: the party serving you the bytes must not also be the party
attesting to them. From v0.1.1 the release tag is signed with a release-signing key that is
separate from any personal key and is published on `localfirstlab.org`, so what anchors the
hashes is a key rather than a GitHub account: taking the account no longer lets someone rewrite
what the tag attests to. `REPRODUCIBLE-BUILD.md` gives the fingerprint, where to fetch the key,
and the verify command. That strengthens the release side and it does not revive Pages, because
the argument above never rested on the anchor. It rests on one party serving the bytes while
hosting the attestation, which stays true however well the tag is signed.

A CDN was considered and rejected separately: edge compute is the most capable possible party
for R1's targeted per-user code swap, and features like Rocket Loader or Auto Minify REWRITE
the served bytes, which would silently break the published-hash check that R1's mitigation
depends on.

An earlier draft of this file recommended **GitHub Pages** and, four sections further down,
handed the operator an nginx server block plus a `curl -sI` assertion on the response header
it produces. Those two instructions cannot both be followed. **GitHub Pages cannot send a
custom response header at all**: there is no `_headers` file, no server block, and no
configuration surface for one. So step 5b is not "a step someone forgot to run" on Pages, it
is a step that cannot be run, and a runbook whose gate is unreachable is a runbook whose gate
gets dropped.

Pages is otherwise a good fit for the reasons that draft gave: a different operator from the
VPS, already in the integrity story as where the signed tag and its hashes live (checking that
signature is the procedure in `REPRODUCIBLE-BUILD.md`), and no application layer to compromise.
What it costs is exact and worth stating rather than papering over.

**What is lost when the CSP exists only as the `<meta>` tag in the page:**

- `frame-ancestors` is IGNORED in a meta tag by specification. With no response header,
  **there is no clickjacking protection**: any site may put the app in a frame. For an app
  whose first screen is a pairing ceremony with a camera on it, that is the directive in this
  policy worth caring about most.
- `form-action` is IGNORED in a meta tag too, by the same rule.
- The rest of the policy DOES take effect from the meta tag: `default-src 'none'`,
  `script-src 'self' 'wasm-unsafe-eval'`, `worker-src`, `connect-src` and the others. So the
  relay-origin tightening this build performs is still enforced on a header-less host. This
  is a partial loss, not a total one.
- The non-CSP headers in the same block are lost with it: `Referrer-Policy`,
  `X-Content-Type-Options`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
  `Permissions-Policy`. `Referrer-Policy` and `X-Content-Type-Options` are the two whose
  absence is worth noting. `Permissions-Policy` is NOT needed to allow the camera, because
  the default for `camera` is already the document's own origin; it is there to deny the
  microphone and geolocation, so losing it does not break the scan step.

**The two options, and the choice belongs to whoever owns the domain:**

1. **Serve the app from something that can send headers.** Either a static host that reads a
   `_headers` file, or a plain nginx vhost on a machine that is NOT the relay host (the
   co-location rule in the topology above still applies, and putting the app on the relay's
   nginx would trade a clickjacking gap for the total break R2 exists to prevent). Step 5b
   then runs exactly as written.
2. **Accept the delta and stay on Pages.** Ship the meta tag only, and record "no
   `frame-ancestors` and no `form-action`, therefore no clickjacking protection" as a named
   residual next to R2 in `NAMED-RESIDUALS.md`, where it is already written down. Do not
   paste the nginx block anywhere and do not claim the header exists.

**Option 1 was chosen on 2026-08-09.** Picking a hosting provider is not an agent's call, and
the choice has a security consequence, so it was made by the owner deliberately rather than
inherited from a sentence in a runbook. What that means concretely for the steps below: step 5b
is REQUIRED, not optional, because the chosen host can send the header; the residual about a
meta-only policy does NOT apply to this deployment; and the two DNS records to create are
`keyweave` pointing at 178.104.41.74 and `relay.keyweave` pointing at the relay box. Enforced
HTTPS on both.

## Step 1: relay config on the VPS

`trust_forwarded_for = 1` is not optional and is not a preference. The relay binds loopback,
so without it every request is attributed to 127.0.0.1: the per-source failure budget cannot
tell clients apart, and any AUTHFAIL line handed to fail2ban bans the proxy itself, which is
a total outage. It is only safe **with** the nginx overwrite in step 2. The two are one
change; do not do either alone.

```bash
sudo install -d -m 0755 /opt/keyweave-relay /etc/keyweave-relay
sudo install -m 0644 keyweave_relay.py /opt/keyweave-relay/keyweave_relay.py
sudo tee /etc/keyweave-relay/relay.conf >/dev/null <<'CONF'
bind_host = 127.0.0.1
bind_port = 8151
data_dir = /var/lib/keyweave-relay
trust_forwarded_for = 1
allowed_origins = https://keyweave.localfirstlab.org
CONF
sudo grep -q '^trust_forwarded_for = 1$' /etc/keyweave-relay/relay.conf \
  && sudo grep -q '^allowed_origins = https://' /etc/keyweave-relay/relay.conf \
  && echo "OK: config written with the coherent XFF setting" \
  || { echo "STOP: relay.conf is not what step 1 intended"; exit 1; }
```

`allowed_origins` must be the app origin exactly, with scheme and no trailing slash. It is
the only thing standing between the relay and any website a user happens to have open.

With split origins the browser PREFLIGHTS the write path: `PUT` carries `Authorization` and
`Content-Type: application/octet-stream`, neither of which is CORS-safelisted, so an
`OPTIONS` goes first and the `PUT` is never sent unless that answer names both headers. The
relay already does this (`_route_options`, `relay/keyweave_relay.py:1416`, allowing
`GET, PUT, POST, DELETE, OPTIONS` and `Authorization, Content-Type`, reflecting the exact
allowlisted origin and never `*`), and
`relay/tests/test_relay_fixes.py::CorsTests` covers that exact request shape. Nothing to
configure beyond `allowed_origins`; a value that does not match the app origin byte for byte
shows up in a browser as a CORS error on the send, not as a configuration message.

## Step 2: nginx

The rate-limit zones live at `http{}` scope and the location snippet fails closed without
them, which is intended.

The gate and the reload are one block on purpose, so a config that fails the gate is never
the config that gets reloaded.

```bash
( set -eu
SNIP=/etc/nginx/snippets/keyweave-relay.conf
sudo tee /etc/nginx/conf.d/keyweave-ratelimit.conf >/dev/null <<'CONF'
limit_req_zone  $binary_remote_addr zone=keyweave_req:1m  rate=10r/s;
limit_conn_zone $binary_remote_addr zone=keyweave_conn:1m;
limit_req_status 429;
limit_conn_status 429;
CONF
sudo install -m 0644 nginx-location.conf "$SNIP"
sed 's/#.*//' "$SNIP" > /tmp/kw-active.conf
N=$(grep -oF 'proxy_set_header X-Forwarded-For $remote_addr;' /tmp/kw-active.conf | wc -l)
A=$(grep -oF 'proxy_add_x_forwarded_for' /tmp/kw-active.conf | wc -l)
rm -f /tmp/kw-active.conf
[ "$N" -eq 1 ] || { echo "STOP: $N active XFF overwrite directives, must be 1"; exit 1; }
[ "$A" -eq 0 ] \
  || { echo "STOP: the APPENDING XFF form is ACTIVE ($A); a client could spoof"; exit 1; }
echo "OK: exactly one active XFF overwrite directive, zero appending forms"
sudo nginx -t && sudo systemctl reload nginx && echo "OK: nginx reloaded"
)
```

`$remote_addr` OVERWRITES; `$proxy_add_x_forwarded_for` appends a client-supplied value and
would let a remote client choose the address the relay trusts. The count catches a paste wrap
(it drops to 0) and a duplicate (it rises to 2), and the second count catches the appending
form being substituted or added alongside.

`sed 's/#.*//'` first is load-bearing, not tidiness. `nginx-location.conf` explains this exact
choice in its own header, and therefore QUOTES both forms in comments: a naive
`grep -c` over the raw file reads **3** and **1** on the pristine, correct file, so the
un-stripped gate STOPped on every correct install and told the operator the shipped config was
spoofable. A gate that fires on correct state teaches operators to delete gates.
`relay/tests/test_relay_fixes.py::DeployClientAddrCoherenceTests` asserts the same
comment-stripped counts against the committed file, so the repo cannot drift out from under
this step.

`limit_req_status` and `limit_conn_status` are set because nginx's default answer to a
throttled request is 503, and 503 is the one class of status this client cannot read
charitably. The browser counts every status at or above 500 as a pull that may have destroyed
a message (`client/src/messaging.ts`, the `interrupted` count), and it is right to: the relay's
own catch-all handler wraps the route INCLUDING the delete, so a 5xx the relay itself chose
could have been decided after the blob was already removed. A 503 from the front proxy never
reached the relay at all, nothing was deleted, and the person is nonetheless told to ask their
contact to send again a message that is still sitting in the mailbox. 429 is the status the
client already maps to `rate-limited`, whose copy says to wait a little and ask again, which is
exactly what did happen. Setting it makes the front wall speak the language the client already
reads correctly, rather than borrowing the one status that means "something may be gone".

## Step 3: systemd

`keyweave-relay.service` ships in the repo: `DynamicUser`, `ProtectSystem=strict`,
`IPAddressDeny=any` with only localhost allowed, an empty capability bounding set, and a
pinned journald rate limit so an unauthenticated flood cannot drown the AUTHFAIL lines
fail2ban reads.

```bash
sudo install -m 0644 keyweave-relay.service \
  /etc/systemd/system/keyweave-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now keyweave-relay.service
systemctl is-active keyweave-relay.service
```

## Step 4: fail2ban

The log format was confirmed against a live relay on 2026-08-08:

    AUTHFAIL client=<ip> method=GET role=pull reason=no-auth

```bash
sudo tee /etc/fail2ban/filter.d/keyweave-relay.conf >/dev/null <<'CONF'
[Definition]
failregex = ^.*AUTHFAIL client=<HOST> method=\S+ role=\S+ reason=\S+$
journalmatch = _SYSTEMD_UNIT=keyweave-relay.service
CONF
sudo fail2ban-regex systemd-journal /etc/fail2ban/filter.d/keyweave-relay.conf \
  --journalmatch "_SYSTEMD_UNIT=keyweave-relay.service" | tail -n 20
```

Read the matched count before enabling the jail. A filter that matches nothing is the
failure mode that looks exactly like a quiet service.

## Step 5: the app bundle

The relay origin is a BUILD INPUT. One environment variable, `KEYWEAVE_RELAY_ORIGIN`, feeds
all three places it has to appear: the `<meta>` CSP in the built page, the response header
you paste in step 5b if the host can send one, and the base URL `RelayClient` is constructed
with. Unset means a same-origin relay, which is the default and is NOT the topology this
document recommends.

An invalid value aborts the build rather than shipping a policy with something extra in it,
so a typo is a failed build and not a silent hole.

From the repository root:

```bash
node client/scripts/print-csp.mjs https://relay.keyweave.localfirstlab.org
```

Read that output before building. It prints the exact policy and the exact nginx block for
this deployment; the block in `DEPLOY-CSP.md` is the same generated text and is asserted
against the generator by the test suite.

Then build the release artifact, which records the value it used:

```bash
export KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org
# Assert before acting, because the gate below is VACUOUS on an empty value:
# `grep -cF ""` matches every line and prints the file's line count, which
# reads exactly like "found it" against an artifact built for someone else.
# Measured on the real artifact: unset variable, gate printed 440, file is
# 440 lines. A mistyped variable NAME on the export line does this silently.
case "$KEYWEAVE_RELAY_ORIGIN" in
  https://*) ;;
  *) echo "STOP: KEYWEAVE_RELAY_ORIGIN is empty or is not an https origin"
     exit 1 ;;
esac
OUT="$(mktemp -d)"
scripts/reproduce.sh <tag> "$OUT"
grep -cF "$KEYWEAVE_RELAY_ORIGIN" "$OUT/src/client/dist/index.html"
```

That count must be at least **1**. Zero means the build ran without the variable and the
bundle will call the app's own origin, where there is no relay: the conversation screen
would report every send as a network failure.

The pattern is `"$KEYWEAVE_RELAY_ORIGIN"`, derived from the value being deployed, and not a
hostname typed into this document. A hardcoded `relay.keyweave` printed **1** for a build
made with somebody else's origin, which is the one answer this gate must never give: it
checks that SOME origin was baked in, when the question is whether THIS one was. `-F` is
load-bearing too, because the value contains `/` and `.` and, on a host whose `grep` is
ugrep, a `$` anywhere in a pattern can be read as an anchor.

**The artifact hash depends on `KEYWEAVE_RELAY_ORIGIN`.** A release attestation that does
not state the value is not verifiable, because a reproducer using a different one gets
different bytes and cannot tell that from tampering. Put the value in the release body next
to the hashes: see `REPRODUCIBLE-BUILD.md`.

**Upload two more paths next to the bundle: `NOTICE` and `LICENSES/`.** The built bundle
carries MIT and Apache-2.0 code, and both licenses require their text to travel with it. The
text is NOT inside `client/dist` and that is on purpose:
`client/test/build-no-external-origin.test.ts` permits no http(s) origin in a default build
(residual R13) and license texts contain URLs, so emitting them into `dist/` fails that gate
with thirteen origins. Serving them beside the bundle satisfies the licenses without putting
an exemption into the origin wall. From the repository root, with `$APPROOT` the directory
the app is served from:

```bash
install -m 0644 NOTICE "$APPROOT/NOTICE"
install -d -m 0755 "$APPROOT/LICENSES"
install -m 0644 LICENSES/*.txt "$APPROOT/LICENSES/"
# Assert, because a silently missing legal file looks exactly like a working deployment:
test -s "$APPROOT/NOTICE" && ls -1 "$APPROOT/LICENSES" | wc -l
```

That count must equal the number of files in `LICENSES/` in the tree you built from. These
two paths are NOT covered by the artifact hashes, which cover `client/dist` only.

Publish the hashes FIRST, and only then upload. Publishing the hash after the bytes are live
inverts the point of it. From `v0.1.1` the hashes go in the ANNOTATED TAG MESSAGE, because that
is what the signature covers; the GitHub release body carries the same block as a readable copy
and stays editable by whoever holds the account. `REPRODUCIBLE-BUILD.md` carries the key
fingerprint, the address to fetch the key from, and the `git verify-tag` invocation. Tags before
`v0.1.1` are unsigned and stay that way.

## Step 5b: the app host's response headers, IF the host can send them

The vhost this step edits does not exist until something creates it: `DEPLOY-APP.md` is the
app-host runbook that creates the docroot, this vhost, the certificate and the upload, and
it runs the check below inside the same paste as the reload.

**Conditional on option 1 above.** This step needs a host with a real nginx server block. On
GitHub Pages, or any other host with no header configuration, SKIP IT: there is nothing to
paste it into. Skipping it is only acceptable if the delta was recorded as a decision (see
"The app host is an OWNER DECISION"), because what is skipped with it is `frame-ancestors`,
and therefore clickjacking protection. A host that reads a `_headers` file needs the same
policy string in that file's syntax rather than nginx's; the policy itself is unchanged, and
`print-csp.mjs` prints it on its own line above the nginx block.

Paste the nginx block `print-csp.mjs` printed in step 5 into the server block for the APP
origin, not the relay. Then check it landed as separate short lines BEFORE reloading, in the
same paste as the reload, because `nginx -t` accepts a multi-line quoted string and the
breakage only appears at the HTTP layer:

```bash
CONF=/etc/nginx/sites-available/keyweave-app     # your app vhost
# -F on every one of these: the third pattern contains a literal $csp_a, and
# some greps (ugrep, for one) read a mid-pattern $ as an anchor and print 0
# for a correct file. A gate that fails on a correct deploy gets deleted.
a=$(grep -cF 'wasm-unsafe-eval' "$CONF")
b=$(grep -cF "frame-ancestors 'none'" "$CONF")
c=$(grep -cF 'Content-Security-Policy "$csp_a' "$CONF")
echo "csp markers: $a $b $c (each must be 1)"
if [ "$a$b$c" != "111" ]; then
  echo "STOP: the CSP block wrapped, is missing, or was pasted twice"
else
  sudo nginx -t && sudo systemctl reload nginx && echo "OK: nginx reloaded"
fi
```

The meta tag in the page is not a substitute: `frame-ancestors` and `form-action` are
ignored in a meta tag by specification and only take effect as a real response header.

## Step 6: verify from outside

From a machine that is neither the build host nor either server:

```bash
curl -sI https://keyweave.localfirstlab.org/ \
  | grep -ci "^content-security-policy:.*wasm-unsafe-eval"
```

Must print **1** if you took option 1 and the host sends the header. Without
`wasm-unsafe-eval` the QR decoder never starts, and it fails silently: no error reaches the
page, so it presents as a camera that does not work.

Under option 2 this prints **0** and that is the expected answer, not a failure: there is no
response header to find. The policy is then only in the page, so check it there instead, and
6b below does exactly that as part of a bigger question. Say which option you are on before
reading the number, or a correct deploy looks broken and the next move is to change something
that was right.

### Step 6b: the header and the bundle must name the SAME relay

One value generated both of them at BUILD time. Nothing has checked them at DEPLOY time, and
deploy time is where they come apart: the header is pasted by a person, from a `print-csp.mjs`
run that may have been given a different origin than the bundle beside it was built with.
Both halves are then internally consistent and the pair is wrong. The symptom is a browser
that refuses the send with a CSP violation, or a client that quietly talks to the wrong
relay, depending on which of the two is stale.

So compare them as they actually exist, on the wire, from outside:

```bash
APP=https://keyweave.localfirstlab.org
WANT=https://relay.keyweave.localfirstlab.org   # what step 5 built with
# One normaliser for both, so a difference is a real difference.
norm() { tr -d '\r\n' | tr -s ' ' | sed 's/^ *//; s/ *$//'; }
# Compare the WHOLE policy, not one directive. Checking only connect-src
# passes a header that also carries worker-src 'none', which blocks both
# ES-module workers, kills the QR decoder, and surfaces no error anywhere.
hdr=$(curl -sI "$APP/" | grep -i '^content-security-policy:' \
  | sed 's/^[^:]*: *//' | norm)
doc=$(curl -s "$APP/" | tr '<' '\n' \
  | sed -n 's/.*Content-Security-Policy" content="\([^"]*\)".*/\1/p' | norm)
echo "header: [$hdr]"
echo "bundle: [$doc]"
# EXACT, never a substring. A substring test accepts a suffix lookalike
# like ...localfirstlab.org.evil.net: the same hole the dist scan already
# had to close, reappearing at deploy time.
if [ -n "$WANT" ]; then want_cs="connect-src 'self' $WANT"
else want_cs="connect-src 'self'"; fi
got_cs=$(printf '%s' "$doc" | tr ';' '\n' | grep -i 'connect-src' | norm)
if [ "$got_cs" != "$want_cs" ]; then
  echo "STOP: the served bundle names a different relay"; exit 1
fi
echo "OK: the served bundle was built for $WANT"
if [ -z "$hdr" ]; then
  echo "NOTE: no CSP response header at all."
  echo "Correct ONLY under option 2 (header-less host, delta accepted)."
elif [ "$hdr" = "$doc" ]; then
  echo "OK: header and bundle name the same relay origin"
else
  echo "STOP: header and bundle disagree; one of them is stale"; exit 1
fi
```

`$WANT` is the value step 5 exported, retyped here on purpose so that a mismatch between what
you MEANT to deploy and what is actually being served has somewhere to show up. The bundle
check runs first and exits: if the artifact is the wrong one, whether the header agrees with
it is not the interesting question.

Then fetch each artifact, hash it, and compare with the hashes in the signed tag message,
having first checked that tag's signature by the procedure in `REPRODUCIBLE-BUILD.md`.
Comparing against a release body nobody verified only proves the deploy matches whatever the
release says today.
This is the step that checks the deploy rather than the build, and it is the one most easily
skipped.

## What is deliberately not here

No CI runner, no auto-deploy, no push-to-publish. Nothing in this project may publish
itself. The agent lane stages; a person runs it.
