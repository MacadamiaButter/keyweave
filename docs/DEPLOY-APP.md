# Deploy the app host (owner-run)

`DEPLOY.md` steps 1 to 4 install the relay. Its step 5 builds the bundle and its step 5b
pastes a header block into `/etc/nginx/sites-available/keyweave-app`. Nothing creates that
file. Nothing creates the docroot it points at, nothing obtains a certificate for the name,
and nothing uploads the built bundle. This document is that missing half: from an empty
server to a served, verified app origin.

Read `DEPLOY.md` step 5 first and do it first. This runbook starts from a `dist/` that
`scripts/reproduce.sh` has already produced at a tag whose hashes are already published in
the signed tag message. Publishing the hashes after the bytes are live inverts the point of
publishing them.

**Every server-touching block here is pasted by the owner.** The agent lane stages the
build and prepares the dry run; it does not run the deploy. Two steps are marked
AGENT-RUNNABLE and neither of them touches the server.

## The decisions this runbook is built on

These were decided before it was written. They are recorded as decisions rather than
options, so that nobody re-opens them at 2am in the middle of a deploy.

- **App origin: `https://keyweave.localfirstlab.org`**, served by nginx on the existing VPS
  `178.104.41.74`, which already serves `localfirstlab.org`. That host can send response
  headers, which is option 1 in `DEPLOY.md` and the reason step 5b is required rather than
  optional.
- **Relay origin: `https://relay.keyweave.localfirstlab.org`**, on a separate box with a
  separate root. That is residual R2 and the relay half has its own runbook. Nothing in this
  document is pasted onto the relay host.
- **No AAAA record for either name in v0.** `localfirstlab.org` itself has an A record only,
  so v4 only matches what the estate already serves; the vhost below does listen on v6 so
  that adding an AAAA later is a DNS change and not a config change. Revisit deliberately,
  not by accident.
- **ACME email: nothing new to decide here.** This host already runs certbot with a
  registered account, so issuance for a new name reuses it and asks for no address. The
  relay host's runbook is where an ACME email is actually chosen; where it refuses its
  placeholder, `hello@localfirstlab.org` is the recommended default for the owner to
  confirm, because that address is already published as the release-signing key's user id
  and so introduces no new identity anywhere.

## Three layers, and which one each step touches

A request to this host passes three independent controls, and a failure looks different at
each. Every step below names the layer it changes, so that a symptom can be traced rather
than guessed at.

| layer | what it is | how a failure presents |
|---|---|---|
| provider firewall | allows TCP 22, 80, 443 and ICMP, on v4 and v6 | a HANG, never a refusal |
| nginx | the vhost, TLS, the headers, the docroot | 404, wrong certificate, missing header |
| fail2ban | active here, watching auth and service logs | your own address stops answering |

**Two ways a hang lies to you, both measured on this estate.** A port with no rule in the
provider firewall DROPS, so the client waits instead of being refused. And a port that IS
allowed but has no process listening behind it ALSO hangs, for about nine seconds, rather
than refusing. So a hang on 80 or 443 is not evidence about the firewall in either
direction. For this deploy the honest reading is simpler than either: 80 and 443 are
already allowed and already have nginx listening on them for `localfirstlab.org`, so this
runbook needs **no change in the provider console at all**, and a hang on those ports means
your request is not arriving at this host, which is a DNS answer to check before anything
else.

**fail2ban is not reconfigured here.** If you ever do change it, paste the change into the
SSH session you already have open, never into a provider web console: a jail installed with
an empty `ignoreip` can lock out the address you are working from, and the session you
already hold is the thing that gets you back in.

**A failed `nginx -t` cannot take the live site down.** nginx keeps running the
configuration it already loaded, so every gate below is placed before its reload rather
than after it, and a STOP means the running config is still the one that was working.

## Before you start

- `DEPLOY.md` step 5 is done: the artifact is built at the tag, the step 5 grep printed at
  least 1, and the hashes are in the signed tag message.
- You have an SSH session open to the app host as root, and you keep it open.
- You can edit DNS for `localfirstlab.org` (Porkbun).
- The relay is already deployed and answering, or you accept that the app will load and
  fail to send until it is. The app is useful to verify either way.

## Step 1: the DNS A record

**Job:** make the name resolve to the app host, so ACME and browsers reach nginx.
**Layer:** none of the three. This is naming, and it happens before the host changes.

In Porkbun, on `localfirstlab.org`, add one record:

    type A, host keyweave, answer 178.104.41.74

No AAAA. Then, from your own machine, not from the server:

```bash
dig +short keyweave.localfirstlab.org A
dig +short keyweave.localfirstlab.org AAAA
```

The first must print `178.104.41.74` and nothing else. The second must print nothing at
all: that empty answer is the decision above, not an unfinished step. Wait for both before
going on, because every later step reads DNS and a stale answer makes them fail in ways
that look like something else.

The name is public from this moment, to anyone who queries it and to the passive DNS
collectors that watch. It is not yet permanent; step 4 is where that changes.

## Step 2: the docroot and a separate ACME root

**Job:** create the two directories, kept apart on purpose.
**Layer:** nginx, and the filesystem it reads.

```bash
sudo install -d -m 0755 /var/www/keyweave.localfirstlab.org
sudo install -d -m 0755 /var/www/keyweave-acme
sudo install -d -m 0755 /var/www/keyweave-acme/.well-known/acme-challenge
ls -ld /var/www/keyweave.localfirstlab.org /var/www/keyweave-acme
```

The challenge root is deliberately NOT inside the docroot. The upload in step 7 runs
`rsync --delete`, which makes the docroot exactly the built `dist/` and would therefore
remove a challenge file that a renewal had just written. Keeping them apart means the
upload can be exact and the renewal can be unattended.

## Step 3: the port 80 vhost, so ACME has somewhere to answer

**Job:** serve the ACME challenge path for this name, and nothing else yet.
**Layer:** nginx.

```bash
( set -eu
CONF=/etc/nginx/sites-available/keyweave-app
grep -rq 'sites-enabled' /etc/nginx/nginx.conf \
  || { echo "STOP: nginx.conf does not include sites-enabled"; exit 1; }
sudo tee "$CONF" >/dev/null <<'VHOST'
# Keyweave app host, stage A: port 80 only, for the ACME challenge.
# docs/DEPLOY-APP.md step 3. Step 5 replaces this whole file with stage B.
server {
    listen 80;
    listen [::]:80;
    server_name keyweave.localfirstlab.org;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/keyweave-acme;
        default_type "text/plain";
    }

    # Inside location /, never at server level. A server-level return runs
    # in the rewrite phase, before a location is chosen, so it would answer
    # the ACME request too and the certificate would never issue.
    location / {
        return 404;
    }
}
VHOST
sudo ln -sfn "$CONF" /etc/nginx/sites-enabled/keyweave-app
sudo nginx -t && sudo systemctl reload nginx && echo "OK: nginx reloaded"
)
```

Now prove the whole path end to end before spending an ACME attempt on it. On the server:

```bash
printf 'keyweave-acme-probe\n' \
  | sudo tee /var/www/keyweave-acme/.well-known/acme-challenge/probe >/dev/null
```

**From your own machine, not from the server**, because a request made on the box never
crosses the provider firewall and so proves nothing about it:

```bash
curl -sS --max-time 15 \
  http://keyweave.localfirstlab.org/.well-known/acme-challenge/probe
```

That must print `keyweave-acme-probe`. A hang means the request is not arriving: check the
DNS answer from step 1 first. A 404 means it arrived and matched a different server block,
so the reload did not take or `server_name` is misspelled. Then remove the probe:

```bash
sudo rm -f /var/www/keyweave-acme/.well-known/acme-challenge/probe
```

## Step 4: the certificate. The dry run first, then the point of no return

**Job:** obtain a certificate for the new name.
**Layer:** nginx reads it, and the public Certificate Transparency logs record it.

```bash
sudo certbot certonly --webroot -w /var/www/keyweave-acme \
  -d keyweave.localfirstlab.org --dry-run
```

The dry run uses the staging authority. It exercises DNS, the provider firewall, the port
80 vhost and the webroot for real, consumes no production rate limit, and does not put the
name in the production CT logs. It is the only honest external oracle for this step: the
probe in step 3 tested the same path with your own client, and this tests it with theirs.

**If certbot asks for an email address, STOP.** This host has a registered account and
should not be asked. Being asked means certbot is registering a NEW account, which is a
decision to make deliberately rather than at a prompt. See the ACME line in the decisions
above.

Then, and this is the step that cannot be undone:

```bash
sudo certbot certonly --webroot -w /var/www/keyweave-acme \
  -d keyweave.localfirstlab.org --deploy-hook "systemctl reload nginx"
sudo test -s /etc/letsencrypt/live/keyweave.localfirstlab.org/fullchain.pem \
  && echo "OK: certificate present"
```

**Issuance writes `keyweave.localfirstlab.org` into the public Certificate Transparency
logs, permanently and searchably.** Deleting the record, the vhost and the certificate
afterwards does not remove it. Everything before this point is reversible; this is not. The
deploy hook is stored in the renewal configuration, so renewals reload nginx by themselves;
if this host already has a global deploy hook, both run and two reloads are harmless.

## Step 5: the real vhost, with the headers the policy depends on

**Job:** serve the docroot over TLS with the generated CSP and the rest of the header set.
**Layer:** nginx, and through it the browser's own enforcement.

Two things about this block are easy to get wrong and both fail quietly.

**nginx `add_header` does not accumulate.** A block that defines any `add_header` of its
own loses every one it would otherwise have inherited. That is why
`Strict-Transport-Security` is written out here even though the apex sends it: this server
block would otherwise drop it. It is also why the cache settings below use `expires` rather
than `add_header`, since an `add_header` inside `location = /index.html` would strip the
CSP from the one response that most needs it.

**The CSP block is generated, not typed.** It is the output of
`node client/scripts/print-csp.mjs https://relay.keyweave.localfirstlab.org`, split into
short pieces by that generator precisely so no line can wrap when pasted. If your relay
origin is different, run the generator and paste what it prints. Do not edit the pieces by
hand: the chunk boundaries move with the length of the origin.

```bash
( set -eu
CONF=/etc/nginx/sites-available/keyweave-app
sudo tee "$CONF" >/dev/null <<'VHOST'
# Keyweave app host, stage B. docs/DEPLOY-APP.md step 5.
# The CSP block is generated by client/scripts/print-csp.mjs. Do not retype it.
server {
    listen 80;
    listen [::]:80;
    server_name keyweave.localfirstlab.org;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/keyweave-acme;
        default_type "text/plain";
    }

    location / {
        return 301 https://keyweave.localfirstlab.org$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name keyweave.localfirstlab.org;

    ssl_certificate /etc/letsencrypt/live/keyweave.localfirstlab.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/keyweave.localfirstlab.org/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    root /var/www/keyweave.localfirstlab.org;
    index index.html;

    # Repeated here on purpose: add_header does not inherit into a block that
    # has add_header directives of its own, and the apex sends this value.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Generated for KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org
    set $csp_a "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self';";
    set $csp_b " connect-src 'self' https://relay.keyweave.localfirstlab.org; img-src";
    set $csp_c " 'self'; media-src 'self' mediastream:; style-src 'self'; font-src 'none';";
    set $csp_d " base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
    add_header Content-Security-Policy "$csp_a$csp_b$csp_c$csp_d" always;

    add_header Referrer-Policy "no-referrer" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Permissions-Policy "camera=(self), microphone=(), geolocation=()" always;

    # expires, never add_header: an add_header here would replace the whole
    # set above for this response, and this is the response carrying the CSP.
    location = /index.html {
        expires -1;
    }

    # An empty types block plus default_type, so the content type does not
    # depend on what this nginx build ships in mime.types. Step 8 reads what
    # actually arrived rather than trusting either.
    location ~ \.wasm$ {
        types { }
        default_type application/wasm;
        expires 1y;
    }

    location /assets/ {
        expires 1y;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
VHOST
a=$(grep -cF 'wasm-unsafe-eval' "$CONF" || true)
b=$(grep -cF "frame-ancestors 'none'" "$CONF" || true)
c=$(grep -cF 'Content-Security-Policy "$csp_a' "$CONF" || true)
d=$(grep -cE '^[[:space:]]*set \$csp_[a-d] ".*";$' "$CONF" || true)
e=$(grep -cF 'Strict-Transport-Security' "$CONF" || true)
echo "markers: a=$a b=$b c=$c d=$d e=$e   (want 1 1 1 4 1)"
if [ "$a" != 1 ] || [ "$b" != 1 ] || [ "$c" != 1 ] || [ "$d" != 4 ] || [ "$e" != 1 ]; then
  echo "STOP: the header block wrapped, is missing, or was pasted twice"
  exit 1
fi
sudo nginx -t && sudo systemctl reload nginx && echo "OK: nginx reloaded"
)
```

`d` is the one that catches the 2026-08-05 failure on this very host. A `set` line that
wrapped in your terminal loses the `set $csp_x "` prefix on its tail, so the count falls
below 4, and it falls below 4 BEFORE the reload. `nginx -t` will not catch it: a quoted
string may legally span lines, and the breakage appears only at the HTTP layer as
`curl: (8) Header without colon`. The `-F` on the other three is load-bearing for the same
reason `DEPLOY.md` gives: pattern `c` contains a literal `$csp_a`, and some greps read a
mid-pattern `$` as an anchor and print 0 for a correct file.

The docroot is still empty at this point, so the site answers 404. That is the expected
state until step 7, not a fault.

## Step 6: build the bundle at the tag (AGENT-RUNNABLE)

**Job:** produce the exact bytes to serve, from the tag, with the relay origin baked in.
**Layer:** none. This happens on the build machine and touches no server.

This is `DEPLOY.md` step 5, repeated here only because step 7 needs the directory it
produces. If you have already run it, reuse that output directory rather than rebuilding.

```bash
export KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org
case "$KEYWEAVE_RELAY_ORIGIN" in
  https://*) ;;
  *) echo "STOP: KEYWEAVE_RELAY_ORIGIN is empty or is not an https origin"
     exit 1 ;;
esac
OUT="$(mktemp -d)"
scripts/reproduce.sh <tag> "$OUT"
DIST="$OUT/src/client/dist"
grep -cF "$KEYWEAVE_RELAY_ORIGIN" "$DIST/index.html"
ls -la "$DIST"
```

The grep must print at least 1, and `DEPLOY.md` step 5 explains why the pattern is the
variable and not a hostname typed into a document. Keep `$DIST` for the next step.

Whatever is in that directory is what gets served, plus exactly two paths that ride BESIDE
the bundle rather than inside it: `NOTICE` and `LICENSES/`, which `DEPLOY.md` step 5 uploads
and explains (license texts carry URLs, and the origin gate permits none inside `dist/`).
The rsync below excludes those two names from its `--delete` so a redeploy cannot silently
remove the legal texts; everything else in the docroot is exactly what `reproduce.sh`
produced.

## Step 7: the dry run, then the upload

**Job:** make the docroot byte-for-byte the built `dist/`.
**Layer:** content only. No nginx change, so no reload.

**Do not use the publish script that deploys `localfirstlab.org`.** It rsyncs that site's
own build into that site's docroot and knows nothing about this one. Pointing it here, or
pointing the command below at the apex docroot, is how a live site gets deleted by a
`--delete` flag.

The dry run is the load-bearing half of this step. Run it, read it, and only then run the
real one. The trailing slash on `$DIST/` is what makes rsync copy the CONTENTS of `dist`
rather than create a `dist` directory inside the docroot.

```bash
DIST=<the dist directory step 6 printed>
APP=root@178.104.41.74:/var/www/keyweave.localfirstlab.org/
test -f "$DIST/index.html" || { echo "STOP: not a dist directory"; exit 1; }
rsync -rlptv --delete --chmod=D755,F644 --itemize-changes --dry-run \
  --exclude=/NOTICE --exclude=/LICENSES/ \
  "$DIST/" "$APP" | tee /tmp/kw-rsync-dry.txt
grep -c '^\*deleting' /tmp/kw-rsync-dry.txt || true
```

Read the deletion count before anything else. On a first deploy it must be **0**. On a
later deploy the only things it may name are old hashed assets from the previous release.
**If it names anything you do not recognise, you are pointed at the wrong docroot: stop and
re-read `$APP`.** That single number is the difference between a deploy and an outage on
another site.

`-rlptv` rather than `-a` on purpose: `-a` would also try to carry the build machine's
ownership across, and the files should simply belong to root on the target. `--chmod`
normalises the modes so the result does not depend on the umask of whoever built.

Then the same command without `--dry-run`:

```bash
rsync -rlptv --delete --chmod=D755,F644 --itemize-changes \
  --exclude=/NOTICE --exclude=/LICENSES/ "$DIST/" "$APP"
```

`--delete` is what makes the docroot exactly the artifact plus the two excluded legal
paths, which is the property the published hashes are about (they cover `dist/` only). Its one cost: a browser that is mid-load across a release can
request an asset that has just been removed and get a 404. A reload fixes it, and the
alternative, a docroot that accumulates every past build, cannot be compared against a hash
at all.

## Step 8: verify from outside

**Job:** confirm what a stranger's browser actually receives.
**Layer:** all three at once, which is why this runs from somewhere else.

From a machine that is neither the build host nor the server:

```bash
APP=https://keyweave.localfirstlab.org
# 1. The redirect. curl ignores HSTS, which is why this is curl and not a browser.
curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' --max-time 15 \
  http://keyweave.localfirstlab.org/
# 2. TLS validates, and the page is the app.
curl -sSI --max-time 15 "$APP/" >/dev/null && echo "OK: certificate chain accepted"
# 3. The CSP header arrived and carries the load-bearing directive.
curl -sI "$APP/" | grep -ci "^content-security-policy:.*wasm-unsafe-eval"
```

Expected: `301 https://keyweave.localfirstlab.org/`, then the OK line, then `1`.

A `0` on the third is either a missing header or a wrapped one, and `curl: (8) Header
without colon` anywhere in this block is the wrap. `DEPLOY-CSP.md` explains why that
pattern carries no `$` anchor and what each answer distinguishes.

Then the relay origin, which must appear in `connect-src` exactly once and as the whole
directive rather than as a substring of a longer one:

```bash
APP=https://keyweave.localfirstlab.org
WANT=https://relay.keyweave.localfirstlab.org
hdr=$(curl -sI "$APP/" | grep -i '^content-security-policy:' \
  | sed 's/^[^:]*: *//' | tr -d '\r\n' | tr -s ' ')
n=$(printf '%s' "$hdr" | tr ';' '\n' | grep -cF "$WANT" || true)
got=$(printf '%s' "$hdr" | tr ';' '\n' | grep -i 'connect-src' \
  | sed 's/^ *//; s/ *$//')
echo "directives naming the relay: $n"
echo "connect-src: [$got]"
[ "$n" = 1 ] || { echo "STOP: the relay origin appears $n times, want 1"; exit 1; }
[ "$got" = "connect-src 'self' $WANT" ] \
  || { echo "STOP: connect-src is not the expected directive"; exit 1; }
echo "OK: connect-src names the relay exactly once"
```

Exact equality, never a substring: a suffix lookalike such as the same name with another
domain glued on its end passes a substring test and is a different origin entirely.

Finally the wasm content type, because a wrong one breaks the QR decoder with no error
anywhere on the page. Take the filename from the build output rather than typing it, since
it is content-hashed:

```bash
WASM=$(cd "$DIST" && ls assets/*.wasm)
curl -sI "https://keyweave.localfirstlab.org/$WASM" \
  | grep -ci '^content-type: *application/wasm'
```

Must print `1`.

Two checks belong to other documents and neither is optional. `DEPLOY.md` step 6b compares
the served header against the served bundle, which is the check that catches a header
pasted for one relay beside a bundle built for another. `REPRODUCIBLE-BUILD.md` step 5
fetches each served file, hashes it, and compares against the signed tag message, which is
the check that the bytes on the wire are the bytes that were attested.

## Rollback

Removing one symlink is the whole rollback:

```bash
sudo rm -f /etc/nginx/sites-enabled/keyweave-app
sudo nginx -t && sudo systemctl reload nginx && echo "OK: app origin withdrawn"
```

The name then falls through to the default server and serves nothing of Keyweave. The
vhost file, the docroot, the certificate and the DNS record all survive, so restoring is
the same `ln -sfn` and reload. `localfirstlab.org` is a different server block in a
different file and is unaffected either way.

What rollback does NOT undo: the name is in the public CT logs from the moment step 4 ran,
and it stays there.

## What is deliberately not here

No CI runner, no auto-deploy, no push-to-publish, and no script that wraps the steps above
into one command. Nothing in this project may publish itself.

No provider firewall change either. Ports 80 and 443 are already open on this host and
already have a listener; a new public port would need a rule added in the provider console,
and its absence would present as a hang rather than as a refusal.

HTTP/2 is not enabled above, which matches what this host serves today. Turning it on later
is one `http2 on;` line in the server block, on nginx 1.25.1 or newer, and it changes
nothing else in this runbook.
