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

**Every block that changes the server is pasted by the owner.** The agent lane stages the
build and runs the rsync dry run; it does not run the deploy. The steps marked
AGENT-RUNNABLE do not change the server, though the dry run does log in to it read-only.

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
  registered account (measured 2026-08-13: exactly one), so issuance for a new name reuses
  it and asks for no address. The relay host's runbook is where an ACME email is actually
  chosen; where it refuses its placeholder, `hello@localfirstlab.org` is the recommended
  default for the owner to confirm, because that address is already published as the
  release-signing key's user id and so introduces no new identity anywhere.
- **This host is shared, and that widens R1 rather than R2.** `178.104.41.74` also serves
  the `localfirstlab.org` static site and a second web application, whose vhost is the
  port 80 default server (`server_name _`) and reverse-proxies `127.0.0.1:8080`. They
  share this machine and so its root, and root is what owns `/etc/nginx` and the docroot
  step 2 creates. Code execution in that local application is therefore a foothold on this
  box, one privilege escalation away from serving a modified bundle. Step 2 creates the
  docroot root-owned and `0755` and step 7 uploads as root, so an unprivileged foothold
  cannot write it directly; that escalation is the whole of the margin. This is the same
  shared-root reasoning `DEPLOY.md` uses to keep the relay off this box, but it is NOT the
  same break: the relay is elsewhere, so "compromise the relay gives you ciphertext only"
  still holds and R2 stands. What it costs is that R1's trust base is this machine as a
  whole and not just its nginx. Accepted deliberately: this is the host with the drilled
  publish flow and the rsync dry-run discipline, and the alternatives were rejected for
  other reasons (Pages cannot send headers, a CDN rewrites bytes), not for this one.
- **CAA: Let's Encrypt only, at the zone apex.** One record pair, added in step 1. It
  removes every other publicly trusted CA from the picture. It does NOT stop anyone who
  can answer the HTTP-01 challenge for this name: they would ask Let's Encrypt, which this
  record permits. The zone is not DNSSEC-signed, so the record is advisory against an
  attacker who can spoof DNS to a CA. Its blast radius is the whole zone, including
  `relay.keyweave.localfirstlab.org` on the other box: a CA not named here stops being
  able to issue for any name under `localfirstlab.org`. That is safe today because both
  hosts take Let's Encrypt certificates through certbot (this host measured 2026-08-13,
  the relay per its own runbook), and public DNS carries no other host in the zone. The
  MX points into Proton's own zone, whose certificates are not covered by this record.

## Three layers, and which one each step touches

A request to this host passes three independent controls, and a failure looks different at
each. Every step below names the layer it changes, so that a symptom can be traced rather
than guessed at.

| layer | what it is | how a failure presents |
|---|---|---|
| provider firewall | allows TCP 22, 80, 443 and ICMP, on v4 and v6 | a HANG, never a refusal |
| nginx | the vhost, TLS, the headers, the docroot | 404, wrong certificate, missing header |
| fail2ban | active here, one jail (sshd), watching auth logs | your own address stops answering |

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
- Every server-touching block below starts by gating on the box's own identity (hostname
  `ubuntu-main-relay`, address `178.104.41.74`), so a paste on the wrong machine stops at
  its first line instead of half-running. The relay sitting proved the need: a block pasted
  on the wrong box PASSED its OS and Python gates, because two estate boxes agree on both.
  This box also serves production sites, which is the reason for the gate, not extra caution.
- You can edit DNS for `localfirstlab.org` (Porkbun).
- The relay is already deployed and answering, or you accept that the app will load and
  fail to send until it is. The app is useful to verify either way.

## Step 1: the DNS records

**Job:** make the name resolve to the app host, and pin the zone's issuance policy while
the console is already open.
**Layer:** none of the three. This is naming and zone policy, before the host changes.

In Porkbun, on `localfirstlab.org`, add one record:

    type A, host keyweave, answer 178.104.41.74

No AAAA. Then the CAA pair from the decisions above. Before adding it, read the record
list in the console and confirm no name under `localfirstlab.org` gets its certificate
from anywhere except Let's Encrypt: the console is the check, not `certbot certificates`,
because certbot on these boxes cannot see a name a third party serves.

    type CAA, host @, flag 0, tag issue, value letsencrypt.org
    type CAA, host @, flag 0, tag iodef, value mailto:hello@localfirstlab.org

No `issuewild`. With none present, wildcard issuance falls under `issue`, so Let's Encrypt
could still issue `*.localfirstlab.org`. Forbidding that outright is stronger and nothing
in this estate needs it, but it fails closed on a future wildcard, so it is a deliberate
second decision rather than part of this paste. The stronger `accounturi=` form binds
issuance to one ACME account; these two boxes registered separate accounts, so an apex
`accounturi` would have to name BOTH or it silently breaks the other box's renewals.
Worth doing as its own step with both URIs read off `/etc/letsencrypt/accounts/` on each
host, not here.

Then, from your own machine, not from the server:

```bash
dig +short keyweave.localfirstlab.org A
dig +short keyweave.localfirstlab.org AAAA
got=$(dig +short localfirstlab.org CAA | sort | tr '\n' '|')
want='0 iodef "mailto:hello@localfirstlab.org"|0 issue "letsencrypt.org"|'
[ "$got" = "$want" ] || { echo "STOP: CAA reads [$got]"; exit 1; }
echo "OK: CAA names Let's Encrypt and nobody else"
```

The first must print `178.104.41.74` and nothing else. The second must print nothing at
all: that empty answer is the decision above, not an unfinished step. If your dig prints a
`\# 22 ...` blob on the CAA query it is too old to format CAA; read the same answer with
`dig localfirstlab.org CAA` and compare by eye. Negative answers cache for 30 minutes here
(the SOA minimum is 1800), so if you correct a mistyped record, wait that out before
concluding the correction did not take. Wait for all of these before going on, because
every later step reads DNS and a stale answer makes them fail in ways that look like
something else.

The name is public from this moment, to anyone who queries it and to the passive DNS
collectors that watch. It is not yet permanent; step 4 is where that changes. And until
step 3 lands, the port-80 default server for this name is the gig-landing application, so
that application is what an ACME validator for this name would talk to: do steps 1 to 3 in
the same sitting.

## Step 2: the docroot and a separate ACME root

**Job:** create the two directories, kept apart on purpose.
**Layer:** nginx, and the filesystem it reads.

```bash
( set -eu
[ "$(hostname)" = ubuntu-main-relay ] || { echo "STOP: wrong box (hostname)"; exit 1; }
ip -4 -o addr show scope global | grep -qF 178.104.41.74 \
  || { echo "STOP: this box does not hold 178.104.41.74"; exit 1; }
sudo install -d -m 0755 /var/www/keyweave.localfirstlab.org
sudo install -d -m 0755 /var/www/keyweave-acme
sudo install -d -m 0755 /var/www/keyweave-acme/.well-known/acme-challenge
ls -ld /var/www/keyweave.localfirstlab.org /var/www/keyweave-acme
)
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
[ "$(hostname)" = ubuntu-main-relay ] || { echo "STOP: wrong box (hostname)"; exit 1; }
ip -4 -o addr show scope global | grep -qF 178.104.41.74 \
  || { echo "STOP: this box does not hold 178.104.41.74"; exit 1; }
command -v curl >/dev/null \
  || { echo "STOP: curl is missing; apt-get install -y curl, then re-paste"; exit 1; }
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
sudo ln -sfn "$CONF" /etc/nginx/sites-enabled/zz-keyweave-app
ls /etc/nginx/sites-enabled | sort | tail -n 1 | grep -qx 'zz-keyweave-app' \
  || { echo "STOP: the Keyweave link no longer sorts last in sites-enabled"; exit 1; }
a80=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:80:127.0.0.1 http://localfirstlab.org/ || true)
a443=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:443:127.0.0.1 https://localfirstlab.org/ || true)
tout=$(sudo nginx -t 2>&1) \
  || { echo "$tout"; echo "STOP: nginx -t failed, the running config is unchanged"; exit 1; }
if printf '%s\n' "$tout" | grep -qi 'conflicting server name'; then
  printf '%s\n' "$tout"
  echo "STOP: this config claims a name another site already serves; not reloading"
  exit 1
fi
sudo systemctl reload nginx
sleep 1
b80=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:80:127.0.0.1 http://localfirstlab.org/ || true)
b443=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:443:127.0.0.1 https://localfirstlab.org/ || true)
if [ "$b80" != "$a80" ] || [ "$b443" != "$a443" ]; then
  echo "STOP: the apex changed across this reload (80 $a80->$b80, 443 $a443->$b443)"
  echo "Undo: sudo rm -f /etc/nginx/sites-enabled/zz-keyweave-app"
  echo "then: sudo nginx -t; sudo systemctl reload nginx"
  exit 1
fi
echo "OK: nginx reloaded, apex unchanged (80=$b80 443=$b443)"
)
```

Three disciplines in that tail, each paid for on this estate. The gate and the reload are
separate lines because under `set -e` a failure anywhere but the LAST command of an `&&`
chain does not exit the script: `nginx -t && reload && echo OK` absorbs a failed
`nginx -t` and the paste continues to a false "step complete", which is exactly what
happened once on the relay box. The `sleep 1` is because a reload is graceful: for about a
second the draining pre-reload workers still answer, with the OLD configuration. And the
apex probes bracket the reload because `nginx -t` proves syntax, not that the co-tenant
sites still answer as they did: the probes pin the apex's status codes across the reload
and STOP on any delta, with SNI on purpose, so an expected default-server change (next
paragraph) cannot fire them.

**Why the link is named `zz-keyweave-app`.** nginx includes `sites-enabled/*` in sorted
order, and no 443 block on this host is marked `default_server`, so the block parsed FIRST
answers every request whose SNI matches no `server_name`. `keyweave-app` sorts before
`localfirstlab.org`; the `zz-` prefix keeps the apex parsed first, so bare-IP and
unmatched-SNI connections on 443 keep getting the apex certificate rather than announcing
Keyweave. The sort gate above is that invariant, checked before anything is applied. A
future editor tidying the "odd" prefix reinstates the displacement silently: do not.

Now prove the whole path end to end before spending an ACME attempt on it. On the server:

```bash
( set -eu
[ "$(hostname)" = ubuntu-main-relay ] || { echo "STOP: wrong box (hostname)"; exit 1; }
ip -4 -o addr show scope global | grep -qF 178.104.41.74 \
  || { echo "STOP: this box does not hold 178.104.41.74"; exit 1; }
printf 'keyweave-acme-probe\n' \
  | sudo tee /var/www/keyweave-acme/.well-known/acme-challenge/probe >/dev/null
)
```

**From your own machine, not from the server**, because a request made on the box never
crosses the provider firewall and so proves nothing about it:

```bash
curl -sS --max-time 15 \
  http://keyweave.localfirstlab.org/.well-known/acme-challenge/probe
```

That must print `keyweave-acme-probe`, exactly. A hang means the request is not arriving:
check the DNS answer from step 1 first. A miss does NOT look like a 404 on this host: the
default port-80 server here is the gig-landing vhost (`server_name _`), which proxies
everything to a local app, so a request that matched no `keyweave` block comes back as a
200 with someone else's HTML (measured 2026-08-13). Anything other than the exact probe
string means the reload did not take or `server_name` is misspelled. Then remove the probe:

```bash
( set -eu
[ "$(hostname)" = ubuntu-main-relay ] || { echo "STOP: wrong box (hostname)"; exit 1; }
ip -4 -o addr show scope global | grep -qF 178.104.41.74 \
  || { echo "STOP: this box does not hold 178.104.41.74"; exit 1; }
sudo rm -f /var/www/keyweave-acme/.well-known/acme-challenge/probe
)
```

## Step 4: the certificate. The dry run first, then the point of no return

**Job:** obtain a certificate for the new name.
**Layer:** nginx reads it, and the public Certificate Transparency logs record it.

```bash
( set -eu
[ "$(hostname)" = ubuntu-main-relay ] || { echo "STOP: wrong box (hostname)"; exit 1; }
ip -4 -o addr show scope global | grep -qF 178.104.41.74 \
  || { echo "STOP: this box does not hold 178.104.41.74"; exit 1; }
sudo certbot certonly --webroot -w /var/www/keyweave-acme \
  -d keyweave.localfirstlab.org --dry-run
)
```

The dry run uses the staging authority. It exercises DNS, the provider firewall, the port
80 vhost and the webroot for real, consumes no production rate limit, and does not put the
name in the production CT logs. It is the only honest external oracle for this step: the
probe in step 3 tested the same path with your own client, and this tests it with theirs.

The dry run also checks CAA. Let's Encrypt's staging directory advertises the same
`caaIdentities` value as production, `letsencrypt.org` (checked 2026-08-13), so a mistyped
CAA record from step 1 fails here, on the staging authority, rather than weeks later on a
renewal of a name this runbook never touches. An error naming CAA means re-read the step 1
records before touching anything on this host.

**If certbot asks for an email address, STOP.** This host has a registered account and
should not be asked. Being asked means certbot is registering a NEW account, which is a
decision to make deliberately rather than at a prompt. See the ACME line in the decisions
above.

Then, and this is the step that cannot be undone:

```bash
( set -eu
[ "$(hostname)" = ubuntu-main-relay ] || { echo "STOP: wrong box (hostname)"; exit 1; }
ip -4 -o addr show scope global | grep -qF 178.104.41.74 \
  || { echo "STOP: this box does not hold 178.104.41.74"; exit 1; }
sudo certbot certonly --webroot -w /var/www/keyweave-acme \
  -d keyweave.localfirstlab.org --deploy-hook "systemctl reload nginx"
sudo test -s /etc/letsencrypt/live/keyweave.localfirstlab.org/fullchain.pem \
  || { echo "STOP: certificate file missing or empty"; exit 1; }
echo "OK: certificate present"
)
```

**Issuance writes `keyweave.localfirstlab.org` into the public Certificate Transparency
logs, permanently and searchably.** Deleting the record, the vhost and the certificate
afterwards does not remove it. Everything before this point is reversible; this is not. The
deploy hook is stored in the renewal configuration, so renewals reload nginx by themselves;
this host has no global deploy hook today (measured 2026-08-13), and if one is ever added,
both run and two reloads are harmless.

The two names on this host renew independently: the apex certificate renews via the nginx
authenticator (its renewal config says so), this name via webroot. `certbot renew` runs
both and they do not interact.

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
short pieces by that generator so every piece stays well under the 100-character paste
bar; the marker gates below carry the rest. If your relay origin is different, run the
generator and paste what it prints. Do not edit the pieces by hand: the chunk boundaries
move with the length of the origin.

**What this vhost deliberately does not set, measured against the live host 2026-08-13.**
This box's `nginx.conf` ships the distro default `server_tokens build;` ACTIVE at http
scope, the same drift the relay sitting hit: adding any `server_tokens` at http scope (a
conf.d file, say) is a duplicate-directive emerg, so this vhost sets none. The http scope
also already carries `ssl_protocols TLSv1.2 TLSv1.3;` and `ssl_prefer_server_ciphers off;`;
the server-level repeats below are legal overrides of the same values, kept so the block
states its own TLS posture. Optional hygiene, the owner's call and not part of this deploy:
flip the distro `server_tokens` line to `off` with a dated `.bak`, as the relay box did.
It affects every site on the box, benignly.

```bash
( set -eu
[ "$(hostname)" = ubuntu-main-relay ] || { echo "STOP: wrong box (hostname)"; exit 1; }
ip -4 -o addr show scope global | grep -qF 178.104.41.74 \
  || { echo "STOP: this box does not hold 178.104.41.74"; exit 1; }
command -v curl >/dev/null \
  || { echo "STOP: curl is missing; apt-get install -y curl, then re-paste"; exit 1; }
CONF=/etc/nginx/sites-available/keyweave-app
sudo tee /etc/nginx/sites-available/keyweave-app-acme >/dev/null <<'ACMEONLY'
# Keyweave app host, ACME-only fallback. docs/DEPLOY-APP.md step 5 writes it,
# Rollback enables it. It serves the challenge path and 404s everything else,
# so a withdrawn app origin never falls through to the port-80 default server.
server {
    listen 80;
    listen [::]:80;
    server_name keyweave.localfirstlab.org;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/keyweave-acme;
        default_type "text/plain";
    }

    location / {
        return 404;
    }
}
ACMEONLY
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

    # The docroot holds regular files only (step 6 refuses anything else);
    # this makes nginx refuse to follow one that appears anyway.
    disable_symlinks on from=$document_root;

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
f=$(grep -cE '^[[:space:]]*add_header [A-Za-z-]+ ".*" always;$' "$CONF" || true)
g=$(grep -cE '^[[:space:]]*add_header ' "$CONF" || true)
echo "markers: a=$a b=$b c=$c d=$d e=$e f=$f g=$g   (want 1 1 1 4 1 7 7)"
if [ "$a" != 1 ] || [ "$b" != 1 ] || [ "$c" != 1 ] || [ "$d" != 4 ] \
   || [ "$e" != 1 ] || [ "$f" != 7 ] || [ "$g" != 7 ]; then
  echo "STOP: a header line wrapped, is missing, or was pasted twice"
  exit 1
fi
sudo ln -sfn "$CONF" /etc/nginx/sites-enabled/zz-keyweave-app
ls /etc/nginx/sites-enabled | sort | tail -n 1 | grep -qx 'zz-keyweave-app' \
  || { echo "STOP: the Keyweave link no longer sorts last in sites-enabled"; exit 1; }
a80=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:80:127.0.0.1 http://localfirstlab.org/ || true)
a443=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:443:127.0.0.1 https://localfirstlab.org/ || true)
tout=$(sudo nginx -t 2>&1) \
  || { echo "$tout"; echo "STOP: nginx -t failed, the running config is unchanged"; exit 1; }
if printf '%s\n' "$tout" | grep -qi 'conflicting server name'; then
  printf '%s\n' "$tout"
  echo "STOP: this config claims a name another site already serves; not reloading"
  exit 1
fi
sudo systemctl reload nginx
sleep 1
b80=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:80:127.0.0.1 http://localfirstlab.org/ || true)
b443=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:443:127.0.0.1 https://localfirstlab.org/ || true)
if [ "$b80" != "$a80" ] || [ "$b443" != "$a443" ]; then
  echo "STOP: the apex changed across this reload (80 $a80->$b80, 443 $a443->$b443)"
  echo "Undo: sudo rm -f /etc/nginx/sites-enabled/zz-keyweave-app"
  echo "then: sudo nginx -t; sudo systemctl reload nginx"
  exit 1
fi
echo "OK: nginx reloaded, apex unchanged (80=$b80 443=$b443)"
n=$(sudo nginx -T 2>/dev/null | grep -cF 'server_name keyweave.localfirstlab.org;' || true)
[ "$n" = 2 ] \
  || { echo "STOP: vhost not loaded (server_name count $n, want 2)"; exit 1; }
resp=$(curl -sS --max-time 10 --resolve keyweave.localfirstlab.org:443:127.0.0.1 \
         -I https://keyweave.localfirstlab.org/ 2>&1) || {
  echo "STOP: the reloaded config is LIVE and does not answer cleanly:"
  printf '%s\n' "$resp"
  echo "Withdraw it with the Rollback block at the end of this runbook, then re-paste."
  exit 1
}
for k in strict-transport-security content-security-policy referrer-policy \
         x-content-type-options cross-origin-opener-policy \
         cross-origin-resource-policy permissions-policy; do
  printf '%s' "$resp" | grep -qi "^$k:" || {
    echo "STOP: $k is not on the live response; see the Rollback block"
    exit 1
  }
done
# No 443 block on this host is marked default_server, so the block nginx parsed
# first answers every unmatched SNI. That must stay the apex. Deliberately no SNI.
for T in 127.0.0.1:443 '[::1]:443'; do
  san=$(openssl s_client -connect "$T" -noservername </dev/null 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null \
        | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  if [ -z "$san" ]; then echo "NOTE: $T gave no certificate, check it separately"; continue; fi
  if printf '%s\n' "$san" | grep -qx 'DNS:keyweave.localfirstlab.org'; then
    echo "STOP: $T now defaults to the Keyweave certificate"; exit 1
  fi
  printf '%s\n' "$san" | grep -qx 'DNS:localfirstlab.org' \
    || { echo "STOP: $T no longer defaults to the apex certificate"; exit 1; }
  echo "OK: $T still defaults to the apex certificate"
done
echo "OK: step 5 complete, vhost loaded, all seven headers on the loopback response"
echo "    (this proves the config only; step 8 is the external oracle)"
)
```

The anchored markers are the wall against the 2026-08-05 failure on this very host, which
was an `add_header` line whose newline landed inside the quotes. `nginx -t` will not catch
a wrap like that: a quoted string may legally span lines, and the breakage appears only at
the HTTP layer as `curl: (8) Header without colon`. `d` anchors the four generated `set`
lines as whole lines; `f` and `g` anchor the seven `add_header` lines the same way, which
is where the original incident actually landed (`g` also counts un-`always`ed additions
that `f` would miss). Markers `a`, `b`, `c`, `e` are substring counts, which a line break
cannot move; they catch missing and doubled pastes, not wraps. The `-F` on them is
load-bearing for the same reason `DEPLOY.md` gives: pattern `c` contains a literal
`$csp_a`, and some greps read a mid-pattern `$` as an anchor and print 0 for a correct
file. The loopback probe after the reload is the backstop for whatever the markers miss;
it STOPs with the config LIVE, which is why its message points at Rollback.

The docroot is still empty at this point, so the site answers 403 on `/` (the directory
exists, the index file does not, and autoindex is off) and 404 on any deeper path. That is
the expected state until step 7, not a fault.

## Step 6: build the bundle at the tag (AGENT-RUNNABLE)

**Job:** produce the exact bytes to serve, from the tag, with the relay origin baked in.
**Layer:** none. This happens on the build machine and touches no server.

This is `DEPLOY.md` step 5, repeated here only because step 7 needs the directory it
produces. If you have already run it, reuse that output directory rather than rebuilding.

Three constraints, and the block enforces the first two. The tag is pinned `v0.1.2`, never
`v0.1.1`: the older tag ships the two retracted claims, and the deploy gate that closed
them says the first deploy pins the corrected release. The tag must verify against the
release key's published fingerprint, not merely "some key in your keyring": import the key
first, per the "Verifying the tag signature" section of `REPRODUCIBLE-BUILD.md`. And run
this from a clone of the PUBLIC repository at the tag, not from a private working copy:
the public tag object is the one a stranger verifies, and `reproduce.sh` stamps the repo
it sits in into its attestation.

The block then refuses to hand over a `$DIST` whose bytes differ from the signed tag's
hash block, which is what makes step 7's upload an upload of ATTESTED bytes rather than of
whatever a build just produced.

```bash
( set -eu
TAG=v0.1.2
FPR=D78D89413752779209479B9ACF5C8AB3DB4A56EB
export KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org
case "$KEYWEAVE_RELAY_ORIGIN" in
  https://*) ;;
  *) echo "STOP: KEYWEAVE_RELAY_ORIGIN is empty or is not an https origin"
     exit 1 ;;
esac
git verify-tag --raw "$TAG" 2>&1 >/dev/null | tee /tmp/kw-tagsig.txt \
  | grep -q '^\[GNUPG:\] GOODSIG' \
  || { echo "STOP: $TAG carries no good signature"; exit 1; }
grep -qE "^\[GNUPG:\] VALIDSIG .* $FPR$" /tmp/kw-tagsig.txt \
  || { echo "STOP: $TAG is signed, but not by the release key $FPR"; exit 1; }
OUT="$(mktemp -d)"
# The FIRST hash block in the tag message is the deployed-origin configuration;
# the second is the same-origin build, which this deploy does not serve. A
# same-origin deploy must take its block instead.
git cat-file -p "$TAG" | awk '
  /artifact hashes \(sha256\):/ && !seen { grab=1; seen=1; next }
  grab && /^[[:space:]]*[0-9a-f]{64}[[:space:]]/ { print $1"  "$2; got++; next }
  grab && got && NF==0 { grab=0 }
' | LC_ALL=C sort -k2 > "$OUT/attested.txt"
[ -s "$OUT/attested.txt" ] || { echo "STOP: no hash block in the tag message"; exit 1; }
git cat-file -p "$TAG" | grep -E '^ +(commit|node|npm|KEYWEAVE_RELAY_ORIGIN) +:' || true
echo "local toolchain: node $(node --version) npm $(npm --version)"
scripts/reproduce.sh "$TAG" "$OUT"
DIST="$OUT/src/client/dist"
n=$(grep -cF "$KEYWEAVE_RELAY_ORIGIN" "$DIST/index.html" || true)
[ "$n" -ge 1 ] || { echo "STOP: built index.html does not name the relay origin"; exit 1; }
echo "relay origin occurrences in index.html: $n"
odd=$(find "$DIST" ! -type d ! -type f -print)
[ -z "$odd" ] || { echo "STOP: dist holds something that is not a regular file:"
  printf '%s\n' "$odd"; exit 1; }
( cd "$DIST" && find . -type f | sed 's|^\./||' | LC_ALL=C sort ) > "$OUT/files.txt"
: > "$OUT/built.txt"
while IFS= read -r f; do
  printf '%s  %s\n' "$(cd "$DIST" && sha256sum "$f" | cut -d' ' -f1)" "$f" \
    >> "$OUT/built.txt"
done < "$OUT/files.txt"
LC_ALL=C sort -k2 -o "$OUT/built.txt" "$OUT/built.txt"
diff -u "$OUT/attested.txt" "$OUT/built.txt" || {
  echo "STOP: built bytes are not the attested bytes."
  echo "      Read the two build-inputs blocks above FIRST: a node or npm difference"
  echo "      is a known legitimate cause (REPRODUCIBLE-BUILD.md) and is not"
  echo "      evidence of tampering."
  exit 1; }
echo "OK: every built file matches the signed tag"
ls -la "$DIST"
printf 'DIST=%s\n' "$DIST"
)
```

`DEPLOY.md` step 5 explains why the origin grep's pattern is the variable and not a
hostname typed into a document. This block runs in a subshell, so `$DIST` does NOT survive
it: copy the `DIST=` line it prints last and paste it over the blank at the top of
step 7a.

Whatever is in that directory is what gets served, plus exactly two paths that ride BESIDE
the bundle rather than inside it: `NOTICE` and `LICENSES/`, which step 7b below uploads;
`DEPLOY.md` step 5 explains why they ride beside the bundle rather than inside it (license
texts carry URLs, and the origin gate permits none inside `dist/`). The main rsync
excludes those two names from its `--delete` so a redeploy cannot silently remove the
legal texts; everything else in the docroot is exactly what `reproduce.sh` produced.

## Step 7: the dry run, then the upload

**Job:** make the docroot byte-for-byte the built `dist/`, plus the two legal paths that
step 7b owns.
**Layer:** content only. No nginx change, so no reload.

**Do not use the publish script that deploys `localfirstlab.org`.** It rsyncs that site's
own build into that site's docroot and knows nothing about this one. Pointing it here, or
pointing the command below at the apex docroot, is how a live site gets deleted by a
`--delete` flag.

### Step 7a: the dry run (AGENT-RUNNABLE, changes nothing)

The dry run is the load-bearing half of this step. Run it, read it, and only then run the
real one. The trailing slash on `$DIST/` is what makes rsync copy the CONTENTS of `dist`
rather than create a `dist` directory inside the docroot. The assignments sit OUTSIDE the
subshell so the later blocks reuse them, and `DIST=` is a valid assignment that always
executes, so an unfilled blank clobbers any stale value instead of hiding behind a parse
error. The redirect into a file rather than `tee` is deliberate: a pipeline masks rsync's
own exit status, and a dry run that failed mid-enumeration hands you a deletion count that
means nothing.

```bash
DIST=            # paste the DIST= line step 6 printed, over this whole line
APP=root@178.104.41.74:/var/www/keyweave.localfirstlab.org/
( set -eu
[ -n "${DIST:-}" ] || { echo "STOP: DIST is empty; paste the line step 6 printed"; exit 1; }
test -f "$DIST/index.html" || { echo "STOP: not a dist directory"; exit 1; }
ls "$DIST"/assets/*.wasm >/dev/null 2>&1 \
  || { echo "STOP: no assets/*.wasm here; not a Keyweave dist"; exit 1; }
rsync -rlptv --delete --chmod=D755,F644 --itemize-changes --dry-run \
  --exclude=/NOTICE --exclude=/LICENSES/ \
  "$DIST/" "$APP" > /tmp/kw-rsync-dry.txt \
  || { echo "STOP: the dry run itself failed; its count means nothing"; exit 1; }
cat /tmp/kw-rsync-dry.txt
grep -q '(DRY RUN)' /tmp/kw-rsync-dry.txt \
  || { echo "STOP: that was not dry-run output"; exit 1; }
echo "deletions: $(grep -c '^\*deleting' /tmp/kw-rsync-dry.txt || true)  <- retype below"
)
```

Read the deletion count before anything else. On a first deploy it must be **0**. On a
later deploy the only things it may name are old hashed assets from the previous release.
**If it names anything you do not recognise, you are pointed at the wrong docroot: stop and
re-read `$APP`.** That single number is the difference between a deploy and an outage on
another site.

`-rlptv` rather than `-a` on purpose: `-a` would also try to carry the build machine's
ownership across, and the files should simply belong to root on the target. `--chmod`
normalises the modes so the result does not depend on the umask of whoever built.

### The upload (owner-run)

Then the same command with `--dry-run` dropped and ONE flag added: `--max-delete`, set to
the deletion count you just read. Never put `--max-delete` in the dry run itself: it
suppresses the `*deleting` lines, so the count you rely on would print 0 whatever the
target holds. The `MAXDEL=` blank is retyped by hand on purpose, the same device as the
`$WANT` retype in `DEPLOY.md` 6b: it is where a number you did not actually read has
somewhere to show up. The APP-equality line is a tripwire against editing that line, not
an independent check; the machine wall is `--max-delete`, and it is a hard "delete
nothing" wall only at 0. The block ends by re-running the dry run and demanding zero
deltas, which proves the upload landed on the machine that ran it.

```bash
MAXDEL=          # retype the deletion count the dry run printed; first deploy: 0
( set -eu
[ -n "${DIST:-}" ] || { echo "STOP: DIST is empty; run step 7a first, same shell"; exit 1; }
[ "$APP" = "root@178.104.41.74:/var/www/keyweave.localfirstlab.org/" ] \
  || { echo "STOP: APP is not the app docroot"; exit 1; }
test -f "$DIST/index.html" || { echo "STOP: not a dist directory"; exit 1; }
case "$MAXDEL" in ''|*[!0-9]*) echo "STOP: MAXDEL is not a number"; exit 1 ;; esac
rsync -rlptv --delete --max-delete="$MAXDEL" --chmod=D755,F644 \
  --itemize-changes --exclude=/NOTICE --exclude=/LICENSES/ "$DIST/" "$APP" \
  || { echo "STOP: rsync failed (25 = the deletion cap stopped it)"; exit 1; }
rsync -rlptv --delete --chmod=D755,F644 --itemize-changes --dry-run \
  --exclude=/NOTICE --exclude=/LICENSES/ "$DIST/" "$APP" > /tmp/kw-rsync-post.txt
p=$(grep -cE '^[<>ch*.]' /tmp/kw-rsync-post.txt || true)
[ "$p" = 0 ] || { echo "STOP: $p items still differ; the upload did not land"; exit 1; }
echo "UPLOAD VERIFIED: docroot matches the artifact"
)
```

`--delete` is what makes the docroot exactly the artifact plus the two excluded legal
paths, which is the property the published hashes are about (they cover `dist/` only). Its one cost: a browser that is mid-load across a release can
request an asset that has just been removed and get a 404. A reload fixes it, and the
alternative, a docroot that accumulates every past build, cannot be compared against a hash
at all.

### Step 7b: the legal texts (owner-run)

Nothing so far has put `NOTICE` or `LICENSES/` on the host: the main rsync deliberately
excludes them from its `--delete`, and excluding is not uploading. This block owns exactly
that subtree, with the same dry-run discipline, and it runs AFTER the upload above. `$SRC`
is derived from `$DIST` rather than retyped: the build tree's root is two directories up.

```bash
( set -eu
[ -n "${DIST:-}" ] || { echo "STOP: DIST is empty; run step 7a first, same shell"; exit 1; }
SRC="${DIST%/client/dist}"
APPHOST=root@178.104.41.74
APPDIR=/var/www/keyweave.localfirstlab.org
case "$APPDIR" in /var/www/keyweave.localfirstlab.org) ;;
  *) echo "STOP: that is not the app docroot"; exit 1 ;; esac
[ "$(ssh "$APPHOST" hostname)" = ubuntu-main-relay ] \
  || { echo "STOP: that ssh target is not the app host"; exit 1; }
test -s "$SRC/NOTICE" || { echo "STOP: no NOTICE in the build clone"; exit 1; }
ls -1 "$SRC/LICENSES"/*.txt >/dev/null \
  || { echo "STOP: no LICENSES/*.txt in the build clone"; exit 1; }
rsync -rlptv --chmod=F644 "$SRC/NOTICE" "$APPHOST:$APPDIR/NOTICE"
# --delete, so this command OWNS the subtree. Dry run first, same discipline.
rsync -rlptv --delete --chmod=D755,F644 --itemize-changes --dry-run \
  "$SRC/LICENSES/" "$APPHOST:$APPDIR/LICENSES/" | tee /tmp/kw-licenses-dry.txt
if grep -qE '^\*deleting +(index\.html|assets/)' /tmp/kw-licenses-dry.txt; then
  echo "STOP: this is pointed at the docroot, not at LICENSES/"; exit 1
fi
grep -c '^\*deleting' /tmp/kw-licenses-dry.txt || true
rsync -rlptv --delete --chmod=D755,F644 --itemize-changes \
  "$SRC/LICENSES/" "$APPHOST:$APPDIR/LICENSES/"
)
```

Read that deletion count too. On a first deploy it is 0; later it may name a license file
the tree dropped, or a stray that does not belong there. Both are the point of `--delete`
owning this subtree, which is what ends the unbounded carve-out.

### Step 7c: the docroot enumeration (AGENT-RUNNABLE, read-only)

The backstop for a stray of any kind, and the only step that ever states the docroot's
full contents. It is exact only because step 2 kept the ACME root outside the docroot.
`! -type d` on BOTH sides is deliberate: a symlink must show up as a line rather than
vanish from one side of the comparison.

```bash
( set -eu
[ -n "${DIST:-}" ] || { echo "STOP: DIST is empty; run step 7a first, same shell"; exit 1; }
SRC="${DIST%/client/dist}"
APPHOST=root@178.104.41.74
APPDIR=/var/www/keyweave.localfirstlab.org
W=$(mktemp); H=$(mktemp); trap 'rm -f "$W" "$H"' EXIT
{ ( cd "$DIST" && find . -mindepth 1 ! -type d ) | sed 's|^\./||'
  ( cd "$SRC"  && find LICENSES -mindepth 1 ! -type d )
  echo NOTICE
} | LC_ALL=C sort > "$W"
ssh "$APPHOST" \
  "cd $APPDIR && find . -mindepth 1 ! -type d | sed 's|^\./||' | LC_ALL=C sort" > "$H"
diff -u "$W" "$H" \
  || { echo "STOP: the docroot is not exactly the artifact plus the legal texts"; exit 1; }
echo "OK: docroot enumerated, $(wc -l < "$W") paths, nothing extra"
)
```

## Step 8: verify from outside

**Job:** confirm what a stranger's browser actually receives.
**Layer:** all three at once, which is why this runs from somewhere else.

From a machine that is neither the build host nor the server; in practice the operator's
laptop. (In this estate the agent's shell runs on the build host, so these blocks are
owner-run; an agent-run copy is advisory, not the check.)

```bash
( set -eu
APP=https://keyweave.localfirstlab.org
# 0. What this vantage resolves and talks to. Both lines must print 178.104.41.74;
#    the second is the address curl actually connected to, so a lying local
#    resolver or hosts file shows up here rather than poisoning every later check.
dig +short @9.9.9.9 keyweave.localfirstlab.org A | tail -n 1
curl -sS -o /dev/null -w '%{remote_ip}\n' --max-time 15 "$APP/"
# 1. The redirect. curl ignores HSTS, which is why this is curl and not a browser.
curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' --max-time 15 \
  http://keyweave.localfirstlab.org/
# 2. TLS validates, the status is 200, and the body is the bundle.
code=$(curl -sS -o /tmp/kw-index.html -w '%{http_code}' --max-time 15 "$APP/")
[ "$code" = 200 ] || { echo "STOP: GET / returned $code, want 200"; exit 1; }
grep -qF 'Content-Security-Policy" content=' /tmp/kw-index.html \
  || { echo "STOP: 200, but the body is not the Keyweave bundle"; exit 1; }
echo "OK: chain accepted, 200, and the served page is the app"
# 3. The CSP header arrived and carries the load-bearing directive.
curl -sI --max-time 15 "$APP/" | grep -ci "^content-security-policy:.*wasm-unsafe-eval"
)
```

Expected: `178.104.41.74` twice, then `301 https://keyweave.localfirstlab.org/`, then the
OK line, then `1`. Check 2's body marker is the same substring `DEPLOY.md` step 6b keys
on, so if the meta tag ever changes, both checks move together. A bare HEAD-succeeds check
used to stand where check 2 is; it passed as readily on an empty docroot's 403 as on the
app, because every header carries `always`, which is why the status and the body are now
asserted rather than implied.

A `0` on the third is either a missing header or a wrapped one, and `curl: (8) Header
without colon` anywhere in this block is the wrap. `DEPLOY-CSP.md` explains why that
pattern carries no `$` anchor and what each answer distinguishes.

Then the relay origin, which must appear in `connect-src` exactly once and as the whole
directive rather than as a substring of a longer one:

```bash
( set -eu
APP=https://keyweave.localfirstlab.org
WANT=https://relay.keyweave.localfirstlab.org
hdr=$(curl -sI --max-time 15 "$APP/" | grep -i '^content-security-policy:' \
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
)
```

Exact equality, never a substring: a suffix lookalike such as the same name with another
domain glued on its end passes a substring test and is a different origin entirely.

Then the wasm content type, because a wrong one breaks the QR decoder with no error
anywhere on the page. The filename comes from the signed tag message's hash block, retyped
the same way 6b retypes `$WANT`: this vantage has no build directory, and the name is
content-hashed so it cannot be guessed. The wasm is referenced only from a worker chunk,
never from `index.html`, so there is no way to scrape it off the page.

```bash
( set -eu
WASM='PASTE-THE-WASM-FILENAME-FROM-THE-TAG-MESSAGE'
case "$WASM" in
  assets/*.wasm) ;;
  *) echo "STOP: the wasm filename was not filled in"; exit 1 ;;
esac
URL="https://keyweave.localfirstlab.org/$WASM"
code=$(curl -sS -I -o /dev/null -w '%{http_code}' --max-time 15 "$URL")
[ "$code" = 200 ] \
  || { echo "STOP: the wasm is not served ($code); check the name and step 7"; exit 1; }
curl -sS -I --max-time 15 "$URL" | grep -ci '^content-type: *application/wasm' || true
)
```

Must print `1`. A `0` here with the 200 gate passed is a wrong content type, not a missing
file.

Finally the check the rest of step 8 cannot make: that the served bytes are the ATTESTED
bytes. Import the release key first, per the "Verifying the tag signature" section of
`REPRODUCIBLE-BUILD.md`. The block clones the public repo on THIS vantage and re-derives
the attested list from the signed tag, rather than trusting a file carried over from the
build host, which would defeat the point of a third machine.

```bash
( set -euo pipefail
APP=https://keyweave.localfirstlab.org
TAG=v0.1.2
FPR=D78D89413752779209479B9ACF5C8AB3DB4A56EB
SRC="$(mktemp -d)"
git clone --quiet https://github.com/MacadamiaButter/keyweave "$SRC"
git -C "$SRC" verify-tag --raw "$TAG" 2>&1 >/dev/null | tee /tmp/kw-tagsig8.txt \
  | grep -q '^\[GNUPG:\] GOODSIG' || { echo "STOP: no good signature"; exit 1; }
grep -qE "^\[GNUPG:\] VALIDSIG .* $FPR$" /tmp/kw-tagsig8.txt \
  || { echo "STOP: not the release key"; exit 1; }
# FIRST hash block = the deployed-origin configuration (see step 6).
git -C "$SRC" cat-file -p "$TAG" | awk '
  /artifact hashes \(sha256\):/ && !seen { grab=1; seen=1; next }
  grab && /^[[:space:]]*[0-9a-f]{64}[[:space:]]/ { print $1"  "$2; got++; next }
  grab && got && NF==0 { grab=0 }
' | LC_ALL=C sort -k2 > "$SRC/attested.txt"
[ -s "$SRC/attested.txt" ] || { echo "STOP: no hash block in the tag message"; exit 1; }
fail=0
while IFS= read -r line; do
  want=${line%% *}; p=${line#*  }
  if got=$(curl -fsS --max-time 30 "$APP/$p" </dev/null | sha256sum | cut -d' ' -f1)
  then :
  else printf 'BAD  %s (fetch failed)\n' "$p"; fail=1; continue; fi
  if [ "$want" = "$got" ]; then printf 'ok   %s\n' "$p"
  else printf 'BAD  %s\n' "$p"; fail=1; fi
done < "$SRC/attested.txt"
[ "$fail" = 0 ] || { echo "STOP: the served bytes are not the attested bytes"; exit 1; }
echo "OK: every attested file is byte-identical on the wire"
)
```

One cross-check remains in another document and it is not optional. `DEPLOY.md` step 6b
compares the served header against the served bundle, which is the check that catches a
header pasted for one relay beside a bundle built for another. The served-bytes block
above IS `REPRODUCIBLE-BUILD.md`'s release-procedure step 5, as a runnable command; it is
no longer deferred prose in a third document.

## Rollback

Repointing one symlink is the whole rollback. It swaps the full vhost for the ACME-only
fallback that step 5 wrote, so the app origin is withdrawn while the name keeps answering
its own challenge path. Same link name, so the swap is atomic and no duplicate
`server_name` can exist even for a moment:

```bash
( set -eu
[ "$(hostname)" = ubuntu-main-relay ] || { echo "STOP: wrong box (hostname)"; exit 1; }
ip -4 -o addr show scope global | grep -qF 178.104.41.74 \
  || { echo "STOP: this box does not hold 178.104.41.74"; exit 1; }
FALLBACK=/etc/nginx/sites-available/keyweave-app-acme
[ -f "$FALLBACK" ] || { echo "STOP: no ACME-only fallback file; re-read step 5"; exit 1; }
if grep -qF 'listen 443' "$FALLBACK"; then
  echo "STOP: the fallback is a full app vhost, not the ACME-only one"
  exit 1
fi
sudo ln -sfn "$FALLBACK" /etc/nginx/sites-enabled/zz-keyweave-app
a80=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:80:127.0.0.1 http://localfirstlab.org/ || true)
a443=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:443:127.0.0.1 https://localfirstlab.org/ || true)
tout=$(sudo nginx -t 2>&1) \
  || { echo "$tout"; echo "STOP: nginx -t failed, the running config is unchanged"; exit 1; }
if printf '%s\n' "$tout" | grep -qi 'conflicting server name'; then
  printf '%s\n' "$tout"
  echo "STOP: this config claims a name another site already serves; not reloading"
  exit 1
fi
sudo systemctl reload nginx
sleep 1
b80=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:80:127.0.0.1 http://localfirstlab.org/ || true)
b443=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  --resolve localfirstlab.org:443:127.0.0.1 https://localfirstlab.org/ || true)
if [ "$b80" != "$a80" ] || [ "$b443" != "$a443" ]; then
  echo "STOP: the apex changed across this reload (80 $a80->$b80, 443 $a443->$b443)"
  echo "Check: sudo nginx -T | grep -n server_name"
  exit 1
fi
echo "OK: app origin withdrawn, ACME path retained (apex 80=$b80 443=$b443)"
)
```

The name then serves nothing of Keyweave, and here is exactly what it serves instead. On
port 80 it keeps a block of its own, which serves only `/.well-known/acme-challenge/`
from `/var/www/keyweave-acme` and 404s everything else, so the name never falls through
to the port-80 default server (the gig-landing vhost, `server_name _`, which proxies
everything to a local app). That matters twice over: with the DNS record still pointing
here, a name with no block of its own would hand its HTTP-01 challenge path to whatever
that proxy fronts, for any CA to validate against; and the retained block is also what
keeps `certbot renew --webroot` working unattended while the origin is withdrawn. On 443
no block is marked `default_server`, so the first configured block answers, which is the
apex, with the apex certificate, and a certificate that does not carry this name is a
browser error before any page. The stage-B vhost file, the docroot, the certificate, the
CAA records and the DNS record all survive: the CAA pair deliberately, since it is zone
policy rather than app state, and it is the one thing here that keeps protecting the name
after the app is withdrawn. Restoring is re-pasting the step 5 block, which re-points the
symlink at the full vhost, re-tests, reloads and proves the vhost is loaded before it
prints OK. `localfirstlab.org` is a different server block in a different file and is
unaffected either way.

What rollback does NOT undo, three things. The name is in the public CT logs from the
moment step 4 ran, and it stays there. The DNS record still points at this host, which is
WHY the port-80 block stays alive. And the certificate and its renewal configuration
still exist: if the withdrawal is meant to be permanent, run
`sudo certbot delete --cert-name keyweave.localfirstlab.org` and remove the A record,
otherwise the lineage renews forever for an origin that no longer serves the app.

## What is deliberately not here

No CI runner, no auto-deploy, no push-to-publish, and no script that wraps the steps above
into one command. Nothing in this project may publish itself.

No provider firewall change either. Ports 80 and 443 are already open on this host and
already have a listener; a new public port would need a rule added in the provider console,
and its absence would present as a hang rather than as a refusal.

HTTP/2 is not enabled above, which matches what this host serves today. Turning it on later
is one `http2 on;` line in the server block, on nginx 1.25.1 or newer, and it changes
nothing else in this runbook.
