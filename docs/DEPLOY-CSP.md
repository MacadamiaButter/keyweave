# The Content-Security-Policy Keyweave ships

R13 has two halves and both fail silently, which is why they are written down rather than
left to whoever runs the deploy.

## The policy is GENERATED, from one value

Three things have to agree about where the relay is: the `<meta http-equiv>` in
`client/index.html`, the response header the app host sends, and the base URL
`RelayClient` is constructed with in `client/src/ui/main.ts`. Each is a real defence. The
way they fail is not one of them being weak, it is a person changing one and not the other
two, so all three are derived from a single build-time value:

    KEYWEAVE_RELAY_ORIGIN

| value | meaning |
|---|---|
| unset, or empty | the relay is on the SAME ORIGIN as the app. This is the default and the development behaviour. |
| an origin, e.g. `https://relay.keyweave.localfirstlab.org` | the split trust domains `DEPLOY.md` recommends (residual R2). The origin is added to `connect-src` and compiled into the client. |

The value must be scheme and host only: no path, no trailing slash, no query, no fragment,
no credentials, no space, no quote, no semicolon, and `http` or `https` only. Anything else
ABORTS the build with a message naming what was wrong. That is not tidiness. The value is
interpolated into a policy string, and `https://x.example; script-src 'unsafe-inline'` as
an environment variable would otherwise ship a page whose CSP carries an extra directive
nobody wrote, and the page would look and behave perfectly.

**The host itself must be a host, and that is a separate rule from the one above.** Exactly
three shapes are accepted:

| shape | example |
|---|---|
| a dotted DNS name of letters, digits and inner hyphens | `https://relay.example`, `https://relay.example:8443`, `https://xn--e1afmkfd.xn--p1ai` |
| a dotted-quad IPv4 literal | `https://127.0.0.1:8151` |
| a bracketed IPv6 literal | `https://[::1]:8443` |

Everything else is refused, and the case that matters is `https://*`. It parses as a URL,
its `origin` is byte-identical to what was typed, and it would have produced
`connect-src 'self' https://*`: permission to connect to any https origin at all, which is
the exact opposite of what this variable exists to express. `https://*.example.com`,
`https://ex*mple.com`, `https://exa_mple.com`, `https://-lead.example` and `https://exa..mple`
all parse the same way and are all refused for the same reason. A single-label host such as
`https://localhost` is refused too; use the loopback address if that is what you meant.
`client/test/build-config.test.ts` is the table, and
`client/test/build-no-external-origin.test.ts` shells a real build for each refusal, because
the property that matters is that the BUILD stops, not that a function returns false.

Derivation lives in `client/build-config.mjs`, which `client/vite.config.ts`, the test suite
and the CLI below all import. There is no second copy.

### Print the exact strings for a deployment

```sh
node client/scripts/print-csp.mjs                          # same-origin relay
node client/scripts/print-csp.mjs https://relay.example    # split trust domains
```

**Paste from that, do not retype it.** It prints the policy and the nginx block for the
origin you give it, and it refuses the same values the build refuses, with the same message,
so it is a safe place to find out before a deploy rather than during one.

## The default policy, character for character

`KEYWEAVE_RELAY_ORIGIN` unset:

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; img-src 'self'; media-src 'self' mediastream:; style-src 'self'; font-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

`KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org`:

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self' https://relay.keyweave.localfirstlab.org; img-src 'self'; media-src 'self' mediastream:; style-src 'self'; font-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

One directive differs and one source is added. Nothing else moves, and that is asserted
rather than promised.

Two tests hold this together and they ask different questions, deliberately:

- `client/test/build-no-external-origin.test.ts` builds BOTH configurations and asserts the
  emitted meta tag against a hardcoded literal. It does not import the generator, so a bug
  in the generator cannot also rewrite the oracle that should catch it.
- `client/test/deploy-csp-verifier.test.ts` asserts that the blocks in THIS DOCUMENT are
  byte-identical to what the generator produces, so hand-editing this file fails the suite
  instead of quietly disagreeing with the artifact.

## Why each directive is what it is

| directive | value | reason |
|---|---|---|
| `default-src` | `'none'` | Everything is denied unless it is named below. |
| `script-src` | `'self' 'wasm-unsafe-eval'` | **`'wasm-unsafe-eval'` is load-bearing.** Without it `WebAssembly.instantiate` is blocked, the zxing decoder never starts, and there is no error a UI would surface: the camera runs and no code is ever read. |
| `worker-src` | `'self'` | Two ES-module workers (QR decode, Argon2id), both emitted to `/assets` and both same-origin. |
| `connect-src` | `'self'`, plus the relay origin when there is one | Two fetches exist: emscripten pulling the same-origin `.wasm` asset, and the mailbox relay. `'self'` covers the first and, in the same-origin topology, the second. A split relay adds EXACTLY ONE origin here and nothing else, from `KEYWEAVE_RELAY_ORIGIN`. |
| `img-src` | `'self'` | No `<img>` at all today. Assets are never inlined, so no `data:` is needed. |
| `media-src` | `'self' mediastream:` | The camera preview is a `MediaStream` assigned to `srcObject`. Assigning `srcObject` is not a fetch, so this is belt and braces. |
| `style-src` | `'self'` | One emitted stylesheet. No inline `<style>`, no `style=` attributes. Note that `element.style.foo = ...` is CSSOM and is not governed by this. |
| `font-src` | `'none'` | Redundant under `default-src 'none'` and written out anyway: "Keyweave fetches no webfont" is a security property. A font request during a pairing ceremony is a third-party beacon. |
| `base-uri` | `'none'` | Does not fall back to `default-src`. Stops an injected `<base>` from repointing every relative URL. |
| `form-action` | `'none'` | Does not fall back to `default-src`. There is no form target; the unlock form is handled in JavaScript. |
| `frame-ancestors` | `'none'` | Does not fall back to `default-src`. **Ignored in a meta tag by specification**, so the header below is the only place it takes effect. |

Not present, deliberately: `'unsafe-inline'`, `'unsafe-eval'`, any `data:`, any `blob:`,
any external origin. `blob:` was in the starting draft for `script-src` and `worker-src`
and was removed on evidence: the built bundle contains no `createObjectURL` anywhere, so
nothing can load a blob URL. The build test asserts that, so the tightening defends itself.

## The response header

The same string, sent by whatever serves `dist/`. It must be the header for the SAME value
the bundle was built with, which is why both are printed by one command.

Keep it, and every other header line, under about 100 characters per SOURCE line: a long
`add_header` line pasted into a terminal can wrap into a real newline inside the quoted
string, `nginx -t` accepts a multi-line quoted string, and the breakage only appears at the
HTTP layer as `curl: (8) Header without colon`. That happened once on another property. The
generator builds the value from short pieces and refuses to emit a line over 100 characters,
including its own comments: a wrapped comment puts its tail at column zero as a directive,
which is the same failure one step further from its cause.

Same-origin relay (`KEYWEAVE_RELAY_ORIGIN` unset):

```nginx
# In the server block for the APP origin. Never the relay: residual R2.
# Generated for a SAME-ORIGIN relay (KEYWEAVE_RELAY_ORIGIN unset at build time).
# Generated by client/scripts/print-csp.mjs. Paste it, do not retype it.
set $csp_a "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self';";
set $csp_b " connect-src 'self'; img-src 'self'; media-src 'self' mediastream:;";
set $csp_c " style-src 'self'; font-src 'none'; base-uri 'none'; form-action 'none';";
set $csp_d " frame-ancestors 'none'";
add_header Content-Security-Policy "$csp_a$csp_b$csp_c$csp_d" always;

add_header Referrer-Policy "no-referrer" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Permissions-Policy "camera=(self), microphone=(), geolocation=()" always;
```

Split trust domains, `KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org`:

```nginx
# In the server block for the APP origin. Never the relay: residual R2.
# Generated for KEYWEAVE_RELAY_ORIGIN=https://relay.keyweave.localfirstlab.org
# Generated by client/scripts/print-csp.mjs. Paste it, do not retype it.
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
```

Both blocks above are generated output, asserted byte-for-byte by
`client/test/deploy-csp-verifier.test.ts`. If your relay origin is a third one, run the CLI
and paste what it prints; the chunk boundaries move with the length of the origin, which is
the sort of edit that is easy to get subtly wrong by hand.

Neither block belongs on the relay host. The relay sends its own CORS headers and no CSP,
and it is a different server block on a different machine: see `DEPLOY.md`.

`Permissions-Policy` has to allow `camera` for the origin itself. A deploy that copies a
hardened default with `camera=()` turns the scan step into a permission denial with no
explanation. The microphone is never requested and is denied explicitly.

Verify after reload, with the assertion inside the paste rather than after it:

```sh
curl -sI https://<app-origin>/ | grep -ci "^content-security-policy:.*wasm-unsafe-eval"
```

That must print `1`. `0` means either the header is missing or it wrapped.

No `$` anchor, and the omission is the point. `script-src` is the second of eleven
directives, so the line does not END at `wasm-unsafe-eval`; it ends at
`frame-ancestors 'none'`, with a CR after that. The anchored version of this check printed
`0` for a CORRECTLY deployed header, which is worse than no check at all: the move that
follows a `0` on a working deploy is either changing a configuration that was right, or
deleting the gate.

What the unanchored form does answer, and what it does not:

- header missing: no line matches, `0`;
- value broken by a paste wrap: curl refuses the response with `curl: (8) Header without
  colon`, stdout is empty, `0`;
- break landing before `wasm-unsafe-eval` in a response curl still accepts: the header line
  no longer carries the token, `0`;
- break landing after the token in a response curl still accepts: `1`. This is a check that
  the load-bearing directive arrived, not a header parser, and reading the `curl -sI` output
  once by eye is still worth doing.

`client/test/deploy-csp-verifier.test.ts` extracts this exact command from this document and
runs it against those inputs, so the gate cannot rot back into an inverted one.

## In development

`index.html` carries a `__KEYWEAVE_CSP__` placeholder, and vite substitutes the generated
policy in `vite dev` exactly as it does in a production build. So `npm run dev` runs under
the real policy, which is the point: a policy only exercised in production is a policy
discovered at deploy time. Do not paste a policy into `index.html` by hand. The build throws
if the placeholder is missing, because a page served with `content="__KEYWEAVE_CSP__"` has
no policy and no symptom, and the dist scan checks that no placeholder ever reaches `dist/`.

Two dev-only consequences, both cosmetic and neither worth loosening the shipped policy for:

- Vite's HMR client opens a same-origin WebSocket. `connect-src 'self'` permits it.
- Vite's error overlay injects styles, which `style-src 'self'` blocks. The overlay is
  degraded in dev; the terminal still prints the error.

Opening `client/index.html` as a `file://` URL is the one path with no CSP at all, because
nothing substitutes the placeholder. That is not a supported way to run Keyweave.

## The relay side, which this policy does not cover

`connect-src` is the browser asking permission to send. The relay separately has to agree to
answer, and with split origins a `PUT` carrying `Authorization` and
`Content-Type: application/octet-stream` is a preflighted request: neither header is
CORS-safelisted, so the browser sends `OPTIONS` first and does not send the `PUT` at all
unless that answer allows both. The relay does this already (`do_OPTIONS` in
`relay/keyweave_relay.py`); what it needs from the operator is `allowed_origins` set to the
APP origin, exactly, in `relay.conf`. See `DEPLOY.md` step 1. A `connect-src` that permits
the relay while the relay's allowlist does not name the app is a working policy in front of
a blocked request, and the browser reports it as a CORS error rather than as a
configuration mismatch.

## What the CSP does not do

It is a mitigation for residual R1, not an answer to it. A compromised origin serves its
own CSP alongside its own JavaScript. The policy raises the cost of an injection into an
otherwise honest bundle; it does nothing against a server that is lying on purpose. That is
what the out-of-band published build hashes are for: `docs/REPRODUCIBLE-BUILD.md`, which as
of this work package also has to state the `KEYWEAVE_RELAY_ORIGIN` a release was built with,
since the artifact hash depends on it.
