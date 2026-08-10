# Vendor provenance: decimen-optical-transfer

| | |
|---|---|
| Upstream | https://github.com/bashalarmistalt/decimen-optical-transfer |
| Pin | `f0c49e92d50366c6867759800dd962b70d840a1a` (tag-less; upstream `main` tip at vendor time) |
| Upstream version at pin | 0.3.0 |
| License | MIT, Copyright (c) 2026 Evan Crawley (Bash Alarmist). Verbatim in `LICENSE` beside this file. |
| Vendored | 2026-08-08 |
| Tracking | NONE. The pin is fixed. A re-vendor is a fresh full-history audit, not a fast-forward. |

The pin was chosen after a full-history review (20 commits, 2026-07-30 to 2026-08-07): no
force-push scars, no orphan objects, no secrets or telemetry, every committed binary a
verified image, one `fetch()` in the whole tree and it is in a file we do not take. Every
line in the subset below is authored by the repository owner. The repository went viral
during the audit (5330 stars, 644 forks) and is now a magnet for drive-by pull requests
from accounts with no history in it, which is the reason the pin is hard rather than a
floating branch.

## Files taken

All eight files are byte-identical to upstream except where the "Local modifications"
section says otherwise.

Line counts are of the VENDORED file as it stands here (upstream length plus whatever the
"Local modifications" section records), so a re-derivation can diff them directly.

| vendored file | upstream path | lines |
|---|---|---|
| `fountain.ts` | `shared/fountain.ts` | 288 |
| `frame.ts` | `shared/protocol.ts` (SPLIT, see below) | 154 |
| `qr-raster.ts` | `shared/qr-raster.ts` | 36 |
| `frame-capacity.ts` | `shared/frame-capacity.ts` | 49 |
| `platform.ts` | `shared/platform.ts` | 62 |
| `worker-pool.ts` | `shared/worker-pool.ts` | 70 |
| `receive-worker.ts` | `receive/worker.ts` | 36 |
| `wasm-url.ts` | `receive/wasm-url.ts` (served variant, not `wasm-url.inline.ts`) | 5 |
| `LICENSE` | `LICENSE` | 21 |

sha256 of the upstream originals at the pin:

```
9a870b9184904abc  shared/fountain.ts
45ace98d26a73cde  shared/protocol.ts        (the file frame.ts is split from)
f71eb3f4a01ef3d5  shared/qr-raster.ts
0b1dfc0c978d225d  shared/frame-capacity.ts
0f9d49de61f461e2  shared/platform.ts
4db12890e0a5effd  shared/worker-pool.ts
10d7db59472f4e7e  receive/worker.ts
cc4d29bbefcd64fc  receive/wasm-url.ts
b4c142c56e708391  LICENSE
```

## Files deliberately NOT taken

- `send/main.ts`, `receive/main.ts`, `home/main.ts` and every `index.html`: application
  shells. Keyweave vendors the codec, not the app.
- `shared/protocol.ts` lines 33-270: the whole "DCF2" file container. See the split below.
- `build/license-banner.ts`: it stamps `SPDX-License-Identifier: MIT` on every built
  artifact while the bundle ships an Apache-2.0-derived 940 KB wasm with no Apache notice.
  That is the exact mistake Keyweave refuses; see the repo NOTICE.
- `vite.config.ts` and the rest of `build/`, `vite-plugin-pwa` (350 transitive packages, a
  service worker, and a Cache API store that persists received bytes across page close),
  `shared/` UI helpers, `public/`, `docs/`.
- Upstream's tests. Keyweave writes its own: `client/test/optical.test.ts` and
  `client/test/optical-patent-invariant.test.ts`.
- Upstream pull request #27 (a header-bounds fix). Its test shapes informed ours; its code
  did not. It comes from an account with no other history in the repository and its
  ceiling is upstream's 64 MB, which is four orders of magnitude past anything Keyweave
  transports.

## Local modifications

Five, all listed. Nothing else in these files differs from upstream by a byte.

### 1. `shared/protocol.ts` was SPLIT into `frame.ts`

Upstream fuses two unrelated layers into one module. `frame.ts` keeps upstream lines
**1-13** (the wire-layout comment), **15** (`HEADER_LEN`), **27-28** (`MAGIC0`, `MAGIC1`)
and **272-353** (`FrameHeader`, `packFrame`, `parseFrame`, `streamIdentity`, `fnv1a`,
`splitmix32`), all verbatim. Everything else is dropped:

- **Lines 33-270, the DCF2 file container**, and with it the entire compression surface:
  `CompressionMode`, `gzipAsync`, `gunzipAsync`, `isPrecompressedType`,
  `PRECOMPRESSED_TYPES`, `packFile`, `unpackFile`, `verifyFile`, `digest`
  (`crypto.subtle`), `safeFileName`, `TextEncoder`/`TextDecoder`.
  `DecompressionStream` reading attacker-supplied bytes off a camera is the
  decompression-bomb class; Keyweave's payload is a small signed CBOR card that gzip
  could not usefully shrink anyway. The property is now "this build cannot decompress
  scanned input", provable with a grep, rather than "its bomb guard looks correct".
- **Line 16 `MAX_FILE_BYTES`** and **line 25 `MAX_FILE_LABEL`**: the container's 64 MB
  ceiling and its UI label. Both are dead once the container is gone, and leaving a 64 MB
  constant next to Keyweave's 16 KB cap would only invite confusion.
- **Lines 26 and 29, `FILE_HEADER_LEN` and `FILE_MAGIC`** (the `DCF2` magic): container
  constants, unused by the frame layer.

A Keyweave header block was prepended saying all of the above. Upstream comment text is
preserved verbatim throughout, em dashes included: `client/vendor/decimen/**` is exempt
from the repo's public-text gate, because mangling a third party's comments to satisfy a
house style is the wrong trade for the most valuable part of this codebase.

### 2. Header caps added to `frame.ts` `parseFrame()`

Marked in-file as `KEYWEAVE HARDENING`. Upstream issue #1 (open at the pin, acknowledged
by the maintainer on 2026-07-31, unfixed through the v0.3.0 release) reports that
`parseFrame` validates only magic, non-zero fields and self-consistent frame length, so
`k` (u16) and `totalLen` (u32) are attacker-chosen. A single 28-byte frame declaring
`k=1, blockLen=8, totalLen=256MB` drives a 256 MB zero-fill in `LTDecoder.assemble()`
plus a full-length `fnv1a` pass over it, from one scanned QR; the u32 ceiling is 4 GB.

The only ceiling upstream had was `MAX_FILE_BYTES` inside `unpackFile()`, i.e. in the
container this vendor drop deletes. **Vendoring the frame layer without adding caps would
be strictly worse than upstream**, which is why they land in the same change as the
vendor drop rather than as a follow-up.

Added, after upstream's own checks:

```
k        <= MAX_K          (32)
blockLen <= MAX_BLOCK_LEN  (2953, QR V40 / ECC-L byte capacity)
totalLen <= MAX_TOTAL_LEN  (16384)
(k-1) * blockLen < totalLen <= k * blockLen
```

The numbers are Keyweave's. The transport carries exactly one signed contact card, which
is about 150 bytes today, so 16 KB is generous headroom rather than a guess at a file
size. The arithmetic invariant is the only relation a real encoder can produce, since
`k = ceil(totalLen / blockLen)`. Ceilings are checked before the products so the products
cannot leave the safe-integer range.

These are one of **two independent walls against a hostile frame**. The other is
`headerRefusal()` in `client/src/optical.ts`, written separately and applied before the
receiver constructs any decoder, so a parser regression cannot silently disarm the decoder
guard, nor the reverse. The three constants are shared deliberately: a cap edit should move
both walls. Both walls have negative controls in `client/test/optical.test.ts`.

What these two walls do NOT cover, stated precisely: they run only on the path through
`OpticalReceiver.feed()`. `headerRefusal()` is an exported free function a caller has to
choose to call, and `parseFrame()` is not on the path of a caller that builds a decoder
itself, so neither bounds `new LTDecoder(...)`. That is what modification 4 is for.

### 3. `fountain.ts` line 18: import repointed

`import { splitmix32 } from "./protocol";` becomes
`import { MAX_BLOCK_LEN, MAX_K, MAX_TOTAL_LEN, splitmix32 } from "./frame";`. The repoint
is the cross-boundary reference the split had to sever; the three constants are pulled in
for modification 4 rather than re-declared, so one cap edit still moves every wall.

### 4. `fountain.ts` `LTDecoder` constructor: the same three ceilings

Marked in-file as `KEYWEAVE HARDENING`. `k`, `blockLen` and `totalLen` are range-checked in
the constructor and an out-of-range value throws a `RangeError`. Upstream issue #1's proof
of concept is a direct construction, not a frame:

```
new LTDecoder(1, 8, 1, 256 * 1024 * 1024).assemble()  // 268435456 bytes, upstream and
                                                       // in this tree before this change
```

This bounds the class itself, so the sentence "a caller that reaches `LTDecoder` without
passing through `parseFrame` is still bounded" is true rather than aspirational. It matters
because the browser UI work package imports from this directory (`worker-pool.ts`,
`receive-worker.ts`, `qr-raster.ts` are vendored for it) and may reasonably wire a decoder
itself.

Ceilings only: the `(k-1)*blockLen < totalLen <= k*blockLen` relation is a statement about
a header, not about a decoder, and stays with the two frame walls. The check is unreachable
from `OpticalReceiver`, which enforces the identical three ceilings first; the regression
test constructs the decoder directly (`client/test/optical.test.ts`).

### 5. `frame-capacity.ts` line 9: import repointed

`import { HEADER_LEN } from "./protocol";` becomes `from "./frame"`. No other change.
(Its `smallestSufficientFrameSize` doc comment still mentions `MAX_FILE_BYTES`, which no
longer exists here. Left verbatim rather than edited: it is upstream prose about upstream's
own sizing, and Keyweave does not call that function.)

Note `wasm-url.ts` is not on the brief's file list but is vendored anyway: `receive-worker.ts`
imports it, and taking the worker without it would leave a dangling import. The served
variant was taken; upstream's `wasm-url.inline.ts` (a `virtual:` module supplied by one of
their Vite plugins) was not.

## Typecheck scope

`client/tsconfig.json` (`npx tsc --noEmit`) covers `src/`, which now reaches SEVEN of the
eight vendored TypeScript files: `frame.ts`, `fountain.ts` and `frame-capacity.ts` through
`src/optical.ts`, and `qr-raster.ts`, `platform.ts` and `worker-pool.ts` through
`src/ui/qr-display.ts` and `src/ui/camera.ts` since the browser work package landed.
`client/tsconfig.vendor.json` still names those last three explicitly. It is now redundant
rather than wrong, and is kept so that removing a UI import cannot silently drop a vendored
file out of every typecheck scope.

`receive-worker.ts` and `wasm-url.ts` are in neither `tsc` scope: they resolve
`zxing-wasm/reader/zxing_reader.wasm?url`, a bundler-time import that `tsc` cannot resolve
without `vite/client` ambient types. They are checked by the bundler: `npm run build`
compiles `receive-worker.ts` into its own ES-module chunk, and
`client/test/build-no-external-origin.test.ts` asserts that chunk exists and references the
emitted wasm by a same-origin path.

## Runtime dependencies this vendor drop brings in

Both pinned to the versions decimen's lockfile resolves at `f0c49e9`, installed with
`--save-exact`:

- `zxing-wasm@2.2.4` (MIT wrapper, Apache-2.0 wasm) for decode. Three transitive
  dependencies, all types-only, zero runtime bytes.
- `qrcode@1.5.4` (MIT) for QR symbol generation on the sender side. One runtime
  transitive dependency reaches the browser entry, `dijkstrajs@1.0.3` (MIT); the
  `yargs` chain is the CLI and `pngjs` is the Node renderer, neither of which resolves in
  a browser build.

Attribution obligations are recorded in the repository `NOTICE`, with the full Apache-2.0
text at `LICENSES/Apache-2.0.txt`.

**Both are installed one work package AHEAD of their consumers, deliberately.** Nothing in
this drop imports either one: `qrcode` renders the QR symbol and `zxing-wasm` decodes it,
and both of those calls live in the browser UI. They are pinned here so the pin comes from
decimen's own lockfile at `f0c49e9` rather than from whatever is current when the UI is
written, which is the point of pinning at all. The same reasoning covers the five vendored
but currently unimported files (`qr-raster`, `platform`, `worker-pool`, `receive-worker`,
`wasm-url`). If the UI work package ends up not needing one of them, remove it then; do not
read an unused runtime dependency here as an accident. `@types/qrcode` is deliberately NOT
installed yet because it is types-only and has no pinning argument behind it.

## Carried residual risk, named

This is an eight-day-old codebase from a single pseudonymous author with no external
security review, and its one publicly reported vulnerability is open at our pin. The
mitigation is the vendor posture itself: about 670 lines read line by line, two runtime
packages, no app shell, no service worker, no compression, hard caps at the parser, again
at the receiver and again in the decoder constructor, and an Ed25519 signature over the
payload that makes the codec's own integrity story irrelevant to correctness.

Two conditions from the pre-vendor audit were left to the browser UI work package. **Both
were discharged on 2026-08-08**, and both are recorded here because the vendored files are
where the next person will look:

- A jsdelivr CDN URL is compiled into zxing-wasm's default `locateFile`. Nothing reaches it
  while `prepareZXingModule({ overrides: { locateFile } })` runs at worker module scope
  before the first `readBarcodes`, which `receive-worker.ts` does. The build now also
  strips the string: `client/vite.config.ts` rewrites the origin to a same-origin path that
  cannot resolve, and `client/test/build-no-external-origin.test.ts` shells the build and
  asserts no `http(s)://` origin survives anywhere in `dist/`. The CSP (with
  `'wasm-unsafe-eval'`, without which the decoder silently never starts) ships in
  `client/index.html` and is documented as a response header in `docs/DEPLOY-CSP.md`.
  Residual R13 is closed and the reasoning is written up there.
  **Note for a re-vendor:** the strip plugin has to be listed under Vite's `worker.plugins`
  as well as `plugins`. A production worker bundle is a separate rollup build that does not
  inherit the top-level plugin list, and the decoder lives only in the worker, so the first
  attempt reported success while shipping the URL.
- The camera-layer quirks upstream encodes in `receive/main.ts` are ported into
  `client/src/ui/camera.ts`: the frame-rate negotiation (as an exact-then-ideal-then-neither
  attempt rather than upstream's iOS branch, so no user-agent string is involved), reading
  `track.getSettings()` back and surfacing the delta, the `requestVideoFrameCallback`
  generation counter, treating a refused live `applyConstraints` as a note rather than a
  failure, capability probing through this drop's `platform.ts`, dropping frames when the
  pool is busy, `willReadFrequently`, and leaving torch probed but unused.
