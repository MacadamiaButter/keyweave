// Vite is not a preference here, it is forced: the vendored decode worker resolves
// `zxing-wasm/reader/zxing_reader.wasm?url`, a bundler-resolved import.
//
// Two build properties are load-bearing and both are security properties, not tidiness:
//   R13: no http(s) origin may survive in dist/. zxing-wasm compiles a jsdelivr CDN
//        into its default locateFile. The worker overrides locateFile before the first
//        decode so nothing reaches that origin at runtime, but a string in the bundle is
//        one library upgrade away from becoming a third-party fetch during a pairing
//        ceremony. stripExternalOrigins() rewrites it to a same-origin path that 404s.
//        The AUTHORITATIVE gate is test/build-no-external-origin.test.ts, which scans the
//        emitted dist/ and fails closed; this plugin is the fix, not the check.
//   No inlined assets. assetsInlineLimit 0 keeps every asset a real file, so the CSP can
//        stay at img-src 'self' with no data: and every byte is hashable out of band.
//
// A third one arrived with the split relay topology (residual R2): the relay origin.
// KEYWEAVE_RELAY_ORIGIN is read ONCE, here, and everything downstream is derived from that
// single value by build-config.mjs. See that file for why (anchor `swisscheese`): the meta
// tag, the response header and the RelayClient base are three layers of one defence, and
// the way they fail is a human editing one of them.

import { defineConfig, type Plugin } from 'vite';
import {
  CSP_PLACEHOLDER,
  RELAY_ORIGIN_DEFINE,
  RELAY_ORIGIN_ENV,
  cspPolicy,
  relayOriginFromEnv,
} from './build-config.mjs';

// The origin prefix, not the whole template literal: the surrounding minified identifiers
// change between zxing-wasm releases, the origin does not.
const CDN_PREFIX = 'https://fastly.jsdelivr.net/npm/';
// A same-origin path that cannot resolve. Chosen over an empty string so a regression is a
// loud 404 with this name in it rather than a silent relative fetch of something real.
const REFUSED_PREFIX = '/keyweave-refuses-external-origin/';

function stripExternalOrigins(): Plugin {
  let hits = 0;
  return {
    name: 'keyweave-strip-external-origins',
    enforce: 'pre',
    transform(code, id) {
      if (!id.includes('zxing-wasm')) return null;
      if (!code.includes(CDN_PREFIX)) return null;
      hits += code.split(CDN_PREFIX).length - 1;
      return { code: code.split(CDN_PREFIX).join(REFUSED_PREFIX), map: null };
    },
    buildEnd() {
      // Not an error: a future zxing-wasm may simply stop shipping the default. The dist
      // scan decides. This line exists so the number is visible in build output.
      this.info(`stripExternalOrigins: rewrote ${hits} CDN origin reference(s)`);
    },
  };
}

/**
 * Fill the CSP placeholder in index.html with the generated policy.
 *
 * This runs in `vite dev` as well as `vite build`, which is the point: the meta tag is how
 * development gets a CSP at all, and a policy only exercised in production is a policy
 * discovered at deploy time. It throws rather than passing the placeholder through, because
 * a page shipped with `content="__KEYWEAVE_CSP__"` has no policy and no symptom.
 */
function injectCsp(policy: string, relayOrigin: string | null): Plugin {
  return {
    name: 'keyweave-inject-csp',
    buildEnd() {
      // Printed so the build log, and therefore scripts/reproduce.sh, records which
      // configuration produced these bytes. The artifact hash depends on it.
      this.info(`${RELAY_ORIGIN_ENV}=${relayOrigin ?? '(unset: same-origin relay)'}`);
    },
    transformIndexHtml: {
      order: 'pre',
      handler(html) {
        if (!html.includes(CSP_PLACEHOLDER)) {
          throw new Error(
            `index.html has no ${CSP_PLACEHOLDER} placeholder; the page would ship with no CSP`,
          );
        }
        return html.split(CSP_PLACEHOLDER).join(policy);
      },
    },
  };
}

// Read once. An invalid value throws here, at config load, so `vite build` exits non-zero
// before anything is emitted rather than shipping an injected directive.
const relayOrigin = relayOriginFromEnv(process.env);
const policy = cspPolicy(relayOrigin);

export default defineConfig({
  plugins: [stripExternalOrigins(), injectCsp(policy, relayOrigin)],
  // The same value the CSP was built from, as a compile-time constant. src/ui/main.ts falls
  // back to location.origin when it is empty, so the default build still names no origin
  // anywhere and test/build-no-external-origin.test.ts still reads zero of them.
  define: {
    [RELAY_ORIGIN_DEFINE]: JSON.stringify(relayOrigin ?? ''),
  },
  // Pre-bundling would hand esbuild's output to the browser without passing through the
  // transform above, so the dev server would keep the CDN string the build strips.
  optimizeDeps: { exclude: ['zxing-wasm'] },
  // Loopback only. A pairing ceremony under development has a camera attached to it.
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  preview: { host: '127.0.0.1', port: 5174, strictPort: true },
  // The decode worker is `new Worker(new URL(...), { type: 'module' })`. Pinning the
  // format keeps Vite from emitting a classic worker wrapped in a blob: URL, which would
  // force blob: into script-src for no gain.
  //
  // worker.plugins is NOT optional here and the reason is worth writing down: in a
  // production build the worker bundle is a SEPARATE rollup build that does not inherit
  // `plugins`. The decoder, and therefore the CDN string, lives only in the worker, so
  // without this line the origin strip runs against a bundle that never contained the
  // origin and reports success. Measured: the first build logged "rewrote 0" and shipped
  // the jsdelivr URL in dist/assets/receive-worker-*.js.
  worker: { format: 'es', plugins: () => [stripExternalOrigins()] },
  build: {
    target: 'es2022',
    // No source maps: a .map is a second artifact the out-of-band hash publication would
    // have to cover, and it embeds local paths.
    sourcemap: false,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    reportCompressedSize: true,
  },
});
