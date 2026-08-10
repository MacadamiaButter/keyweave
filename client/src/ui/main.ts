// Entry point. Kept to wiring so index.html can hold no inline script at all: an inline
// script would need 'unsafe-inline' or a nonce in the CSP, and a nonce needs a server that
// generates one per response, which is a server this application deliberately does not
// have.

import { KeyweaveApp } from './app.js';
import { RelayClient } from '../relay-client.js';
import { createBlobStore } from './storage.js';
import { createVaultCrypto } from './vault-client.js';

// WHERE THE RELAY IS. One value, chosen at build time by KEYWEAVE_RELAY_ORIGIN and
// substituted here by vite's `define` (see ../../build-config.mjs). Empty means SAME
// ORIGIN, which is the default and the dev behaviour, and in that case the constant folds
// away so no origin string exists anywhere in dist/.
//
// swisscheese: the SAME value put this origin into `connect-src` in the page's CSP and into
// the response header docs/DEPLOY-CSP.md publishes. Hard-coding a different one here would
// give a client that calls an origin its own policy forbids, which fails as a network error
// with no explanation of the real cause. Nothing in src/ names an origin; this constant is
// the only channel.
declare const __KEYWEAVE_RELAY_ORIGIN__: string;
const relayBase = __KEYWEAVE_RELAY_ORIGIN__ || location.origin;

const app = new KeyweaveApp({
  crypto: createVaultCrypto(),
  store: createBlobStore(),
  relay: new RelayClient({
    baseUrl: new URL('/', relayBase).href,
    fetch: (input, init) => fetch(input, init as RequestInit),
  }),
});

void app.start().catch((error: unknown) => {
  // Nothing has been unlocked at this point, so the honest thing is a plain message rather
  // than a screen that implies a working session.
  const screens = document.getElementById('screens');
  if (!screens) return;
  const paragraph = document.createElement('p');
  paragraph.className = 'error';
  paragraph.textContent = `Keyweave could not start: ${
    error instanceof Error ? error.message : String(error)
  }`;
  screens.replaceChildren(paragraph);
});
