#!/usr/bin/env node
// Print the exact Content-Security-Policy and nginx block for a given relay origin.
//
//   node client/scripts/print-csp.mjs                          same-origin relay (default)
//   node client/scripts/print-csp.mjs https://relay.example    split trust domains (R2)
//
// PASTE FROM THIS, DO NOT RETYPE. The policy is generated from one value by
// client/build-config.mjs and is also what the build puts in the page's meta tag and what
// src/ui/main.ts calls. Retyping the header by hand is how the three stop agreeing, and a
// header that disagrees with the meta tag is a policy nobody can reason about.
//
// Exits 2 on a value the build would refuse, printing the same message the build prints, so
// this is a safe place to find out before a deploy rather than during one.

import { RELAY_ORIGIN_ENV, cspPolicy, nginxCspBlock, normalizeRelayOrigin } from '../build-config.mjs';

const argv = process.argv.slice(2);
if (argv.includes('-h') || argv.includes('--help')) {
  process.stdout.write(
    'usage: node client/scripts/print-csp.mjs [relay-origin]\n' +
      '  no argument   same-origin relay (the default build)\n' +
      '  relay-origin  scheme and host, no path and no trailing slash\n',
  );
  process.exit(0);
}
if (argv.length > 1) {
  process.stderr.write('print-csp: one optional argument, the relay origin\n');
  process.exit(2);
}

let origin;
try {
  origin = normalizeRelayOrigin(argv[0] ?? '');
} catch (error) {
  process.stderr.write(`print-csp: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(2);
}

const build =
  origin === null
    ? 'npm run build'
    : `${RELAY_ORIGIN_ENV}=${origin} npm run build`;

process.stdout.write(
  [
    `# Build command this policy belongs to:`,
    `#   cd client && ${build}`,
    '',
    '# The policy, one line. This is what the build puts in the meta tag.',
    cspPolicy(origin),
    '',
    '# The response header, for the server that serves dist/ (NOT the relay host).',
    nginxCspBlock(origin),
    '',
  ].join('\n'),
);
