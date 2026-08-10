// The relay client against a relay that lies (test/hostile-relay.ts).
//
// Every assertion here is of the form "the relay did X, and the client did not break". The
// bar is not that the operation succeeded: for most of these it must NOT succeed. It is that
// the failure is bounded, named, and attributable to the relay.

import { describe, it, expect } from 'vitest';
import {
  BLOB_ID_RE,
  MAILBOX_ID_RE,
  MAX_RESPONSE_BYTES,
  RelayClient,
  RelayError,
} from '../src/relay-client.js';
import { HostileRelay } from './hostile-relay.js';

const BASE = 'https://relay.test/';

function client(relay: HostileRelay, timeoutMs = 250): RelayClient {
  return new RelayClient({ baseUrl: BASE, fetch: relay.fetch, timeoutMs });
}

async function failureOf(work: () => Promise<unknown>): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof RelayError) return error.failure;
    return `not-a-relay-error: ${String(error)}`;
  }
  return 'no-failure';
}

describe('the honest path, so the hostile ones are measured against something', () => {
  it('creates, puts, lists and pulls, with delete-on-pull', async () => {
    const relay = new HostileRelay();
    const api = client(relay);

    const box = await api.createMailbox();
    expect(box.mailboxId).toMatch(MAILBOX_ID_RE);

    const put = await api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([1, 2, 3]));
    expect(put.blobId).toMatch(BLOB_ID_RE);
    expect(put.size).toBe(3);

    const listed = await api.listBlobs(box.mailboxId, box.pullToken);
    expect(listed.map((b) => b.blobId)).toEqual([put.blobId]);

    const bytes = await api.pullBlob(box.mailboxId, put.blobId, box.pullToken);
    expect([...(bytes ?? [])]).toEqual([1, 2, 3]);
    // Gone, exactly once (R9).
    expect(await api.pullBlob(box.mailboxId, put.blobId, box.pullToken)).toBeNull();
    expect(await api.listBlobs(box.mailboxId, box.pullToken)).toEqual([]);
  });

  it('never puts a capability in a URL, sends no credentials, and refuses redirects', async () => {
    const relay = new HostileRelay();
    const api = client(relay);
    const box = await api.createMailbox();
    await api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([7]));
    await api.listBlobs(box.mailboxId, box.pullToken);

    expect(relay.calls.length).toBeGreaterThanOrEqual(3);
    for (const call of relay.calls) {
      expect(call.url).not.toContain(box.writeCap);
      expect(call.url).not.toContain(box.pullToken);
      expect(call.credentials).toBe('omit');
      expect(call.redirect).toBe('error');
      expect(call.cache).toBe('no-store');
    }
    // The tokens went somewhere, so this is not passing because nothing was sent.
    expect(relay.calls.some((c) => c.authorization === `Bearer ${box.pullToken}`)).toBe(true);
  });
});

describe('wall 1: the response size ceiling, enforced while reading', () => {
  it('refuses a body that streams past the ceiling with no Content-Length to warn it', async () => {
    const relay = new HostileRelay();
    const api = new RelayClient({
      baseUrl: BASE,
      fetch: relay.fetch,
      timeoutMs: 5_000,
      maxResponseBytes: 64 * 1024,
    });
    const box = await api.createMailbox();
    const put = await api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([1]));

    // 8 MiB, streamed, headers silent. Only the counter on the read can stop this.
    relay.lies.oversizeBytes = 8 * 1024 * 1024;
    expect(await failureOf(() => api.pullBlob(box.mailboxId, put.blobId, box.pullToken))).toBe(
      'oversize',
    );
  });

  it('refuses on the DECLARED length before reading a byte, when the relay declares one', async () => {
    const relay = new HostileRelay();
    const api = client(relay, 5_000);
    const box = await api.createMailbox();
    const put = await api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([1]));

    relay.lies.oversizeBytes = 1024;
    relay.lies.declaredLength = MAX_RESPONSE_BYTES + 1;
    expect(await failureOf(() => api.pullBlob(box.mailboxId, put.blobId, box.pullToken))).toBe(
      'oversize',
    );
  });

  it('a Content-Length that lies LOW does not buy the relay a bigger buffer', async () => {
    // Negative control for the check above: if the ceiling were implemented from the header,
    // declaring 10 bytes and streaming 8 MiB would sail straight through.
    const relay = new HostileRelay();
    const api = new RelayClient({
      baseUrl: BASE,
      fetch: relay.fetch,
      timeoutMs: 5_000,
      maxResponseBytes: 64 * 1024,
    });
    const box = await api.createMailbox();
    const put = await api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([1]));

    relay.lies.oversizeBytes = 8 * 1024 * 1024;
    relay.lies.declaredLength = 10;
    expect(await failureOf(() => api.pullBlob(box.mailboxId, put.blobId, box.pullToken))).toBe(
      'oversize',
    );
  });

  it('a body just under the ceiling is still returned in full', async () => {
    const relay = new HostileRelay();
    const api = new RelayClient({
      baseUrl: BASE,
      fetch: relay.fetch,
      timeoutMs: 5_000,
      maxResponseBytes: 128 * 1024,
    });
    const box = await api.createMailbox();
    const put = await api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([1]));
    relay.lies.oversizeBytes = 96 * 1024;
    const bytes = await api.pullBlob(box.mailboxId, put.blobId, box.pullToken);
    expect(bytes?.length).toBe(96 * 1024);
  });
});

describe('wall 2: strict validation of every relay-supplied string', () => {
  it('a mailbox id that is not 32 lowercase hex is refused at create', async () => {
    for (const bad of [
      '../../etc/passwd',
      '0123456789abcdef0123456789abcdeF', // one uppercase
      '0123456789abcdef0123456789abcde', // 31
      '0123456789abcdef0123456789abcdef0', // 33
      '',
      '0123456789abcdef0123456789abcdef ',
    ]) {
      const relay = new HostileRelay();
      relay.lies.fakeMailboxId = bad;
      expect(await failureOf(() => client(relay).createMailbox()), bad).toBe('malformed');
    }
  });

  it('a mailbox id carrying path traversal never reaches a URL', async () => {
    const relay = new HostileRelay();
    relay.lies.fakeMailboxId = '../../../v1/mailboxes/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const api = client(relay);
    expect(await failureOf(() => api.createMailbox())).toBe('malformed');

    // And directly, in case a caller ever holds one from somewhere other than create.
    const calls = relay.calls.length;
    expect(
      await failureOf(() => api.listBlobs('../../../v1/mailboxes/x', 'a'.repeat(20))),
    ).toBe('malformed');
    // Refused BEFORE the wire, which is the property that matters.
    expect(relay.calls.length).toBe(calls);
  });

  it('a newline inside an otherwise well-shaped id is refused as a class', async () => {
    const relay = new HostileRelay();
    const api = client(relay);
    const withNewline = `0123456789abcdef0123456789abcdef\n`;
    expect(await failureOf(() => api.listBlobs(withNewline, 'a'.repeat(20)))).toBe('malformed');
    expect(relay.calls.length).toBe(0);
  });

  it('a capability token with a control character never becomes a header', async () => {
    const relay = new HostileRelay();
    const api = client(relay);
    const box = await api.createMailbox();
    const calls = relay.calls.length;
    expect(
      await failureOf(() =>
        api.listBlobs(box.mailboxId, `token\r\nX-Injected: yes${'a'.repeat(20)}`),
      ),
    ).toBe('malformed');
    expect(relay.calls.length).toBe(calls);
  });

  it('a capability the relay minted badly is refused at create', async () => {
    const relay = new HostileRelay();
    relay.lies.fakeCap = 'short';
    expect(await failureOf(() => client(relay).createMailbox())).toBe('malformed');
  });

  it('a blob id that fails validation is dropped from a list rather than failing it', async () => {
    // One bad entry must not stop delivery of the good ones, or the relay gets a way to
    // block a mailbox forever by appending a single malformed id.
    const relay = new HostileRelay();
    const api = client(relay);
    const box = await api.createMailbox();
    const good = await api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([9]));

    const honest = relay.fetch;
    const spliced = new HostileRelay();
    spliced.lies = relay.lies;
    // Splice one hostile entry into the real list response.
    const api2 = new RelayClient({
      baseUrl: BASE,
      timeoutMs: 250,
      fetch: async (url, init) => {
        const res = await honest(url, init);
        if (!url.endsWith('/blobs') || init.method !== 'GET') return res;
        const body = JSON.parse(await res.text()) as { blobs: unknown[] };
        body.blobs.unshift({ blob_id: '../../../etc/passwd', size: 1 });
        body.blobs.push({ blob_id: 'bl-not-a-timestamp.zzzz', size: 1 });
        return new Response(new TextEncoder().encode(JSON.stringify(body)), { status: 200 });
      },
    });
    const listed = await api2.listBlobs(box.mailboxId, box.pullToken);
    expect(listed.map((b) => b.blobId)).toEqual([good.blobId]);
  });

  it('a blob id the relay invents for a PUT is refused', async () => {
    const relay = new HostileRelay();
    relay.lies.fakeBlobId = 'bl-../../secret.000000000000';
    const api = client(relay);
    const box = await api.createMailbox();
    expect(
      await failureOf(() => api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([1]))),
    ).toBe('malformed');
  });
});

describe('wall 3: no redirects', () => {
  it('a fetch that rejects on redirect is a named network failure', async () => {
    const relay = new HostileRelay();
    relay.lies.redirect = 'throw';
    expect(await failureOf(() => client(relay).createMailbox())).toBe('network');
  });

  it('a runtime that FOLLOWED a redirect is still refused', async () => {
    // Belt and braces behind redirect: 'error'. A stub, a polyfill or a future runtime that
    // resolves a redirect instead of rejecting must not get a pass.
    const relay = new HostileRelay();
    relay.lies.redirect = 'followed';
    const api = client(relay);
    expect(await failureOf(() => api.listBlobs('0'.repeat(32), 'a'.repeat(20)))).toBe('network');
  });
});

describe('wall 4: deadlines', () => {
  it('a relay that never answers fails as a timeout, not a hang', async () => {
    const relay = new HostileRelay();
    relay.lies.hang = true;
    const started = Date.now();
    expect(await failureOf(() => client(relay, 120).createMailbox())).toBe('timeout');
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it('a relay that answers the headers and then trickles the body forever also times out', async () => {
    // The deadline has to cover the BODY. A relay that resolves the fetch promptly and then
    // sends one byte every 40 ms has hung the interface just as thoroughly, and neither the
    // size ceiling nor a handshake timeout would ever fire on it.
    const relay = new HostileRelay();
    const api = client(relay, 150);
    const box = await api.createMailbox();
    const put = await api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([1]));
    relay.lies.trickleForever = true;
    const started = Date.now();
    expect(await failureOf(() => api.pullBlob(box.mailboxId, put.blobId, box.pullToken))).toBe(
      'timeout',
    );
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it('a slow relay inside the deadline still works, so the deadline is not the whole answer', async () => {
    const relay = new HostileRelay();
    relay.lies.delayMs = 30;
    const box = await client(relay, 2_000).createMailbox();
    expect(box.mailboxId).toMatch(MAILBOX_ID_RE);
  });

  it('a caller can shorten one request deadline and can never lengthen it', async () => {
    // A caller running several requests under one wall-clock budget passes what is left of
    // it. That has to be a floor-only control: if a caller could pass a LONGER value, the
    // per-request wall would be set by the caller rather than by this client, and the
    // constructor's deadline would stop being a wall at all.
    const relay = new HostileRelay();
    relay.lies.hang = true; // so nothing but a deadline can end either request
    const box = '0'.repeat(32);
    const cap = 'a'.repeat(24);

    const shortened = Date.now();
    expect(await failureOf(() => client(relay, 3_000).listBlobs(box, cap, 150))).toBe('timeout');
    expect(Date.now() - shortened).toBeLessThan(1_500);

    // The same request asking for far MORE than the client allows still stops at the
    // client's own deadline, not at the caller's number.
    const lengthened = Date.now();
    expect(await failureOf(() => client(relay, 150).listBlobs(box, cap, 60_000))).toBe('timeout');
    expect(Date.now() - lengthened).toBeLessThan(1_500);
  });
});

describe('shapes the protocol does not allow', () => {
  it('malformed JSON is a named failure', async () => {
    const relay = new HostileRelay();
    relay.lies.malformedJson = true;
    expect(await failureOf(() => client(relay).createMailbox())).toBe('malformed');
  });

  it('valid JSON of the wrong shape is a named failure, in three flavours', async () => {
    for (const shape of ['array', 'missing', 'nested'] as const) {
      const relay = new HostileRelay();
      relay.lies.wrongShape = shape;
      expect(await failureOf(() => client(relay).createMailbox()), shape).toBe('malformed');
    }
    const relay = new HostileRelay();
    const api = client(relay);
    const box = await api.createMailbox();
    relay.lies.wrongShape = 'nested'; // { blobs: { ... } }, an object where an array belongs
    expect(await failureOf(() => api.listBlobs(box.mailboxId, box.pullToken))).toBe('malformed');
  });

  it('every documented status maps to its own named failure', async () => {
    const cases: [number, string][] = [
      [401, 'unauthorized'],
      [413, 'too-large'],
      [429, 'rate-limited'],
      [507, 'full'],
      [500, 'server'],
    ];
    for (const [status, failure] of cases) {
      const relay = new HostileRelay();
      const api = client(relay);
      const box = await api.createMailbox();
      relay.lies.status = status;
      expect(
        await failureOf(() => api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([1]))),
        String(status),
      ).toBe(failure);
    }
  });

  it('a 404 on a pull is null, not an error: the blob being gone is ordinary', async () => {
    const relay = new HostileRelay();
    const api = client(relay);
    const box = await api.createMailbox();
    const put = await api.putBlob(box.mailboxId, box.writeCap, new Uint8Array([1]));
    relay.lies.dropOnPull = true;
    expect(await api.pullBlob(box.mailboxId, put.blobId, box.pullToken)).toBeNull();
  });
});

describe('the base URL is a boundary, not a suggestion', () => {
  it('a relative base is refused at construction', () => {
    expect(() => new RelayClient({ baseUrl: '/v1', fetch: async () => new Response('') })).toThrow(
      /base URL must be absolute/,
    );
  });

  it('a base with a path prefix keeps its prefix', async () => {
    const relay = new HostileRelay();
    const api = new RelayClient({
      baseUrl: 'https://relay.test/keyweave',
      fetch: relay.fetch,
      timeoutMs: 250,
    });
    // The mailbox will not exist under that prefix, but the URL is what is being asserted.
    await failureOf(() => api.listBlobs('0'.repeat(32), 'a'.repeat(20)));
    expect(relay.calls[0]!.url).toBe(`https://relay.test/keyweave/v1/mailboxes/${'0'.repeat(32)}/blobs`);
  });
});
