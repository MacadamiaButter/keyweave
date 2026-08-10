// A relay that lies. This is the deliverable the messaging tests actually rest on: the real
// relay is untrusted by design, so a stub that only behaves correctly proves nothing about
// the client that talks to it.
//
// In its default state it is an honest in-memory implementation of the fixed wire protocol
// (relay/keyweave_relay.py), so the end-to-end paths run through it. Every deviation is a
// flag on `lies`, switched on per test:
//
//   reorder, duplicate and drop entries from a list; delay an answer past a deadline;
//   truncate a blob; flip a byte in one; answer with megabytes; answer with a blob nobody
//   put there, or one addressed to somebody else, or one from a different sender; answer
//   with malformed JSON, or valid JSON of the wrong shape; answer with ids that fail
//   validation, including one carrying path traversal; and answer with a redirect.
//
// It also RECORDS every request, so a test can assert what never happened: no capability
// token in a URL, no cookies, no followed redirect.

import type { FetchLike, RelayRequestInit } from '../src/relay-client.js';

export interface RelayLies {
  /** 'throw' is what a real fetch does under redirect: 'error'. 'followed' is a runtime that did not. */
  redirect?: 'throw' | 'followed';
  /** Answer every request after this many ms (the client's deadline is far shorter in tests). */
  delayMs?: number;
  /** Never resolve at all. */
  hang?: boolean;
  /** Force this status on every routed request. */
  status?: number;
  /** Body that is not JSON. */
  malformedJson?: boolean;
  /** Valid JSON, wrong shape (an array, or an object missing its fields). */
  wrongShape?: 'array' | 'missing' | 'nested';
  /** Hand back this mailbox id from create, whatever was really minted. */
  fakeMailboxId?: string;
  /** Hand back this blob id from create/put/list, whatever was really minted. */
  fakeBlobId?: string;
  /** Hand back this capability token from create. */
  fakeCap?: string;
  /** Repeat every listed id this many times. */
  duplicateList?: number;
  /** Reverse the listed order. */
  reverseList?: boolean;
  /** Claim the mailbox is empty. */
  emptyList?: boolean;
  /** 404 every pull, as if the blobs were never there. */
  dropOnPull?: boolean;
  /** Flip one byte of every pulled blob. */
  corruptByte?: boolean;
  /** Return only the first half of every pulled blob. */
  truncate?: boolean;
  /** Stream this many bytes on every pull, in 64 KiB chunks. */
  oversizeBytes?: number;
  /** Declare this Content-Length regardless of what is actually sent. */
  declaredLength?: number;
  /** Serve these bytes instead of the real blob (a foreign or re-addressed message). */
  substitute?: Uint8Array;
  /** Answer the headers promptly, then trickle one byte forever and never close. */
  trickleForever?: boolean;
  /**
   * Answer the headers promptly, then pace the body so it crosses the SIZE ceiling just
   * inside the per-request deadline. The nastier shape of the two: each pull ends in
   * `oversize`, which the receive loop treats as a defect in one answer and continues past,
   * so the relay gets to spend a near-full deadline on every id it chose to list.
   */
  tricklePastCeiling?: boolean;
}

interface Box {
  writeCap: string;
  pullToken: string;
  blobs: Map<string, Uint8Array>;
}

export interface RecordedCall {
  method: string;
  url: string;
  authorization: string | undefined;
  credentials: string;
  redirect: string;
  cache: string;
}

const hex = (n: number): string => {
  let out = '';
  for (let i = 0; i < n; i++) out += '0123456789abcdef'[Math.floor(Math.random() * 16)];
  return out;
};

let capCounter = 0;
const cap = (): string => `cap${String(capCounter++).padStart(3, '0')}${hex(36)}`;

export class HostileRelay {
  readonly boxes = new Map<string, Box>();
  readonly calls: RecordedCall[] = [];
  lies: RelayLies = {};
  /** Blob ids handed out, newest last, for tests that need to name one. */
  readonly minted: string[] = [];
  private blobSeq = 0;

  /** A fresh, honest mailbox, as if a peer had reserved it. */
  mint(): { mailboxId: string; writeCap: string; pullToken: string } {
    const mailboxId = hex(32);
    const box: Box = { writeCap: cap(), pullToken: cap(), blobs: new Map() };
    this.boxes.set(mailboxId, box);
    return { mailboxId, writeCap: box.writeCap, pullToken: box.pullToken };
  }

  /** Put a blob in directly, bypassing auth, the way the peer's device would have. */
  deposit(mailboxId: string, bytes: Uint8Array): string {
    const box = this.boxes.get(mailboxId);
    if (!box) throw new Error('hostile-relay: no such mailbox');
    const blobId = this.nextBlobId();
    box.blobs.set(blobId, Uint8Array.from(bytes));
    return blobId;
  }

  private nextBlobId(): string {
    const seq = this.blobSeq++;
    const stamp = `2026${String(1 + (seq % 9)).padStart(2, '0')}08T12${String(seq % 60).padStart(2, '0')}00Z`;
    const blobId = `bl-${stamp}.${hex(12)}`;
    this.minted.push(blobId);
    return blobId;
  }

  readonly fetch: FetchLike = async (url, init) => {
    this.calls.push({
      method: init.method,
      url,
      authorization: init.headers['Authorization'],
      credentials: init.credentials,
      redirect: init.redirect,
      cache: init.cache,
    });

    // Deliberately IGNORES the abort signal. A real fetch rejects when the signal fires, so
    // a stub that also rejected would make the deadline test pass without proving the client
    // can survive a transport that does not honour it.
    if (this.lies.hang) return new Promise<Response>(() => undefined);
    if (this.lies.delayMs) await sleep(this.lies.delayMs, init);
    if (this.lies.redirect === 'throw') {
      // Exactly what a real fetch does when a redirect meets redirect: 'error'.
      throw new TypeError('fetch failed: unexpected redirect');
    }
    if (this.lies.redirect === 'followed') {
      const res = this.jsonResponse(200, { blobs: [] });
      Object.defineProperty(res, 'redirected', { value: true, configurable: true });
      return res;
    }
    return this.route(url, init);
  };

  private route(url: string, init: RelayRequestInit): Response {
    const path = new URL(url).pathname;
    const bearer = (init.headers['Authorization'] ?? '').replace(/^Bearer /, '');

    if (init.method === 'POST' && path === '/v1/mailboxes') {
      const created = this.mint();
      return this.jsonResponse(this.lies.status ?? 201, {
        mailbox_id: this.lies.fakeMailboxId ?? created.mailboxId,
        write_cap: this.lies.fakeCap ?? created.writeCap,
        pull_token: this.lies.fakeCap ?? created.pullToken,
      });
    }

    const blobsMatch = /^\/v1\/mailboxes\/([0-9a-f]{32})\/blobs$/.exec(path);
    if (blobsMatch && init.method === 'PUT') {
      const box = this.boxes.get(blobsMatch[1]!);
      if (!box || box.writeCap !== bearer) return this.jsonResponse(401, { error: 'unauthorized' });
      const blobId = this.nextBlobId();
      box.blobs.set(blobId, Uint8Array.from(init.body ?? new Uint8Array(0)));
      return this.jsonResponse(this.lies.status ?? 201, {
        blob_id: this.lies.fakeBlobId ?? blobId,
        size: init.body?.length ?? 0,
      });
    }

    if (blobsMatch && init.method === 'GET') {
      const box = this.boxes.get(blobsMatch[1]!);
      if (!box || box.pullToken !== bearer) return this.jsonResponse(401, { error: 'unauthorized' });
      let ids = [...box.blobs.keys()];
      if (this.lies.emptyList) ids = [];
      if (this.lies.reverseList) ids.reverse();
      if (this.lies.fakeBlobId) ids = ids.map(() => this.lies.fakeBlobId!);
      if (this.lies.duplicateList) {
        ids = ids.flatMap((id) => Array<string>(this.lies.duplicateList!).fill(id));
      }
      const blobs = ids.map((id) => ({ blob_id: id, size: box.blobs.get(id)?.length ?? 0 }));
      return this.jsonResponse(this.lies.status ?? 200, { blobs });
    }

    const blobMatch = /^\/v1\/mailboxes\/([0-9a-f]{32})\/blobs\/([^/]+)$/.exec(path);
    if (blobMatch && init.method === 'GET') {
      const box = this.boxes.get(blobMatch[1]!);
      if (!box || box.pullToken !== bearer) return this.jsonResponse(401, { error: 'unauthorized' });
      if (this.lies.trickleForever) return this.trickleResponse();
      if (this.lies.tricklePastCeiling) return this.trickleResponse(256);
      if (this.lies.oversizeBytes) return this.streamResponse(this.lies.oversizeBytes);
      const blobId = decodeURIComponent(blobMatch[2]!);
      const stored = box.blobs.get(blobId);
      if (this.lies.dropOnPull || !stored) return this.jsonResponse(404, { error: 'not found' });
      box.blobs.delete(blobId); // delete-on-pull, exactly like the real relay
      let bytes = this.lies.substitute ?? stored;
      if (this.lies.truncate) bytes = bytes.subarray(0, Math.floor(bytes.length / 2));
      if (this.lies.corruptByte) {
        bytes = Uint8Array.from(bytes);
        bytes[Math.floor(bytes.length / 2)] ^= 0x01;
      }
      return this.octetResponse(this.lies.status ?? 200, bytes);
    }

    return this.jsonResponse(404, { error: 'not found' });
  }

  private body(): string | undefined {
    if (this.lies.malformedJson) return '{not json at all';
    if (this.lies.wrongShape === 'array') return '[1, 2, 3]';
    if (this.lies.wrongShape === 'missing') return '{}';
    if (this.lies.wrongShape === 'nested') return '{"blobs": {"blob_id": "x"}}';
    return undefined;
  }

  private jsonResponse(status: number, payload: unknown): Response {
    const text = this.body() ?? JSON.stringify(payload);
    const bytes = new TextEncoder().encode(text);
    return new Response(bytes, {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': String(this.lies.declaredLength ?? bytes.length),
      },
    });
  }

  private octetResponse(status: number, bytes: Uint8Array): Response {
    const forced = this.body();
    const payload = forced === undefined ? bytes : new TextEncoder().encode(forced);
    return new Response(payload, {
      status,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(this.lies.declaredLength ?? payload.length),
      },
    });
  }

  /**
   * Headers now, then a chunk every 40 ms at the default size, never closed. At one byte a
   * chunk the size ceiling can never fire and the fetch has already resolved, so the only
   * thing left to stop it is a deadline that covers the BODY as well as the handshake. At a
   * larger chunk it crosses the ceiling instead, which is the slow-and-oversize case.
   */
  private trickleResponse(chunkBytes = 1): Response {
    const everyMs = chunkBytes === 1 ? 40 : 10;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        return new Promise<void>((resolve) => {
          setTimeout(() => {
            controller.enqueue(new Uint8Array(chunkBytes));
            resolve();
          }, everyMs);
        });
      },
    });
    return new Response(stream, {
      status: 200,
      headers: { 'Content-Type': 'application/octet-stream' },
    });
  }

  /**
   * Stream `total` bytes in chunks WITHOUT an honest Content-Length, which is the case the
   * ceiling exists for: nothing in the headers warns the client, so the only thing that can
   * stop it is a counter on the read.
   */
  private streamResponse(total: number): Response {
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent >= total) {
          controller.close();
          return;
        }
        const size = Math.min(64 * 1024, total - sent);
        sent += size;
        controller.enqueue(new Uint8Array(size));
      },
    });
    const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' };
    if (this.lies.declaredLength !== undefined) {
      headers['Content-Length'] = String(this.lies.declaredLength);
    }
    return new Response(stream, { status: 200, headers });
  }
}

function sleep(ms: number, init: RelayRequestInit): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    // A stub that ignored the signal would make every timeout test pass for the wrong
    // reason (the test's own patience), so the abort is honoured here the way fetch does.
    init.signal.addEventListener('abort', () => {
      clearTimeout(timer);
      reject(new DOMException('aborted', 'AbortError'));
    });
  });
}
