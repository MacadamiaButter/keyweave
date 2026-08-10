// The client half of the mailbox relay wire protocol (relay/keyweave_relay.py, "Wire
// protocol v1 (fixed)"). The contract is the relay's; this file conforms to it.
//
// THE RELAY IS UNTRUSTED AND DUMB. It sees ciphertext blobs and an opaque mailbox id. It
// can reorder, duplicate, drop, delay, replay, truncate, hand back blobs nobody sent,
// hand back another mailbox's blobs, call a full mailbox empty, answer a 2 KiB blob with a
// 10 MiB body, or answer any request with a redirect to somewhere else entirely. None of
// that may corrupt state or crash the client, and none of it is ever reported to the user
// as something their contact did. Everything here is therefore written against a lying
// server, not a flaky one.
//
// Four independent walls (anchor `defdepth`; none of them is the others' backstop):
//   1. A SIZE CEILING ENFORCED WHILE READING. Content-Length is a claim by the liar, so it
//      is used only to refuse early, never to size a buffer. The body is streamed and the
//      read is abandoned the moment it passes the ceiling.
//   2. STRICT VALIDATION OF EVERY RELAY-SUPPLIED STRING, before it can reach a URL or a
//      header. A blob id is the relay's to choose, and an unvalidated one interpolated
//      into a path is a path traversal aimed at the client's own origin.
//   3. NO REDIRECTS (`redirect: 'error'`). A redirect is the relay choosing a different
//      origin on our behalf; same class as the fleetglass and lfl-security scope_guard
//      findings, and the answer is the same one: do not follow, refuse.
//   4. A DEADLINE ON EVERY REQUEST via AbortController. A relay that accepts a connection
//      and then says nothing must not be able to hang the interface.
//
// leastpriv: this module holds a mailbox id and two capability tokens and nothing else. It
// never sees a key, never opens a blob, and never learns who a mailbox belongs to. Tokens
// travel in the Authorization header, never in a URL (a URL reaches proxy logs, the
// Referer header, and the relay's own nginx error_log) and never in a log line here,
// because there is no log line here.
//
// THE BASE URL AND THE CSP. This module takes a base URL and never chooses one. The choice
// is a single build-time value, KEYWEAVE_RELAY_ORIGIN, which the SAME definition
// (client/build-config.mjs) also uses to write `connect-src` in the page's CSP and in the
// response header docs/DEPLOY-CSP.md publishes. Unset means the relay is on the app's own
// origin, which is the default; setting it is the split trust domains residual R2 asks for.
// src/ui/main.ts is the only file that reads it. Nothing here names an origin, and a base
// URL that disagrees with the page's own connect-src is a request the browser refuses to
// send at all, which is why there is one value and not three.

import { CAP_TOKEN_RE } from './constants.js';

/** Only the parts of fetch this client uses, so a test can pass a hostile stub. */
export type FetchLike = (input: string, init: RelayRequestInit) => Promise<Response>;

export interface RelayRequestInit {
  method: string;
  headers: Record<string, string>;
  body?: Uint8Array;
  signal: AbortSignal;
  redirect: 'error';
  credentials: 'omit';
  cache: 'no-store';
  referrerPolicy: 'no-referrer';
  mode: 'cors';
}

/** Exactly the relay's MAILBOX_ID_RE, anchored to the whole string. */
export const MAILBOX_ID_RE = /^[0-9a-f]{32}$/;
/** Exactly the relay's BLOB_ID_RE: bl-<compact UTC timestamp>.<12 hex>. */
export const BLOB_ID_RE = /^bl-\d{8}T\d{6}Z\.[0-9a-f]{12}$/;

/**
 * The relay's own max_blob_bytes (65536) plus slack for the JSON list response, which grows
 * with max_blobs_per_mailbox. Nothing legitimate approaches it; it exists so an unbounded
 * body cannot be buffered.
 */
export const MAX_RESPONSE_BYTES = 256 * 1024;
export const DEFAULT_TIMEOUT_MS = 15_000;

export type RelayFailure =
  | 'timeout' // no answer inside the deadline
  | 'network' // fetch itself rejected, redirect included
  | 'unauthorized' // 401: the capability is wrong, or the mailbox is gone
  | 'rate-limited' // 429
  | 'not-found' // 404
  | 'too-large' // 413: we tried to write more than the relay accepts
  | 'full' // 507
  | 'server' // any other non-2xx
  | 'oversize' // the RESPONSE passed the ceiling
  | 'malformed'; // the response was not the shape the protocol promises

/**
 * Every failure is one of these, so the UI can be honest about which of them happened
 * without ever attributing any of them to the peer.
 */
export class RelayError extends Error {
  constructor(
    readonly failure: RelayFailure,
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'RelayError';
  }
}

export interface MailboxCredentials {
  readonly mailboxId: string; // 32 lowercase hex
  readonly writeCap: string;
  readonly pullToken: string;
}

export interface BlobSummary {
  readonly blobId: string;
  readonly size: number;
}

export interface RelayClientOptions {
  /**
   * ABSOLUTE base URL. A relative one is refused rather than resolved: this module has no
   * business reading `location`, and the caller that does know the origin is the one place
   * the same-origin default belongs (src/ui/main.ts). Every request path is resolved
   * against this and re-checked before it is fetched.
   */
  baseUrl: string;
  fetch: FetchLike;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

/** A relay-supplied string that will touch a URL or a header. Newlines first, then the shape. */
function checkToken(value: unknown, pattern: RegExp, label: string): string {
  if (typeof value !== 'string') throw new RelayError('malformed', `relay: ${label} is not a string`);
  // Anchors alone are not enough to reason about safely once a value can carry a control
  // character, so the class is rejected outright before the anchored pattern runs.
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(value)) {
    throw new RelayError('malformed', `relay: ${label} carries a control character`);
  }
  if (!pattern.test(value)) throw new RelayError('malformed', `relay: ${label} is malformed`);
  return value;
}

export class RelayClient {
  private readonly base: URL;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;

  constructor(opts: RelayClientOptions) {
    // A base without a trailing slash silently drops its last path segment when a relative
    // path is resolved against it, which is how a deployment under /relay/ would end up
    // talking to /v1/ at the root.
    const base = opts.baseUrl.endsWith('/') ? opts.baseUrl : `${opts.baseUrl}/`;
    try {
      this.base = new URL(base);
    } catch {
      throw new RelayError('malformed', 'relay: base URL must be absolute');
    }
    this.fetchImpl = opts.fetch;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxBytes = opts.maxResponseBytes ?? MAX_RESPONSE_BYTES;
  }

  /**
   * The hard ceiling on every request this client makes, in ms. `withinMs` can only shorten
   * it, never lengthen it, so no request here can ever be given more than this.
   *
   * Exposed because a caller running a multi-request pass under one budget (messaging.ts)
   * states a MINIMUM deadline it will start a pull with, and a minimum above this ceiling is
   * a promise the transport cannot keep. The caller caps itself to this rather than
   * documenting an invariant it does not have.
   */
  get requestCeilingMs(): number {
    return this.timeoutMs;
  }

  /**
   * Resolve one protocol path against the base and refuse anything that escapes it. The id
   * validators above already make traversal impossible; this is the second wall, and it is
   * the one that still holds if a future caller forgets the first.
   */
  private url(path: string): string {
    const resolved = new URL(path, this.base);
    if (resolved.origin !== this.base.origin || !resolved.pathname.startsWith(this.base.pathname)) {
      throw new RelayError('malformed', 'relay: refusing a path that leaves the relay base');
    }
    return resolved.href;
  }

  private async request(
    path: string,
    method: string,
    token: string | undefined,
    body?: Uint8Array,
    withinMs?: number,
  ): Promise<{ status: number; bytes: Uint8Array }> {
    const url = this.url(path);
    const headers: Record<string, string> = {};
    if (token !== undefined) {
      // Validated here as well as at its source: a token is a header value, and a header
      // value is the one place a stray newline is a request-splitting primitive.
      headers['Authorization'] = `Bearer ${checkToken(token, CAP_TOKEN_RE, 'capability token')}`;
    }
    if (body !== undefined) headers['Content-Type'] = 'application/octet-stream';

    // The deadline is a RACE, not only an AbortController. Aborting is the polite half: it
    // tells the transport to stop. But "a hung relay must not hang the interface" cannot
    // rest on the transport honouring the signal, and the same deadline has to cover the
    // BODY, because a relay that sends headers promptly and then trickles bytes forever has
    // hung the interface just as thoroughly.
    //
    // `withinMs` is a caller-supplied SHORTENING of that deadline, never a lengthening of
    // it: a caller running a multi-request pass under one wall-clock budget passes what is
    // left of the budget, so the pass costs one deadline in total rather than one per
    // request. It can only make this request finish sooner, so the per-request wall stands.
    const limitMs = Math.max(1, Math.min(this.timeoutMs, withinMs ?? this.timeoutMs));
    const controller = new AbortController();
    let expire: (reason: RelayError) => void = () => undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      expire = reject;
    });
    // The race leaves the losing promise rejected and unobserved, which is an unhandled
    // rejection in Node unless it is claimed here.
    deadline.catch(() => undefined);
    const timer = setTimeout(() => {
      controller.abort();
      expire(new RelayError('timeout', 'relay: no answer inside the deadline'));
    }, limitMs);

    try {
      let response: Response;
      try {
        response = await Promise.race([
          this.fetchImpl(url, {
            method,
            headers,
            ...(body === undefined ? {} : { body }),
            signal: controller.signal,
            // A redirect is the relay picking a different origin for us. Never followed.
            redirect: 'error',
            credentials: 'omit',
            cache: 'no-store',
            referrerPolicy: 'no-referrer',
            mode: 'cors',
          }),
          deadline,
        ]);
      } catch (error) {
        if (error instanceof RelayError) throw error;
        if (controller.signal.aborted) {
          throw new RelayError('timeout', 'relay: no answer inside the deadline');
        }
        throw new RelayError('network', `relay: request failed (${describe(error)})`);
      }

      // Belt and braces behind redirect: 'error'. A stub, a polyfill or a future runtime
      // that resolves a redirect instead of rejecting must not get a pass.
      if (response.redirected === true) {
        throw new RelayError('network', 'relay: the response was redirected');
      }
      const bytes = await Promise.race([this.readCapped(response), deadline]);
      return { status: response.status, bytes };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Read a body with the ceiling enforced AS IT ARRIVES. Content-Length is only ever used to
   * refuse before reading; a relay that lies low and then streams is stopped by the counter,
   * and the reader is cancelled rather than drained so the bytes stop coming.
   */
  private async readCapped(response: Response): Promise<Uint8Array> {
    const declared = Number(response.headers?.get?.('Content-Length') ?? '');
    if (Number.isFinite(declared) && declared > this.maxBytes) {
      throw new RelayError('oversize', 'relay: response declares more than the ceiling');
    }
    const body = response.body;
    if (!body) {
      // No stream at all means no body (204 and the like). Anything else would be a runtime
      // that cannot be read under a ceiling, and buffering it is exactly what is refused.
      return new Uint8Array(0);
    }
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        total += value.length;
        if (total > this.maxBytes) {
          throw new RelayError('oversize', 'relay: response passed the size ceiling');
        }
        chunks.push(value);
      }
    } finally {
      // Cancel unconditionally: on the oversize path it stops the sender, and on the normal
      // path a completed stream cancels to a no-op.
      void reader.cancel().catch(() => undefined);
    }
    const out = new Uint8Array(total);
    let at = 0;
    for (const chunk of chunks) {
      out.set(chunk, at);
      at += chunk.length;
    }
    return out;
  }

  private json(bytes: Uint8Array): Record<string, unknown> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } catch {
      throw new RelayError('malformed', 'relay: response was not JSON');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new RelayError('malformed', 'relay: response was not a JSON object');
    }
    return parsed as Record<string, unknown>;
  }

  /** Mint a fresh mailbox. No auth; the relay rate-limits creation per source address. */
  async createMailbox(): Promise<MailboxCredentials> {
    const { status, bytes } = await this.request('v1/mailboxes', 'POST', undefined);
    if (status !== 201) throw failureFor(status, 'create mailbox');
    const body = this.json(bytes);
    return {
      mailboxId: checkToken(body['mailbox_id'], MAILBOX_ID_RE, 'mailbox id'),
      writeCap: checkToken(body['write_cap'], CAP_TOKEN_RE, 'write cap'),
      pullToken: checkToken(body['pull_token'], CAP_TOKEN_RE, 'pull token'),
    };
  }

  /**
   * Hand the relay one opaque blob. The bytes are never inspected on this path.
   *
   * `withinMs` shortens this request's deadline, exactly as it does on the two read paths:
   * a caller offering several queued blobs under one wall-clock budget (messaging.ts
   * flush()) passes what is left of it, so the pass costs one budget rather than one
   * deadline per record. Omitted, the request gets the full per-request deadline, which is
   * what every caller before the budget got.
   */
  async putBlob(
    mailboxId: string,
    writeCap: string,
    blob: Uint8Array,
    withinMs?: number,
  ): Promise<BlobSummary> {
    const mid = checkToken(mailboxId, MAILBOX_ID_RE, 'mailbox id');
    const { status, bytes } = await this.request(
      `v1/mailboxes/${mid}/blobs`,
      'PUT',
      writeCap,
      blob,
      withinMs,
    );
    if (status !== 201) throw failureFor(status, 'store blob');
    const body = this.json(bytes);
    const size = body['size'];
    if (typeof size !== 'number' || !Number.isInteger(size) || size < 0) {
      throw new RelayError('malformed', 'relay: blob size is not an integer');
    }
    return { blobId: checkToken(body['blob_id'], BLOB_ID_RE, 'blob id'), size };
  }

  /**
   * Metadata for what is waiting. Ids that fail validation are DROPPED rather than failing
   * the whole list: one bad entry among ten is a relay defect, and refusing the batch would
   * hand the relay a way to stop delivery entirely by appending one malformed id.
   */
  async listBlobs(
    mailboxId: string,
    pullToken: string,
    withinMs?: number,
  ): Promise<BlobSummary[]> {
    const mid = checkToken(mailboxId, MAILBOX_ID_RE, 'mailbox id');
    const { status, bytes } = await this.request(
      `v1/mailboxes/${mid}/blobs`,
      'GET',
      pullToken,
      undefined,
      withinMs,
    );
    if (status !== 200) throw failureFor(status, 'list blobs');
    const body = this.json(bytes);
    const raw = body['blobs'];
    if (!Array.isArray(raw)) throw new RelayError('malformed', 'relay: blob list is not an array');
    const out: BlobSummary[] = [];
    for (const entry of raw) {
      if (typeof entry !== 'object' || entry === null) continue;
      const record = entry as Record<string, unknown>;
      const blobId = record['blob_id'];
      if (typeof blobId !== 'string' || !isCleanBlobId(blobId)) continue;
      const size = record['size'];
      out.push({ blobId, size: typeof size === 'number' && size >= 0 ? size : 0 });
    }
    return out;
  }

  /**
   * Pull one blob. DELETE-ON-PULL: the relay removes it before the bytes reach the wire, so
   * this is at-most-once (R9) and a failure here is a lost message, not a retryable one.
   * `null` means the relay says it is not there, which includes "never was".
   */
  async pullBlob(
    mailboxId: string,
    blobId: string,
    pullToken: string,
    withinMs?: number,
  ): Promise<Uint8Array | null> {
    const mid = checkToken(mailboxId, MAILBOX_ID_RE, 'mailbox id');
    const bid = checkToken(blobId, BLOB_ID_RE, 'blob id');
    const { status, bytes } = await this.request(
      `v1/mailboxes/${mid}/blobs/${bid}`,
      'GET',
      pullToken,
      undefined,
      withinMs,
    );
    if (status === 404) return null;
    if (status !== 200) throw failureFor(status, 'pull blob');
    return bytes;
  }
}

function isCleanBlobId(value: string): boolean {
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(value)) return false;
  return BLOB_ID_RE.test(value);
}

function failureFor(status: number, what: string): RelayError {
  const failure: RelayFailure =
    status === 401
      ? 'unauthorized'
      : status === 404
        ? 'not-found'
        : status === 413
          ? 'too-large'
          : status === 429
            ? 'rate-limited'
            : status === 507
              ? 'full'
              : 'server';
  return new RelayError(failure, `relay: could not ${what} (status ${status})`, status);
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
