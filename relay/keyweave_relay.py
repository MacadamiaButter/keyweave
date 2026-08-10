#!/usr/bin/env python3
"""Keyweave mailbox relay: a dumb store-and-forward drop box for OPAQUE ciphertext.

Single-file, standard-library-only HTTP service meant for a small VPS, bound to
loopback behind a TLS-terminating reverse proxy (nginx). It stores opaque
ciphertext blobs against random 128-bit mailbox ids. It holds no private key and
no plaintext, and it NEVER decodes, parses, decompresses, or decrypts a blob.
That "never decode" property is the structural defense against the
decompression-bomb class the parent (EdgeDancer ingest relay) had to guard
against on its decrypt path: Keyweave's relay has no decrypt path at all.

Forked from the adversarially-hardened EdgeDancer inbox relay. The reused SHAPE
is the disk-persisted RateLimiter / FailureLimiter, the flock-based file
locking, the fail-closed config validation, and the log-nothing-sensitive
discipline. The EdgeDancer-specific paths (gpg encrypt-on-receipt, single global
submit/pull tokens, the flat item store, the whole-store single-lock purge) are
deliberately NOT carried over -- the parent's assurance does not transfer to the
rewritten per-mailbox auth + nested-store paths, so those get their own tests.

Security model (Kerckhoffs): this file is public. All security rests on two
per-mailbox bearer capabilities plus TLS at the proxy. Nothing here depends on
secrecy of the code.

Capability split (a mailbox has two independent secrets):
  * write_cap  -- may PUT blobs into the mailbox. CANNOT read or delete.
  * pull_token -- may list, pull (delete-on-pull), and delete. CANNOT write.
Only the SHA-256 DIGEST of each is stored; the tokens themselves never touch
disk after the create response. Comparison is constant-time (hmac.compare_digest)
against a digest that is a dummy random value when the mailbox does not exist, so
the auth path does no disk I/O and never reveals which mailboxes exist.

Wire protocol v1 (fixed):
  POST   /v1/mailboxes                      (no auth; per-IP create rate limit)
         201 {"mailbox_id","write_cap","pull_token"}; 429; 507 (mailbox cap)
  PUT    /v1/mailboxes/<mid>/blobs          write_cap; body = raw opaque bytes
         201 {"blob_id","size"}; 401; 411; 413 (> max_blob_bytes); 429;
         507 (mailbox or relay full)
  GET    /v1/mailboxes/<mid>/blobs          pull_token
         200 {"blobs":[{"blob_id","size","received"}]}  (metadata only)
  GET    /v1/mailboxes/<mid>/blobs/<bid>    pull_token; delete-on-pull
         200 raw opaque bytes (application/octet-stream), then the blob is gone
  DELETE /v1/mailboxes/<mid>/blobs/<bid>    pull_token
         204; 404 unknown/already-gone

Mailbox ids are 32 lowercase hex chars (128 random bits). Blob ids look like
bl-20260808T120000Z.<12 hex> (UTC compact timestamp, a dot, then 12 hex). The
timestamp drives the TTL and the "received" metadata; the relay generates it, so
it leaks nothing the relay does not already know.

Independent resource walls (defense in depth -- each is REAL, none decorative):
  1. max_blob_bytes        hard per-blob size cap (checked from Content-Length
                           BEFORE the body is ever read; the blob is never parsed)
  2. max_blobs_per_mailbox per-mailbox blob COUNT cap
  3. max_mailbox_bytes     per-mailbox BYTE cap
  4. max_mailboxes         global mailbox COUNT cap
  5. max_total_bytes       global BYTE cap, backed by a durable LOCKED ledger
                           updated in the same critical section as every add and
                           delete, and RECONCILED from disk at startup so a crash
                           can never let it drift into fiction
  6. create_rate_per_hour  per-source-IP mailbox-creation rate
  7. write_rate_per_hour   per-mailbox blob-write rate
  8. auth_fail_limit       per-source-IP auth-failure budget, consulted BEFORE
                           the token compare so an unauthenticated flood hits a
                           disk-backed 429 wall instead of drowning the AUTHFAIL
                           journal lines fail2ban depends on

The global byte cap (5) is an AVAILABILITY boundary, NOT a security one. The
per-source sliding-window byte budget (max_source_write_bytes_per_hour, a
per-CLIENT rate once the deploy hands the relay real client addresses) bounds
how fast ONE source consumes shared storage, but a DISTRIBUTED flood across many
sources can still fill max_total_bytes and return 507 to every tenant. That is a
NAMED residual (RELAY-RESIDUALS.md R10): mitigated by the 14-day TTL +
delete-on-pull reclaiming space, with full oldest-first eviction deferred past
v0. Treat "relay full" as an availability event (alert / raise the cap / shorten
the TTL), never as a confidentiality or integrity property.

Logging discipline: the relay NEVER logs a mailbox id, a blob id, a token, or a
request path (any of which could carry a mailbox id). AUTHFAIL lines carry the
client address, method, and role only. NOTE that nginx's error_log records the
full request line (including the mailbox id) even with access_log off, so the
relay's own log discipline is not sufficient at the nginx layer -- see the deploy
notes below and turn error_log down / scrub it.

--------------------------------------------------------------------------------
Intended deployment (this module does NOT run any of it). The deploy artifacts
SHIP ALONGSIDE this file and are the SINGLE SOURCE OF TRUTH -- copy them, never
transcribe from here:

  * keyweave-relay.service  -- hardened systemd unit (DynamicUser, loopback-only
                              IPAddressAllow=localhost, the sandboxing set, and
                              the journald LogRateLimit* budget fail2ban needs).
  * nginx-location.conf    -- the /v1/ location: TLS terminates at nginx, the
                              relay is 127.0.0.1:8151 only, the real-client-
                              address config (a pinned last-hop X-Forwarded-For
                              that nginx OVERWRITES + trust_forwarded_for=1; the
                              file explains why nginx real_ip alone never reaches
                              a loopback upstream), the limit_req/limit_conn
                              zones, client_max_body_size, and the error_log note.

Earlier revisions inlined those snippets in this docstring; they drifted from the
shipped files (the nginx zone name and the journald LogRateLimit values both
diverged), so the inline copies were DELETED to leave one source of truth. Read
the two files above.

Two deploy-critical facts that live with the CODE, not only the config:
  * The relay binds loopback only, so the TCP peer of the nginx->relay hop is
    always 127.0.0.1. The ONE coherent way to hand the relay the real client
    address is nginx OVERWRITING X-Forwarded-For with the peer it saw
    (proxy_set_header X-Forwarded-For $remote_addr) AND trust_forwarded_for=1 in
    relay.conf. nginx real_ip ALONE does not work: it rewrites nginx's own
    $remote_addr, not the relay's TCP peer, so the relay still sees 127.0.0.1
    (realip is only a prerequisite when nginx itself sits behind another proxy).
    Otherwise every request is attributed to the proxy peer and the failure
    budget / fail2ban would ban the proxy itself. build_server() logs a loud
    STARTUP warning while trust_forwarded_for=0.
  * nginx's error_log records the full request line (incl. the mailbox id) even
    with access_log off -- keep it at crit or somewhere access-controlled/short.
--------------------------------------------------------------------------------
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

__version__ = "1.0.0"

RECEIVED_FMT = "%Y-%m-%dT%H:%M:%SZ"
BLOB_TS_FMT = "%Y%m%dT%H%M%SZ"

# Anchors are \A...\Z, never ^...$. In Python $ also matches just before a
# trailing newline, so "<id>\n" would slip through a $-anchored check; \Z is the
# absolute end of string (the parent used $; the hardened spec pins \z/\Z here).
MAILBOX_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")
BLOB_ID_RE = re.compile(r"\Abl-\d{8}T\d{6}Z\.[0-9a-f]{12}\Z")

# Route patterns double as validators: a malformed id fails to match and 404s
# during routing, so it never reaches the (constant-time) auth path.
RE_MAILBOXES = re.compile(r"\A/v1/mailboxes\Z")
RE_BLOBS = re.compile(r"\A/v1/mailboxes/([0-9a-f]{32})/blobs\Z")
RE_BLOB = re.compile(
    r"\A/v1/mailboxes/([0-9a-f]{32})/blobs/(bl-\d{8}T\d{6}Z\.[0-9a-f]{12})\Z")

RATE_WINDOW_S = 3600
DRAIN_CAP = 1024 * 1024
# Grace before a leftover .<hex>.tmp (a SIGKILL mid-PUT artifact) is swept. A
# live add_blob commits its tmp in milliseconds, so an hour is unambiguously
# orphaned and cannot race an in-flight write.
_TMP_ORPHAN_GRACE_S = 3600
DEFAULT_CONFIG_PATH = "/etc/keyweave-relay/relay.conf"

LOG = logging.getLogger("keyweave_relay")

_CTRL_RE = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029]")

# Any path segment that can carry a mailbox or blob id, collapsed before it can
# reach a log line (defense in depth behind the log_request override below).
_REDACT_PATH_RE = re.compile(
    r"/v1/mailboxes/[0-9a-f]{32}(?:/blobs(?:/bl-\d{8}T\d{6}Z\.[0-9a-f]{12})?)?")

# The FILESYSTEM form of a mailbox path: an OSError carries <data_dir>/mailboxes/
# <32hex>/... in its str(), which is NOT a /v1 request path, so it would slip the
# request-path redactor. This catches the on-disk shape wherever it appears.
_REDACT_FS_RE = re.compile(r"/mailboxes/[0-9a-f]{32}(?:/[^\s'\"]*)?")


class ConfigError(Exception):
    """Legible configuration problem; the service refuses to start."""


class RelayError(Exception):
    """Runtime failure that must fail the request closed."""


class MailboxNotFound(Exception):
    """The mailbox directory is gone underneath a request."""


class MailboxFull(Exception):
    """A per-mailbox count or byte cap was reached."""


class RelayFull(Exception):
    """A global cap (mailbox count or total bytes) was reached."""


class BlobTooLarge(Exception):
    """Blob exceeds max_blob_bytes (backstop; handler checks Content-Length)."""


def sanitize_line(value, cap=200):
    """Collapse anything log-bound to one safe single line (no control chars)."""
    return _CTRL_RE.sub("?", str(value))[:cap]


def redact_path(value):
    """Strip mailbox/blob ids out of anything log-bound, in BOTH the /v1 request
    form and the on-disk <data_dir>/mailboxes/<32hex>/... form (an OSError str
    carries the latter). The relay must never log an id (nginx's error_log still
    records the full request line -- see the deploy notes -- so this is the
    relay's half of that discipline)."""
    text = _REDACT_PATH_RE.sub("/v1/mailboxes/<redacted>", str(value))
    return _REDACT_FS_RE.sub("/mailboxes/<redacted>", text)


def utcnow():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Client-address / failure-budget keying
# ---------------------------------------------------------------------------

def failkey(client):
    """Bucket a client address into ONE auth-failure-budget key.

    IPv6 collapses to its /64: a single allocation routinely hands an attacker
    2^64 addresses, and per-address keying would mint millions of state files
    (inode exhaustion -> the budget that is supposed to contain the flood
    breaks). One /64 must map to exactly one key. IPv4 keys per address.

    An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is NORMALIZED to its IPv4 form
    FIRST, before the /64 bucketing -- otherwise every mapped address shares the
    single all-zero /64 key "v6:/64:::" and the entire IPv4 internet collapses
    into one budget. ::ffff:a.b.c.d must key identically to a.b.c.d.
    """
    try:
        ip = ipaddress.ip_address(client)
    except ValueError:
        # Callers pass a validated IP: _client() falls back to the socket peer
        # when a forwarded value does not parse, so a client-chosen non-IP can
        # never reach here to mint an unbounded 'raw:'+arbitrary keyspace. This
        # is a defensive single constant bucket, not a per-value key.
        return "unparsed"
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            ip = mapped
    if isinstance(ip, ipaddress.IPv6Address):
        net = ipaddress.ip_network("%s/64" % ip.compressed, strict=False)
        return "v6:/64:" + net.network_address.compressed
    return "v4:" + ip.compressed


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    bind_host: str = "127.0.0.1"
    bind_port: int = 8151
    data_dir: str = "/var/lib/keyweave-relay"
    max_blob_bytes: int = 65536
    max_blobs_per_mailbox: int = 100
    max_mailbox_bytes: int = 1048576
    max_mailboxes: int = 10000
    max_total_bytes: int = 1073741824
    create_rate_per_hour: int = 60
    write_rate_per_hour: int = 600
    # Per-SOURCE (per failkey) write-BYTES budget per hour -- a per-CLIENT rate
    # once the deploy hands the relay real client addresses (trust_forwarded_for
    # =1 + nginx X-Forwarded-For overwrite). It bounds how fast ONE client can
    # consume shared storage, and self-heals (expired stamps age out of the
    # window -- no delete-time attribution problem). It is NOT a guarantee that
    # one source cannot fill the global cap: the global max_total_bytes cap is an
    # AVAILABILITY boundary, not a security one, and a DISTRIBUTED flood across
    # many sources can still fill it (named residual R10 -- see the module
    # docstring and RELAY-RESIDUALS.md; mitigated by the TTL + delete-on-pull,
    # full oldest-first eviction deferred past v0). Sized as a generous default
    # for a text messenger: ~128 max-size (64 KiB) blobs per hour.
    max_source_write_bytes_per_hour: int = 8388608  # 8 MiB (~128 x 64 KiB/h)
    auth_fail_limit_per_hour: int = 60
    # Per-SOURCE (per failkey, mailbox-INDEPENDENT) auth-failure budget, with a
    # HIGHER limit than the per-(source,mailbox) one above. It is consulted and
    # recorded ONLY for requests whose target mailbox does NOT exist -- the
    # id-rotation surface. A source that ROTATES mailbox ids (a fresh,
    # non-existent id per request) would otherwise mint one per-(source,mailbox)
    # file per request (the unbounded-keyspace / inode-growth hole the failure
    # limiter exists to close); this source-level wall 429s such a source and
    # stops it minting new files. Requests to a REAL mailbox never touch this
    # wall -- critical under shared attribution (behind nginx with
    # trust_forwarded_for=0 every client is the same proxy peer, so gating
    # existing mailboxes on a shared wall would let one flood 429 every tenant).
    # Legit clients touch an EXISTING mailbox, so the per-mailbox cap governs
    # them; this only walls id-rotation against non-existent ids.
    auth_fail_source_limit_per_hour: int = 600
    ttl_days: int = 14
    mailbox_idle_days: int = 30
    purge_interval_s: int = 300
    purge_budget: int = 200
    # X-Forwarded-For is attacker-controlled unless a trusted proxy rewrites it;
    # ignored unless the operator explicitly sets 1 (see deploy notes).
    trust_forwarded_for: int = 0
    # Browser CORS allowlist (comma-separated origins). The client is served
    # from a trust domain distinct from the relay (spec R2), so a preflight from
    # the app origin must be answered; NEVER '*' with credentials. Default = the
    # public app origin; override for a private/preview host.
    allowed_origins: str = "https://keyweave.localfirstlab.org"

    @property
    def mailboxes_dir(self):
        return Path(self.data_dir) / "mailboxes"

    @property
    def state_dir(self):
        return Path(self.data_dir) / "state"

    @property
    def ledger_path(self):
        return self.state_dir / "bytes.ledger"

    @property
    def allowed_origin_set(self):
        return frozenset(
            o.strip() for o in self.allowed_origins.split(",") if o.strip())


# Explicit allowed-key set: an attribute-existence check would also accept
# property names (mailboxes_dir, state_dir, ledger_path) and silently shadow
# them with strings. Only real dataclass fields are settable from the file.
CONFIG_KEYS = frozenset(f.name for f in fields(Config))


def require_loopback_bind(host):
    """Refuse any non-loopback bind_host. The relay is loopback-only by design
    (nginx terminates TLS in front); a wider bind would silently void the deploy
    doc, whose gates only ever probe 127.0.0.1."""
    if host == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise ConfigError(
        "bind_host %r is not loopback; the relay must bind 127.0.0.1 or ::1 and"
        " sit behind a reverse proxy" % host)


def load_config(path):
    """Parse a `key = value` config file into a Config. Keys outside the explicit
    CONFIG_KEYS set refuse (never attribute existence)."""
    cfg = Config()
    p = Path(path)
    if not p.is_file():
        raise ConfigError("config file not found: %s" % p)
    for lineno, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError("%s:%d: expected key = value" % (p, lineno))
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key not in CONFIG_KEYS:
            raise ConfigError("%s:%d: unknown config key %r" % (p, lineno, key))
        current = getattr(cfg, key)
        if isinstance(current, int):
            try:
                value = int(value)
            except ValueError:
                raise ConfigError(
                    "%s:%d: %s must be an integer" % (p, lineno, key)) from None
        setattr(cfg, key, value)
    require_loopback_bind(cfg.bind_host)
    return cfg


def ensure_dirs(cfg):
    for d in (Path(cfg.data_dir), cfg.mailboxes_dir, cfg.state_dir):
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Locking (flock is per open-file-description: two threads that each open() the
# same lock file contend, so this serializes across threads AND processes)
# ---------------------------------------------------------------------------

class _FileLock:
    def __init__(self, path):
        self.path = str(path)
        self._fd: int | None = None

    def __enter__(self):
        self._fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fd = self._fd
        if fd is None:  # never entered / already exited
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
            self._fd = None
        return False


def _atomic_write_bytes(path, data):
    """Write data to a temp file (fsync'd) then atomically rename into place."""
    path = Path(path)
    tmp = path.with_name("." + path.name + ".tmp-" + secrets.token_hex(4))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with open(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise
    os.replace(str(tmp), str(path))


# ---------------------------------------------------------------------------
# Rate / failure limiters (disk-persisted sliding window; a process restart must
# not reset a window). Both GC their own state files: an inline unlink when a
# window has emptied, plus a periodic bounded mtime sweep.
# ---------------------------------------------------------------------------

class _Limiter:
    prefix = "rate-"

    def __init__(self, state_dir, limit_per_hour, window_s=RATE_WINDOW_S):
        self.state_dir = Path(state_dir)
        self.limit = int(limit_per_hour)
        self.window_s = int(window_s)

    def _path_for(self, key):
        digest = hashlib.sha256(
            (self.prefix + key).encode("utf-8")).hexdigest()[:16]
        return self.state_dir / ("%s%s.json" % (self.prefix, digest))

    def _fresh(self, stamps, now):
        return [t for t in stamps
                if isinstance(t, (int, float)) and t > now - self.window_s]

    def sweep_stale(self, now=None, budget=None):
        """Unlink limiter files whose newest stamp is older than the window (so
        the whole window has emptied). mtime is a safe proxy: a file untouched
        for a full window can hold no live stamp, and an active writer keeps its
        mtime fresh, so the sweep never races a busy key.

        The bound is on DELETIONS, not on files examined. A cap on examinations
        (sorted(glob)[:budget]) lets fresh, lexicographically-first files starve
        reclamation of every stale file after them -- the sweep would keep
        re-examining the same fresh prefix and never reach the stale tail. Here
        the walk continues past fresh files (skipping them) and stops only once
        `budget` STALE files have actually been unlinked."""
        now = time.time() if now is None else now
        cutoff = now - self.window_s
        prefix = self.prefix
        removed = 0
        try:
            scan = os.scandir(self.state_dir)
        except OSError:
            return 0
        with scan:
            for entry in scan:
                if budget is not None and removed >= budget:
                    break
                name = entry.name
                if not (name.startswith(prefix) and name.endswith(".json")):
                    continue
                try:
                    if entry.stat().st_mtime < cutoff:
                        os.unlink(entry.path)
                        removed += 1
                except OSError:
                    continue
        return removed

    def forget(self, key):
        """Unlink one key's state file (e.g. when its mailbox is reclaimed, so
        the per-mailbox write-rate file does not outlive the mailbox)."""
        try:
            self._path_for(key).unlink()
        except OSError:
            pass


class RateLimiter(_Limiter):
    prefix = "rate-"

    def allow(self, key, now=None):
        """Record one attempt. Returns (allowed, retry_after_seconds)."""
        now = time.time() if now is None else now
        path = self._path_for(key)
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            raw = _read_all(fd)
            try:
                stamps = json.loads(raw.decode("utf-8")) if raw.strip() else []
            except ValueError:
                stamps = []
            window = self._fresh(stamps, now)
            if len(window) >= self.limit:
                allowed = False
                retry_after = max(1, int(min(window) + self.window_s - now) + 1)
            else:
                window.append(now)
                allowed = True
                retry_after = 0
            _write_all(fd, json.dumps(window).encode("utf-8"))
            return allowed, retry_after
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


class ByteRateLimiter(_Limiter):
    """Per-source sliding-window BYTE budget (records [timestamp, size] pairs and
    sums the sizes inside the window). Bounds how many bytes one source can
    write per hour so a single source cannot fill the shared global byte cap and
    wedge every tenant for a TTL. Self-healing: expired stamps simply age out of
    the window, so there is no delete-time attribution problem (unlike a durable
    per-source total, which would need to know which source wrote each freed
    blob)."""

    prefix = "srcbytes-"

    def _fresh_pairs(self, entries, now):
        out = []
        for e in entries:
            if (isinstance(e, (list, tuple)) and len(e) == 2
                    and isinstance(e[0], (int, float))
                    and isinstance(e[1], (int, float))
                    and not isinstance(e[0], bool)
                    and e[0] > now - self.window_s):
                out.append([float(e[0]), int(e[1])])
        return out

    def charge(self, key, size, now=None):
        """Charge `size` bytes against the source's window. Returns
        (allowed, retry_after_seconds). On refusal the window is left unchanged
        (the rejected bytes are not counted)."""
        now = time.time() if now is None else now
        size = int(size)
        fd = os.open(str(self._path_for(key)), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            raw = _read_all(fd)
            try:
                entries = json.loads(raw.decode("utf-8")) if raw.strip() else []
            except ValueError:
                entries = []
            window = self._fresh_pairs(entries, now)
            used = sum(e[1] for e in window)
            if used + size > self.limit:
                retry = max(1, int(min(e[0] for e in window)
                                   + self.window_s - now) + 1) if window else 1
                _write_all(fd, json.dumps(window).encode("utf-8"))
                return False, retry
            window.append([now, size])
            _write_all(fd, json.dumps(window).encode("utf-8"))
            return True, 0
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


class FailureLimiter(_Limiter):
    """Per-source AUTH-FAILURE budget. Consulted BEFORE any token compare so a
    credential-less flood hits a disk-backed 429 wall instead of one journal
    line per request (journald rate-limits per service and fail2ban reads that
    journal; an unthrottled 401 flood would drown the AUTHFAIL lines the ban
    logic needs). Disk, never module globals: a restart must not reset it."""

    prefix = "authfail-"

    def _stamps(self, path, now):
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return []
        try:
            stamps = json.loads(raw) if raw.strip() else []
        except ValueError:
            return []
        return self._fresh(stamps, now)

    def blocked(self, key, now=None):
        """Read-only check: (blocked, retry_after_s). Never creates state, so
        already-blocked flood traffic costs one small file read each. If the
        window has emptied it reclaims the file inline (locked re-check)."""
        now = time.time() if now is None else now
        path = self._path_for(key)
        window = self._stamps(path, now)
        if not window:
            self._unlink_if_empty(path, now)
            return False, 0
        if len(window) < self.limit:
            return False, 0
        return True, max(1, int(min(window) + self.window_s - now) + 1)

    def _unlink_if_empty(self, path, now):
        """Inline GC: unlink a file whose window has fully emptied. Re-checks
        under the lock so it cannot race a concurrent record() that just
        appended a fresh stamp. A benign race (an orphaned empty file) is caught
        by the periodic mtime sweep."""
        try:
            fd = os.open(str(path), os.O_RDWR)
        except FileNotFoundError:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            raw = _read_all(fd)
            try:
                stamps = json.loads(raw.decode("utf-8")) if raw.strip() else []
            except ValueError:
                stamps = []
            if not self._fresh(stamps, now):
                Path(path).unlink(missing_ok=True)
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def record(self, key, now=None):
        """Append one failure stamp under an exclusive lock."""
        now = time.time() if now is None else now
        fd = os.open(str(self._path_for(key)), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            raw = _read_all(fd)
            try:
                stamps = json.loads(raw.decode("utf-8")) if raw.strip() else []
            except ValueError:
                stamps = []
            window = self._fresh(stamps, now)
            window.append(now)
            _write_all(fd, json.dumps(window).encode("utf-8"))
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


class SourceFailureLimiter(FailureLimiter):
    """Per-SOURCE (per /64 or IPv4, mailbox-INDEPENDENT) auth-failure budget.

    Same disk-backed sliding-window mechanism as FailureLimiter but keyed on the
    source alone and given a higher limit. It is consulted in _authz BEFORE the
    per-(source,mailbox) budget's record(), so a source that rotates mailbox ids
    to mint a fresh per-mailbox state file per request trips this source-level
    wall and stops creating files. Distinct 'authfailsrc-' prefix so its state
    files never collide with (nor are swept by) the per-mailbox 'authfail-' set."""

    prefix = "authfailsrc-"


def _read_all(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    raw = b""
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        raw += chunk
    return raw


def _write_all(fd, payload):
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    os.write(fd, payload)


# ---------------------------------------------------------------------------
# Mailbox store: opaque blobs under random mailbox ids, per-mailbox locking, a
# durable global byte ledger, and bounded (never whole-store-locked) purge.
# ---------------------------------------------------------------------------

class MailboxEntry:
    __slots__ = ("write_digest", "pull_digest", "created")

    def __init__(self, write_digest, pull_digest, created):
        self.write_digest = write_digest
        self.pull_digest = pull_digest
        self.created = created


def _ledger_read_fd(fd):
    raw = _read_all(fd)
    try:
        return max(0, int(raw.decode("utf-8").strip() or "0"))
    except ValueError:
        return 0


def _ledger_write_fd(fd, n):
    _write_all(fd, str(int(n)).encode("utf-8"))
    os.fsync(fd)


class Store:
    def __init__(self, cfg):
        self.cfg = cfg
        self.mailboxes_dir = cfg.mailboxes_dir
        self.ledger_path = cfg.ledger_path
        self.index = {}
        self.index_lock = threading.Lock()
        # Constant-time auth compares against this when a mailbox is absent, so
        # the auth path branches identically for present and absent mailboxes.
        self.dummy_digest = secrets.token_bytes(32)
        self._purge_cursor = 0
        # Test seam: called inside per-mailbox purge while holding ONLY that
        # mailbox's lock, to prove concurrent ops proceed during a purge.
        self.purge_hook: "Callable[[str], None] | None" = None
        # Test seam: called inside add_blob while holding ONLY the target
        # mailbox's write lock (BEFORE the global ledger lock), to prove the
        # write path locks per-mailbox and not with a global lock -- a swap to a
        # global lock would let a block on mailbox A stall a PUT to mailbox B.
        self.add_hook: "Callable[[str], None] | None" = None
        # Set by build_server so a reclaimed mailbox can drop its per-mailbox
        # write-rate limiter file (None in standalone/CLI use).
        self.write_rate: "RateLimiter | None" = None

    # -- paths --------------------------------------------------------------

    def _mailbox_dir(self, mid):
        return self.mailboxes_dir / mid

    def _blobs_dir(self, mid):
        return self.mailboxes_dir / mid / "blobs"

    def _mbox_lock(self, mid):
        return self.mailboxes_dir / mid / "mbox.lock"

    def _touch_mailbox(self, mid):
        """Stamp the mailbox dir mtime as LAST ACTIVITY. Idle reclamation keys
        off this, never off creation time: a pull-to-delete mailbox is empty in
        steady state, so keying reclamation off creation would silently destroy
        an actively-used mailbox mailbox_idle_days after it was created (both
        capabilities -> 401). Every add/list/pull/delete calls this."""
        try:
            os.utime(self._mailbox_dir(mid))
        except OSError:
            pass

    @contextlib.contextmanager
    def _ledger_fd(self):
        fd = os.open(str(self.ledger_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield fd
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    # -- index / auth -------------------------------------------------------

    def index_get(self, mid):
        # dict.get is atomic under the GIL; no lock, no disk, so the auth path
        # is constant-time and never reveals which mailboxes exist.
        return self.index.get(mid)

    def mailbox_count(self):
        return len(self.index)

    # -- reconciliation (startup) ------------------------------------------

    def reconcile(self):
        """Rebuild the in-memory index from meta.json files and RECOMPUTE the
        global byte ledger by summing every blob on disk. This is the startup
        sweep that makes the ledger a real cap rather than a fiction: any drift
        from a crash mid-add/mid-delete is corrected here."""
        new_index = {}
        total = 0
        if self.mailboxes_dir.is_dir():
            for mdir in self.mailboxes_dir.iterdir():
                if not mdir.is_dir():
                    continue
                mid = mdir.name
                if not MAILBOX_ID_RE.match(mid):
                    continue
                try:
                    meta = json.loads((mdir / "meta.json").read_text("utf-8"))
                    wd = bytes.fromhex(meta["write_digest"])
                    pd = bytes.fromhex(meta["pull_digest"])
                    created = str(meta.get("created", ""))
                except (OSError, ValueError, KeyError):
                    continue
                new_index[mid] = MailboxEntry(wd, pd, created)
                bdir = mdir / "blobs"
                if bdir.is_dir():
                    # A SIGKILL mid-PUT leaves an uncommitted .<hex>.tmp behind
                    # (written before the ledger lock, so it is invisible to the
                    # committed-blob glob and never counted). Startup is single-
                    # threaded with no add in flight, so unlink every stray tmp;
                    # it was never committed, so it is not summed into the ledger.
                    for tp in bdir.glob(".*.tmp"):
                        try:
                            tp.unlink()
                        except OSError:
                            continue
                    for bp in bdir.glob("bl-*.blob"):
                        try:
                            total += bp.stat().st_size
                        except OSError:
                            continue
        with self.index_lock:
            self.index = new_index
        with self._ledger_fd() as lfd:
            _ledger_write_fd(lfd, total)
        return total

    # -- create -------------------------------------------------------------

    def create_mailbox(self):
        """Mint a mailbox: random 128-bit id, random write_cap + pull_token.
        Only digests are stored. Enforces max_mailboxes under the index lock
        (O(1), never a store walk)."""
        write_cap = secrets.token_urlsafe(32)
        pull_token = secrets.token_urlsafe(32)
        wd = hashlib.sha256(write_cap.encode("utf-8")).digest()
        pd = hashlib.sha256(pull_token.encode("utf-8")).digest()
        created = utcnow().strftime(RECEIVED_FMT)
        with self.index_lock:
            if len(self.index) >= self.cfg.max_mailboxes:
                raise RelayFull("mailbox capacity reached")
            for _ in range(8):
                mid = secrets.token_hex(16)
                if mid not in self.index and not self._mailbox_dir(mid).exists():
                    break
            else:  # pragma: no cover - 8 collisions in 128-bit space
                raise RelayError("could not allocate a mailbox id")
            bdir = self._blobs_dir(mid)
            bdir.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self._mailbox_dir(mid), 0o700)
            os.chmod(bdir, 0o700)
            meta = {"write_digest": wd.hex(), "pull_digest": pd.hex(),
                    "created": created}
            _atomic_write_bytes(self._mailbox_dir(mid) / "meta.json",
                                json.dumps(meta).encode("utf-8"))
            # Pre-create the lock file so _FileLock never has to create it in a
            # dir a concurrent GC might be removing.
            lp = self._mbox_lock(mid)
            os.close(os.open(str(lp), os.O_RDWR | os.O_CREAT, 0o600))
            self.index[mid] = MailboxEntry(wd, pd, created)
        return mid, write_cap, pull_token

    # -- add ----------------------------------------------------------------

    def add_blob(self, mid, data, now=None):
        """Store one OPAQUE blob. data is never decoded/parsed. The blob file is
        fsync'd to a temp path first, then made live and counted into the ledger
        in ONE critical section (per-mailbox lock -> ledger lock)."""
        now = utcnow() if now is None else now
        size = len(data)
        if size > self.cfg.max_blob_bytes:
            raise BlobTooLarge()
        blobs_dir = self._blobs_dir(mid)
        if not blobs_dir.is_dir():
            raise MailboxNotFound()
        tmp = blobs_dir / ("." + secrets.token_hex(8) + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with open(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            Path(tmp).unlink(missing_ok=True)
            raise
        committed = False
        try:
            with _FileLock(self._mbox_lock(mid)):
                # Test seam: runs while holding ONLY this mailbox's write lock,
                # and BEFORE the global ledger lock, so a block here cannot stall
                # an unrelated mailbox unless the write path were (wrongly) using
                # a global lock.
                if self.add_hook is not None:
                    self.add_hook(mid)
                self._touch_mailbox(mid)
                existing = sorted(blobs_dir.glob("bl-*.blob"))
                if len(existing) >= self.cfg.max_blobs_per_mailbox:
                    raise MailboxFull()
                mbox_bytes = 0
                for p in existing:
                    try:
                        mbox_bytes += p.stat().st_size
                    except OSError:
                        continue
                if mbox_bytes + size > self.cfg.max_mailbox_bytes:
                    raise MailboxFull()
                for _ in range(8):
                    bid = "bl-%s.%s" % (now.strftime(BLOB_TS_FMT),
                                        secrets.token_hex(6))
                    final = blobs_dir / (bid + ".blob")
                    if not final.exists():
                        break
                else:  # pragma: no cover - 8 collisions in one second
                    raise RelayError("could not allocate a blob id")
                with self._ledger_fd() as lfd:
                    total = _ledger_read_fd(lfd)
                    if total + size > self.cfg.max_total_bytes:
                        raise RelayFull("relay storage full")
                    os.replace(str(tmp), str(final))
                    _ledger_write_fd(lfd, total + size)
                    committed = True
                return bid, size
        finally:
            if not committed:
                Path(tmp).unlink(missing_ok=True)

    # -- read / pull / delete ----------------------------------------------

    def list_blobs(self, mid):
        blobs_dir = self._blobs_dir(mid)
        out = []
        with _FileLock(self._mbox_lock(mid)):
            self._touch_mailbox(mid)
            for p in sorted(blobs_dir.glob("bl-*.blob")):
                bid = p.name[:-len(".blob")]
                try:
                    size = p.stat().st_size
                except OSError:
                    continue
                out.append({"blob_id": bid, "size": size,
                            "received": _received_from_id(bid)})
        return out

    def pull_blob(self, mid, bid):
        """Delete-on-pull: read the bytes, then remove the file and decrement the
        ledger in one critical section, and return the captured bytes. At-most-
        once: if the network send fails after this returns, the blob is gone
        (documented residual; messages are resendable)."""
        path = self._blobs_dir(mid) / (bid + ".blob")
        with _FileLock(self._mbox_lock(mid)):
            self._touch_mailbox(mid)
            try:
                data = path.read_bytes()
            except FileNotFoundError:
                return None
            size = len(data)
            with self._ledger_fd() as lfd:
                total = _ledger_read_fd(lfd)
                try:
                    os.remove(str(path))
                except FileNotFoundError:
                    return None
                _ledger_write_fd(lfd, max(0, total - size))
            return data

    def delete_blob(self, mid, bid):
        path = self._blobs_dir(mid) / (bid + ".blob")
        with _FileLock(self._mbox_lock(mid)):
            self._touch_mailbox(mid)
            try:
                size = path.stat().st_size
            except FileNotFoundError:
                return False
            with self._ledger_fd() as lfd:
                total = _ledger_read_fd(lfd)
                try:
                    os.remove(str(path))
                except FileNotFoundError:
                    return False
                _ledger_write_fd(lfd, max(0, total - size))
            return True

    # -- purge (bounded; never a global lock across a full-store walk) ------

    def _all_mailbox_ids(self):
        # A lock-free directory listing (O(#mailboxes), no blob walk, no lock).
        if not self.mailboxes_dir.is_dir():
            return []
        return sorted(d.name for d in self.mailboxes_dir.iterdir()
                      if d.is_dir() and MAILBOX_ID_RE.match(d.name))

    def purge_mailbox(self, mid, now=None):
        """Purge expired blobs in ONE mailbox under ONLY that mailbox's lock.
        The global ledger lock is grabbed briefly per deletion (O(1)), never
        held across the walk. GCs the mailbox itself when empty and idle."""
        now = utcnow() if now is None else now
        cutoff = now - timedelta(days=self.cfg.ttl_days)
        blobs_dir = self._blobs_dir(mid)
        removed = 0
        try:
            lock_ctx = _FileLock(self._mbox_lock(mid))
        except OSError:
            return 0
        with lock_ctx:
            if self.purge_hook is not None:
                self.purge_hook(mid)
            if not blobs_dir.is_dir():
                return 0
            for p in sorted(blobs_dir.glob("bl-*.blob")):
                bid = p.name[:-len(".blob")]
                expired = _blob_expired(bid, p, cutoff)
                if not expired:
                    continue
                try:
                    size = p.stat().st_size
                except OSError:
                    continue
                with self._ledger_fd() as lfd:
                    total = _ledger_read_fd(lfd)
                    try:
                        os.remove(str(p))
                    except FileNotFoundError:
                        continue
                    _ledger_write_fd(lfd, max(0, total - size))
                removed += 1
            self._sweep_orphan_tmps(blobs_dir, now)
            self._maybe_gc_mailbox(mid, blobs_dir, now)
        return removed

    def _sweep_orphan_tmps(self, blobs_dir, now):
        """Unlink uncommitted .<hex>.tmp files a SIGKILL mid-PUT left behind.
        Only those older than a generous grace are removed: a live add_blob
        writes+fsyncs+commits its tmp in milliseconds, so a tmp older than the
        grace is definitively orphaned and cannot race an in-flight write (which
        would also be serialized behind the mailbox lock we hold here)."""
        cutoff = now - timedelta(seconds=_TMP_ORPHAN_GRACE_S)
        for tp in blobs_dir.glob(".*.tmp"):
            try:
                mt = datetime.fromtimestamp(tp.stat().st_mtime, timezone.utc)
            except OSError:
                continue
            if mt < cutoff:
                try:
                    tp.unlink()
                except OSError:
                    continue

    def _maybe_gc_mailbox(self, mid, blobs_dir, now):
        """Reclaim an empty mailbox that has been idle past mailbox_idle_days, so
        an abandoned mailbox does not permanently consume the max_mailboxes
        budget. Runs while this mailbox's lock is held.

        Idle is measured from LAST ACTIVITY (the mailbox dir mtime, touched on
        every add/list/pull/delete), NEVER from creation time. A pull-to-delete
        mailbox is empty in steady state; keying reclamation off creation would
        destroy an actively-used mailbox mailbox_idle_days after creation the
        first time a purge found it momentarily empty -- both capabilities gone,
        silent 401. Empty + recently active => keep; empty + genuinely idle =>
        reclaim."""
        if any(blobs_dir.glob("bl-*.blob")):
            return
        try:
            last_used = datetime.fromtimestamp(
                self._mailbox_dir(mid).stat().st_mtime, timezone.utc)
        except OSError:
            return
        if last_used >= now - timedelta(days=self.cfg.mailbox_idle_days):
            return
        with self.index_lock:
            self.index.pop(mid, None)
        shutil.rmtree(self._mailbox_dir(mid), ignore_errors=True)
        # Drop the per-mailbox write-rate state file so it does not outlive the
        # mailbox (10k mailboxes would otherwise leak 10k rate-*.json files).
        if self.write_rate is not None:
            self.write_rate.forget("write:" + mid)

    def purge_tick(self, budget=None, now=None):
        """Process up to `budget` mailboxes this tick (advancing a cursor across
        ticks). Each mailbox is handled under its own lock; no global lock is
        ever held across this loop."""
        now = utcnow() if now is None else now
        budget = self.cfg.purge_budget if budget is None else budget
        mids = self._all_mailbox_ids()
        if not mids:
            self._purge_cursor = 0
            return 0
        start = self._purge_cursor % len(mids) if mids else 0
        slice_ = mids[start:start + budget]
        removed = 0
        for mid in slice_:
            try:
                removed += self.purge_mailbox(mid, now)
            except OSError:
                continue
        self._purge_cursor = start + budget
        if self._purge_cursor >= len(mids):
            self._purge_cursor = 0
        return removed

    def purge_all(self, now=None):
        """Whole-store purge for startup/CLI (single-threaded contexts). Still
        one mailbox lock at a time, never a global store lock."""
        now = utcnow() if now is None else now
        removed = 0
        for mid in self._all_mailbox_ids():
            try:
                removed += self.purge_mailbox(mid, now)
            except OSError:
                continue
        return removed


def _received_from_id(bid):
    try:
        dt = datetime.strptime(bid[3:3 + 16], BLOB_TS_FMT).replace(
            tzinfo=timezone.utc)
        return dt.strftime(RECEIVED_FMT)
    except (ValueError, IndexError):
        return ""


def _blob_expired(bid, path, cutoff):
    try:
        dt = datetime.strptime(bid[3:3 + 16], BLOB_TS_FMT).replace(
            tzinfo=timezone.utc)
        return dt < cutoff
    except (ValueError, IndexError):
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        except OSError:
            return False
        return mtime < cutoff


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class RelayHandler(BaseHTTPRequestHandler):
    server_version = "keyweave-relay"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30
    # Narrow the inherited BaseServer type so the dynamically-attached relay
    # attributes (cfg/store/limiters) type-check; RelayHTTPServer sets them all.
    # (Narrowing a subclass onto a mutable inherited attribute is exactly the
    # dynamic-attribute case the spec flags as a false positive.)
    server: "RelayHTTPServer"  # pyright: ignore[reportIncompatibleVariableOverride]

    # -- logging: never bodies, tokens, ids, or paths -----------------------

    def log_request(self, code="-", size="-"):
        # The stdlib default logs self.requestline, which carries the mailbox id.
        # Log only the method and status; never the request line/path.
        LOG.debug("http %s %s", sanitize_line(self.command, 8), str(code))

    def log_message(self, format, *args):  # noqa: A002 (match base signature)
        LOG.debug("http %s", redact_path(sanitize_line(format % args)))

    def log_error(self, format, *args):  # noqa: A002 (match base signature)
        LOG.info("http-error %s", redact_path(sanitize_line(format % args)))

    def _client(self):
        """Best-effort client address for logs and the failure budget.

        X-Forwarded-For is a plain request header any client can send, so it is
        IGNORED unless the operator set trust_forwarded_for = 1 (safe only when
        the proxy overwrites/pins it to the peer it actually saw). When trusted,
        the LAST hop wins -- the only entry the remote client cannot choose."""
        if self.server.cfg.trust_forwarded_for:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                last = forwarded.split(",")[-1].strip()
                cleaned = re.sub(r"[^0-9a-fA-F.:]", "", last)[:45]
                # Only honor a forwarded value that actually parses as an IP.
                # A non-IP (garbage or a client-chosen token) must fall back to
                # the socket peer, never mint a per-value failure-budget key.
                if cleaned:
                    try:
                        ipaddress.ip_address(cleaned)
                        return cleaned
                    except ValueError:
                        pass
        return self.client_address[0]

    # -- CORS ---------------------------------------------------------------

    def _cors_origin(self):
        """The request Origin IF it is in the configured allowlist, else None.
        Never '*': the client is served from a distinct trust domain (spec R2)
        and sends credentials (the bearer capability), so the reflected origin
        must be exact."""
        origin = self.headers.get("Origin", "")
        if origin and origin in self.server.cfg.allowed_origin_set:
            return origin
        return None

    def _send_cors_headers(self):
        # NO Access-Control-Allow-Credentials. Authorization is a bearer capability in a
        # header; the relay sets no cookie and reads none, and the browser client sends
        # credentials: 'omit'. Allowing credentialed cross-origin requests would grant a
        # privilege nothing here uses, and it is the half of the CORS rules that turns a
        # future allowlist mistake into account-scoped damage rather than a blocked read.
        allow = self._cors_origin()
        if allow:
            self.send_header("Access-Control-Allow-Origin", allow)
            self.send_header("Vary", "Origin")

    # -- responses ----------------------------------------------------------

    def _send_json(self, code, obj, extra_headers=None):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._send_cors_headers()
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        if code >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _send_octet(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._send_cors_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _send_no_content(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _not_found(self):
        self._send_json(404, {"error": "not found"})

    # -- auth ---------------------------------------------------------------

    def _bearer(self):
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            token = header[len("Bearer "):].strip()
            return token or None
        return None

    def _authz(self, mid, role):
        """Constant-time capability check for `role` ('write' or 'pull').

        Order (rate-limit BEFORE auth): the per-source failure budget is
        consulted FIRST, so a credential-less flood hits a disk-backed 429 wall
        and spends no per-request journal volume. The token compare then runs
        against the role's stored digest, or a random dummy digest when the
        mailbox does not exist -- identical work either way, no disk I/O, so the
        response never reveals which mailboxes exist."""
        client = self._client()
        # Key the auth-failure budget per (SOURCE, MAILBOX), not per source
        # alone. Behind nginx with trust_forwarded_for=0 every request is
        # attributed to the same proxy peer, so a source-only key lets one
        # abuser flooding mailbox A drive the shared budget to 429 and lock out
        # every OTHER mailbox too. Scoping the budget to the mailbox means a
        # flood against A cannot deny service to B. The AUTHFAIL log line still
        # carries the client address, so fail2ban still bans the real IP.
        src_key = failkey(client)
        key = src_key + "|mbx:" + mid
        entry = self.server.store.index_get(mid)
        # The per-SOURCE wall is consulted/recorded ONLY when the target mailbox
        # does NOT exist. That is the whole id-rotation surface: a source that
        # rotates a fresh (non-existent) mailbox id per request would otherwise
        # mint one new per-(source,mailbox) authfail file per request forever
        # (inode growth that defeats the failure limiter), so those requests hit
        # the higher source-level budget which 429s the source and stops it
        # minting new files. But under shared attribution (trust_forwarded_for=0,
        # every client == the proxy peer) gating EXISTING mailboxes on that
        # shared wall would let a flood -- or id-rotation elsewhere -- 429 every
        # tenant and break the per-(source,mailbox) isolation. So requests to a
        # REAL mailbox never touch the source wall: they are governed solely by
        # the per-mailbox budget (which isolates a single-mailbox flood) and are
        # already bounded in number by max_mailboxes.
        consult_source = entry is None
        if consult_source:
            src_blocked, src_retry = self.server.auth_guard_source.blocked(
                src_key)
            if src_blocked:
                LOG.debug("AUTHLIMIT-SRC client=%s", sanitize_line(client, 45))
                self._send_json(429, {"error": "rate limited"},
                                extra_headers={"Retry-After": str(src_retry)})
                return False
        blocked, retry = self.server.auth_guard.blocked(key)
        if blocked:
            LOG.debug("AUTHLIMIT client=%s", sanitize_line(client, 45))
            self._send_json(429, {"error": "rate limited"},
                            extra_headers={"Retry-After": str(retry)})
            return False
        presented = self._bearer()
        if role == "write":
            expected = (entry.write_digest if entry is not None
                        else self.server.store.dummy_digest)
        else:
            expected = (entry.pull_digest if entry is not None
                        else self.server.store.dummy_digest)
        presented_digest = hashlib.sha256(
            (presented or "").encode("utf-8")).digest()
        match = hmac.compare_digest(presented_digest, expected)
        if match and entry is not None and presented is not None:
            return True
        # Always record the per-mailbox wall (isolates a single-mailbox flood).
        # Record the per-SOURCE wall too ONLY for a non-existent target, so
        # id-rotation trips it and cannot mint an unbounded per-(source,mailbox)
        # keyspace, while a flood against a REAL mailbox never touches the shared
        # source wall (per-tenant isolation holds under shared attribution).
        if consult_source:
            self.server.auth_guard_source.record(src_key)
        self.server.auth_guard.record(key)
        # No mailbox id and no request path in the log line.
        LOG.warning("AUTHFAIL client=%s method=%s role=%s reason=%s",
                    sanitize_line(client, 45), sanitize_line(self.command, 8),
                    role, "no-auth" if presented is None else "bad-token")
        self._send_json(401, {"error": "unauthorized"},
                        extra_headers={"WWW-Authenticate": "Bearer"})
        return False

    # -- body helpers -------------------------------------------------------

    def _content_length(self):
        raw = self.headers.get("Content-Length")
        if raw is None:
            return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    def _drain(self, content_length):
        remaining = min(max(0, content_length), DRAIN_CAP)
        try:
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.rfile.read(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _pathonly(self):
        return urllib.parse.urlsplit(self.path).path

    # -- dispatch -----------------------------------------------------------

    def _guarded(self, route):
        """Last-ditch wrap: ANY unexpected exception becomes a clean 500 with a
        single sanitized log line, never a dropped connection or a traceback."""
        try:
            route()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as exc:
            # Log the exception TYPE only, never its str(): an OSError carries a
            # filesystem path <data_dir>/mailboxes/<mid>/... in its message, and
            # the relay must never emit a mailbox id. (redact_path is applied as
            # belt-and-suspenders in case a type name ever changes.)
            LOG.error("UNHANDLED method=%s type=%s",
                      sanitize_line(self.command, 8),
                      redact_path(type(exc).__name__))
            try:
                self._send_json(500, {"error": "internal error"})
            except Exception:
                self.close_connection = True

    def do_POST(self):
        self._guarded(self._route_post)

    def do_PUT(self):
        self._guarded(self._route_put)

    def do_GET(self):
        self._guarded(self._route_get)

    def do_DELETE(self):
        self._guarded(self._route_delete)

    def do_OPTIONS(self):
        self._guarded(self._route_options)

    def _route_options(self):
        """Answer a CORS preflight from an allowlisted origin. Without this a
        browser client on the (distinct) app origin gets a 501 and cannot talk
        to the relay at all -- which breaks the split-trust-domain architecture
        (spec R2). A non-allowlisted origin gets a 204 with NO ACAO, so the
        browser blocks the real request."""
        allow = self._cors_origin()
        self.send_response(204)
        if allow:
            self.send_header("Access-Control-Allow-Origin", allow)
            # No Allow-Credentials here either; see _send_cors_headers.
            self.send_header("Access-Control-Allow-Methods",
                             "GET, PUT, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers",
                             "Authorization, Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Vary", "Origin")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- routes -------------------------------------------------------------

    def _route_post(self):
        if not RE_MAILBOXES.match(self._pathonly()):
            self._not_found()
            return
        clen = self._content_length()
        if clen:
            self._drain(clen)
        client = self._client()
        allowed, retry = self.server.create_rate.allow("create:" + failkey(client))
        if not allowed:
            self._send_json(429, {"error": "rate limited"},
                            extra_headers={"Retry-After": str(retry)})
            return
        try:
            mid, write_cap, pull_token = self.server.store.create_mailbox()
        except RelayFull:
            self._send_json(507, {"error": "mailbox capacity reached",
                                  "limit": self.server.cfg.max_mailboxes})
            return
        LOG.info("MAILBOX created")  # no id
        self._send_json(201, {"mailbox_id": mid, "write_cap": write_cap,
                              "pull_token": pull_token})

    def _route_put(self):
        match = RE_BLOBS.match(self._pathonly())
        if not match:
            self._not_found()
            return
        mid = match.group(1)
        if not self._authz(mid, "write"):
            return
        cfg = self.server.cfg
        clen = self._content_length()
        if clen is None:
            self._send_json(411, {"error": "length required"})
            return
        if clen < 0:
            self._send_json(422, {"error": "invalid Content-Length"})
            return
        # Oversize is rejected from the Content-Length ALONE: the body is drained
        # and discarded, never read into memory and never parsed.
        if clen > cfg.max_blob_bytes:
            self._drain(clen)
            self._send_json(413, {"error": "blob too large",
                                  "limit_bytes": cfg.max_blob_bytes})
            return
        allowed, retry = self.server.write_rate.allow("write:" + mid)
        if not allowed:
            self._drain(clen)
            self._send_json(429, {"error": "rate limited"},
                            extra_headers={"Retry-After": str(retry)})
            return
        # Per-SOURCE byte budget: charge the declared Content-Length (already
        # <= max_blob_bytes) against this source's sliding-window byte quota, so
        # a single source cannot race the shared global byte cap to full and
        # wedge every other tenant (507) for a TTL. The global cap is then an
        # AVAILABILITY boundary, not a per-source one.
        src_ok, src_retry = self.server.source_bytes.charge(
            failkey(self._client()), clen)
        if not src_ok:
            self._drain(clen)
            self._send_json(429, {"error": "rate limited"},
                            extra_headers={"Retry-After": str(src_retry)})
            return
        raw = self._read_exact(clen)
        if raw is None:
            self._send_json(422, {"error": "request body was truncated"})
            return
        # raw is OPAQUE. It is stored byte-for-byte and never decoded.
        try:
            blob_id, size = self.server.store.add_blob(mid, raw)
        except BlobTooLarge:
            self._send_json(413, {"error": "blob too large",
                                  "limit_bytes": cfg.max_blob_bytes})
            return
        except MailboxFull:
            self._send_json(507, {"error": "mailbox full"})
            return
        except RelayFull:
            self._send_json(507, {"error": "relay storage full"})
            return
        except MailboxNotFound:
            self._not_found()
            return
        LOG.info("BLOB stored size=%d", size)  # no ids
        self._send_json(201, {"blob_id": blob_id, "size": size})

    def _route_get(self):
        path = self._pathonly()
        match = RE_BLOBS.match(path)
        if match:
            mid = match.group(1)
            if not self._authz(mid, "pull"):
                return
            self._send_json(200, {"blobs": self.server.store.list_blobs(mid)})
            return
        match = RE_BLOB.match(path)
        if match:
            mid, blob_id = match.group(1), match.group(2)
            if not self._authz(mid, "pull"):
                return
            data = self.server.store.pull_blob(mid, blob_id)
            if data is None:
                self._not_found()
                return
            LOG.info("BLOB pulled size=%d", len(data))  # no ids
            self._send_octet(200, data)
            return
        self._not_found()

    def _route_delete(self):
        match = RE_BLOB.match(self._pathonly())
        if not match:
            self._not_found()
            return
        mid, blob_id = match.group(1), match.group(2)
        if not self._authz(mid, "pull"):
            return
        if self.server.store.delete_blob(mid, blob_id):
            LOG.info("BLOB deleted")  # no ids
            self._send_no_content()
        else:
            self._not_found()


# ---------------------------------------------------------------------------
# Server assembly
# ---------------------------------------------------------------------------

class _PurgeThread(threading.Thread):
    def __init__(self, server):
        super().__init__(daemon=True)
        self.server = server
        self._stop = threading.Event()

    def run(self):
        cfg = self.server.cfg
        interval = max(1, cfg.purge_interval_s)
        while not self._stop.wait(interval):
            try:
                self.server.store.purge_tick()
                now = time.time()
                self.server.create_rate.sweep_stale(now, cfg.purge_budget)
                self.server.write_rate.sweep_stale(now, cfg.purge_budget)
                self.server.auth_guard.sweep_stale(now, cfg.purge_budget)
                self.server.auth_guard_source.sweep_stale(now, cfg.purge_budget)
                self.server.source_bytes.sweep_stale(now, cfg.purge_budget)
            except Exception as exc:  # pragma: no cover - defensive
                LOG.error("PURGE-TICK failed: %s", sanitize_line(exc, 160))

    def stop(self):
        self._stop.set()


class RelayHTTPServer(ThreadingHTTPServer):
    """Threaded loopback server with the relay's dynamically-attached state
    declared as typed attributes (so the handler type-checks) and a larger
    listen backlog. The stdlib default request_queue_size is 5, so a burst of
    connections beyond that gets ECONNRESET before a worker accepts them; 128
    matches the documented nginx limit_conn in front."""

    daemon_threads = True
    request_queue_size = 128

    cfg: "Config"
    store: "Store"
    create_rate: "RateLimiter"
    write_rate: "RateLimiter"
    source_bytes: "ByteRateLimiter"
    auth_guard: "FailureLimiter"
    auth_guard_source: "SourceFailureLimiter"
    purge_thread: "_PurgeThread | None"


def build_server(cfg):
    """Validate config, reconcile the store from disk, and return a ready
    loopback RelayHTTPServer. Never starts half-configured."""
    require_loopback_bind(cfg.bind_host)
    ensure_dirs(cfg)
    if not cfg.trust_forwarded_for:
        # The relay binds loopback only and sits behind nginx, so with XFF
        # untrusted EVERY request is attributed to the proxy peer (typically
        # 127.0.0.1). The per-source failure budget then cannot distinguish
        # clients, and any AUTHFAIL line fed to fail2ban would ban the proxy
        # itself -- a total outage. Say so loudly at startup, and name the ONE
        # coherent remedy (nginx real_ip alone does NOT reach a loopback
        # upstream -- see nginx-location.conf).
        LOG.warning(
            "STARTUP trust_forwarded_for=0: all clients will be attributed to"
            " the proxy peer; set trust_forwarded_for=1 in relay.conf AND nginx"
            " 'proxy_set_header X-Forwarded-For $remote_addr' (overwrite) so the"
            " failure budget and fail2ban see real client addresses")
    store = Store(cfg)
    store.reconcile()
    store.purge_all()
    server = RelayHTTPServer((cfg.bind_host, cfg.bind_port), RelayHandler)
    server.cfg = cfg
    server.store = store
    server.create_rate = RateLimiter(cfg.state_dir, cfg.create_rate_per_hour)
    server.write_rate = RateLimiter(cfg.state_dir, cfg.write_rate_per_hour)
    server.source_bytes = ByteRateLimiter(
        cfg.state_dir, cfg.max_source_write_bytes_per_hour)
    server.auth_guard = FailureLimiter(cfg.state_dir, cfg.auth_fail_limit_per_hour)
    server.auth_guard_source = SourceFailureLimiter(
        cfg.state_dir, cfg.auth_fail_source_limit_per_hour)
    # Let a reclaimed mailbox drop its per-mailbox write-rate state file.
    store.write_rate = server.write_rate
    server.purge_thread = None
    return server


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _setup_logging():
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s keyweave-relay %(message)s", "%Y-%m-%dT%H:%M:%S"))
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)


def cmd_serve(cfg):
    os.umask(0o077)
    try:
        server = build_server(cfg)
    except ConfigError as exc:
        print("keyweave-relay: refusing to start: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("keyweave-relay: cannot bind %s:%d (%s). Is another relay already"
              " running?" % (cfg.bind_host, cfg.bind_port, exc), file=sys.stderr)
        return 1
    if cfg.purge_interval_s > 0:
        server.purge_thread = _PurgeThread(server)
        server.purge_thread.start()
    LOG.info("listening on %s:%d (version %s)",
             cfg.bind_host, cfg.bind_port, __version__)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server.purge_thread is not None:
            server.purge_thread.stop()
        server.server_close()
    return 0


def cmd_status(cfg):
    print("keyweave-relay %s" % __version__)
    print("bind: %s:%d" % (cfg.bind_host, cfg.bind_port))
    print("data_dir: %s" % cfg.data_dir)
    try:
        store = Store(cfg)
        print("mailboxes: %d (cap %d)"
              % (len(store._all_mailbox_ids()), cfg.max_mailboxes))
    except OSError:
        print("mailboxes: n/a (data_dir not readable from here)")
    print("caps: blob %d B, mailbox %d B / %d blobs, total %d B"
          % (cfg.max_blob_bytes, cfg.max_mailbox_bytes,
             cfg.max_blobs_per_mailbox, cfg.max_total_bytes))
    print("rate: create %d/h per IP, write %d/h per mailbox, %d B/h per source;"
          " ttl %d days"
          % (cfg.create_rate_per_hour, cfg.write_rate_per_hour,
             cfg.max_source_write_bytes_per_hour, cfg.ttl_days))
    print("auth-fail budget: %d/h per (source,mailbox), %d/h per source;"
          " trust_forwarded_for: %s"
          % (cfg.auth_fail_limit_per_hour, cfg.auth_fail_source_limit_per_hour,
             "on" if cfg.trust_forwarded_for else "off"))
    print("cors allowed origins: %s"
          % (", ".join(sorted(cfg.allowed_origin_set)) or "(none)"))
    return 0


def cmd_purge(cfg):
    ensure_dirs(cfg)
    store = Store(cfg)
    store.reconcile()
    removed = store.purge_all()
    print("purged %d expired blob(s)" % removed)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="keyweave_relay",
        description="Keyweave mailbox relay (loopback, behind nginx)")
    parser.add_argument("--config",
                        default=os.environ.get("KEYWEAVE_RELAY_CONFIG",
                                               DEFAULT_CONFIG_PATH),
                        help="path to relay.conf")
    parser.add_argument("command", choices=["serve", "status", "purge"])
    args = parser.parse_args(argv)
    _setup_logging()
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print("keyweave-relay: %s" % exc, file=sys.stderr)
        return 2
    handlers = {"serve": cmd_serve, "status": cmd_status, "purge": cmd_purge}
    return handlers[args.command](cfg)


if __name__ == "__main__":
    sys.exit(main())
