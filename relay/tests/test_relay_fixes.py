"""Adversarial-review fix round: one reproducible test per fix. Each pins the
corrected behaviour so a regression to the flagged code turns a green suite red.

Fix map (numbers match the review):
  1  CRITICAL idle reclamation keys off LAST ACTIVITY, never creation time
  2  HIGH     XFF/self-ban: startup warning + per-(source,mailbox) budget + files
  3  HIGH     per-source byte budget so one source can't wedge the global cap
  4  HIGH     failkey normalizes IPv4-mapped IPv6 BEFORE /64 bucketing
  5  MED      sweep caps DELETIONS not examinations; reclaim drops the rate file
  6  MED      a forced OSError never leaks a mailbox path into the log
  7  MED      CORS preflight + ACAO from an origin allowlist (never '*')
  8  MED      the write path locks per-mailbox, not globally
  9  LOW      orphan .*.tmp files are swept by purge and reconcile
 10  LOW      listen backlog raised above the stdlib default of 5
 12  LOW      a non-IP forwarded value falls back to the socket peer (bounded)
"""
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from . import helper
from .helper import (create_mailbox, delete_blob, list_blobs, pull_blob,
                     put_blob, request, relay)

RELAY_DIR = Path(__file__).resolve().parents[1]


def active_conf_lines(text):
    """An nginx config with every comment stripped.

    A gate that counts LINES CONTAINING a directive counts the comments that
    QUOTE that directive too. nginx-location.conf quotes both the required
    overwrite form and the forbidden appending form in its own header, so a
    naive count reads 3 and 1 where the truth is 1 and 0. Strip from the first
    '#' to end of line, then count. No directive value in this file is quoted,
    so no '#' here is anything but a comment.
    """
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def is_full_checkout():
    """True when RELAY_DIR.parent is a full checkout, not a relay-only export.

    `git archive HEAD relay docs/NAMED-RESIDUALS.md` produces a tree holding
    the relay subtree plus the one doc file its suite reads, and nothing else.
    A full checkout also carries the client bundle and/or the git metadata.
    The distinction decides whether a MISSING docs/NAMED-RESIDUALS.md is a real
    regression (fail loudly) or a packaging gap in someone's export (skip, and
    say which archive command fixes it).
    """
    root = RELAY_DIR.parent
    return (root / ".git").exists() or (root / "client").is_dir()


def put_src(fx, mid, data, cap, src):
    """PUT a blob with an explicit X-Forwarded-For source (needs
    trust_forwarded_for=1 on the fixture)."""
    return request(fx.base, "PUT", "/v1/mailboxes/%s/blobs" % mid, token=cap,
                   data=data, content_type="application/octet-stream",
                   headers={"X-Forwarded-For": src})


def ci_headers(resp):
    return {k.lower(): v for k, v in resp.headers.items()}


# ---------------------------------------------------------------------------
# Fix 1 [CRITICAL] - idle reclamation is keyed off LAST ACTIVITY, not creation.
# ---------------------------------------------------------------------------

class IdleReclaimTests(unittest.TestCase):
    def test_recently_active_but_empty_mailbox_is_not_reclaimed(self):
        # A pull-to-delete mailbox is empty in steady state. The OLD code
        # reclaimed mailbox_idle_days after CREATION, so an actively-used mailbox
        # would vanish (both caps -> 401). Here creation is ancient but activity
        # is fresh: it must SURVIVE, and its capabilities must still work.
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, mailbox_idle_days=1)
            try:
                mid, wcap, ptok = create_mailbox(fx)
                bid = put_blob(fx, mid, b"m", wcap).json["blob_id"]
                self.assertEqual(delete_blob(fx, mid, bid, ptok).status, 204)
                # Prove creation time is NOT consulted: stamp it ancient.
                fx.store.index[mid].created = "2000-01-01T00:00:00Z"
                removed = fx.store.purge_mailbox(mid)
                self.assertEqual(removed, 0)
                self.assertIn(mid, fx.store.index)
                self.assertTrue((fx.cfg.mailboxes_dir / mid).exists())
                # Capability still live (would be a silent 401 under the bug).
                self.assertEqual(put_blob(fx, mid, b"still-here", wcap).status,
                                 201)
            finally:
                fx.close()

    def test_genuinely_idle_empty_mailbox_is_reclaimed_and_rate_file_dropped(self):
        # Empty AND no activity for > mailbox_idle_days -> reclaimed, and the
        # per-mailbox write-rate state file is unlinked with it (fix 5 tail).
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, mailbox_idle_days=1)
            try:
                mid, wcap, ptok = create_mailbox(fx)
                bid = put_blob(fx, mid, b"m", wcap).json["blob_id"]
                # The HTTP write created the mailbox's write-rate state file.
                wr_path = fx.server.write_rate._path_for("write:" + mid)
                self.assertTrue(wr_path.exists())
                self.assertEqual(delete_blob(fx, mid, bid, ptok).status, 204)
                # Backdate LAST ACTIVITY (dir mtime) to two days ago.
                old = time.time() - 2 * 86400
                os.utime(fx.cfg.mailboxes_dir / mid, (old, old))
                removed = fx.store.purge_mailbox(mid)
                self.assertEqual(removed, 0)  # no blobs removed; the box itself GC'd
                self.assertNotIn(mid, fx.store.index)
                self.assertFalse((fx.cfg.mailboxes_dir / mid).exists())
                self.assertFalse(wr_path.exists(),
                                 "write-rate file outlived the reclaimed mailbox")
            finally:
                fx.close()


# ---------------------------------------------------------------------------
# Fix 2 [HIGH] - XFF/self-ban coherence.
# ---------------------------------------------------------------------------

class XffCoherenceTests(unittest.TestCase):
    def test_startup_warns_when_forwarded_for_untrusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            _p, cfg = helper.write_env(tmp, trust_forwarded_for=0)
            with helper.LogCapture() as cap:
                server = relay.build_server(cfg)
                server.server_close()
        warns = [l for l in cap.records if l.startswith("STARTUP")]
        self.assertEqual(len(warns), 1, cap.records)
        self.assertIn("trust_forwarded_for=0", warns[0])

    def test_no_startup_warning_when_forwarded_for_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            _p, cfg = helper.write_env(tmp, trust_forwarded_for=1)
            with helper.LogCapture() as cap:
                server = relay.build_server(cfg)
                server.server_close()
        self.assertEqual([l for l in cap.records if l.startswith("STARTUP")], [])

    def test_flood_of_one_mailbox_does_not_lock_out_another(self):
        # trust_forwarded_for=0 (default): every request is the same socket peer.
        # A source-only failure key would let a flood of mailbox A 429 mailbox B
        # too. Per-(source,mailbox) keying isolates them.
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, auth_fail_limit_per_hour=3)
            try:
                mid_a, _wa, _pa = create_mailbox(fx)
                mid_b, _wb, pb = create_mailbox(fx)
                path_a = "/v1/mailboxes/%s/blobs" % mid_a
                codes_a = [request(fx.base, "GET", path_a, token="bad").status
                           for _ in range(6)]
                # A is budgeted to 429...
                self.assertIn(429, codes_a)
                # ...but B, with a CORRECT pull token, is untouched.
                self.assertEqual(list_blobs(fx, mid_b, pb).status, 200)
            finally:
                fx.close()

    def test_deploy_files_are_shipped_with_real_client_addr_config(self):
        svc = (RELAY_DIR / "keyweave-relay.service").read_text()
        ngx = (RELAY_DIR / "nginx-location.conf").read_text()
        # systemd unit: loopback-only, dynamic user.
        self.assertIn("DynamicUser=yes", svc)
        self.assertIn("IPAddressAllow=localhost", svc)
        # nginx: derives a REAL client address (real_ip and/or last-hop XFF).
        self.assertIn("real_ip_header", ngx)
        self.assertIn("X-Forwarded-For", ngx)
        self.assertIn("127.0.0.1:8151", ngx)


# ---------------------------------------------------------------------------
# Fix 3 [HIGH] - per-source byte budget bounds one source across mailboxes.
# ---------------------------------------------------------------------------

class SourceByteBudgetTests(unittest.TestCase):
    def test_one_source_is_capped_across_mailboxes_others_unaffected(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(
                tmp, trust_forwarded_for=1,
                max_source_write_bytes_per_hour=300,
                max_blob_bytes=1000, max_mailbox_bytes=10_000_000,
                max_total_bytes=10_000_000, max_blobs_per_mailbox=1000,
                write_rate_per_hour=100_000, auth_fail_limit_per_hour=100_000)
            try:
                mid_a, wa, _pa = create_mailbox(fx)
                mid_b, wb, _pb = create_mailbox(fx)
                src_x = "203.0.113.10"
                body = b"x" * 100
                # 300-byte/hour budget: 3 writes ok ACROSS the two mailboxes.
                self.assertEqual(put_src(fx, mid_a, body, wa, src_x).status, 201)
                self.assertEqual(put_src(fx, mid_b, body, wb, src_x).status, 201)
                self.assertEqual(put_src(fx, mid_a, body, wa, src_x).status, 201)
                # 4th write from the SAME source is refused on bytes (not size,
                # not count, not global cap -- all far from full).
                over = put_src(fx, mid_a, body, wa, src_x)
                self.assertEqual(over.status, 429)
                self.assertGreater(int(over.headers.get("Retry-After", "0")), 0)
                # A DIFFERENT source is unaffected.
                self.assertEqual(
                    put_src(fx, mid_b, body, wb, "203.0.113.99").status, 201)
            finally:
                fx.close()


# ---------------------------------------------------------------------------
# Fix 4 [HIGH] - IPv4-mapped IPv6 normalized before /64 bucketing.
# ---------------------------------------------------------------------------

class Ipv4MappedTests(unittest.TestCase):
    def test_mapped_addresses_get_distinct_keys_matching_their_ipv4(self):
        a = relay.failkey("::ffff:1.2.3.4")
        b = relay.failkey("::ffff:5.6.7.8")
        self.assertNotEqual(a, b, "whole IPv4 internet collapsed into one key")
        self.assertEqual(a, relay.failkey("1.2.3.4"))
        self.assertEqual(a, "v4:1.2.3.4")
        # Real (non-mapped) IPv6 still buckets to /64.
        self.assertTrue(relay.failkey("2001:db8:1:2::1").startswith("v6:/64:"))


# ---------------------------------------------------------------------------
# Fix 5 [MED] - sweep caps DELETIONS, so fresh files can't starve stale ones.
# ---------------------------------------------------------------------------

class SweepBoundsDeletionsTests(unittest.TestCase):
    def test_stale_files_are_not_starved_by_lexicographically_first_fresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            rate = relay.RateLimiter(state, limit_per_hour=10, window_s=100)
            now = time.time()
            # Fresh files that sort FIRST (the old sorted(glob)[:budget] would
            # examine only these and reclaim nothing).
            for name in ("rate-0000000000000001.json",
                         "rate-0000000000000002.json",
                         "rate-0000000000000003.json"):
                p = state / name
                p.write_text("[]")
                os.utime(p, (now, now))
            # Stale files that sort LAST.
            stale = []
            for name in ("rate-fffffffffffffff1.json",
                         "rate-fffffffffffffff2.json"):
                p = state / name
                p.write_text("[]")
                old = now - 200
                os.utime(p, (old, old))
                stale.append(p)
            removed = rate.sweep_stale(now=now, budget=2)
            self.assertEqual(removed, 2, "sweep starved behind fresh-first files")
            for p in stale:
                self.assertFalse(p.exists())


# ---------------------------------------------------------------------------
# Fix 6 [MED] - a forced OSError never leaks a mailbox path into the log.
# ---------------------------------------------------------------------------

class OsErrorLogHygieneTests(unittest.TestCase):
    def test_forced_oserror_with_mailbox_path_logs_no_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp)
            try:
                mid, wcap, _ptok = create_mailbox(fx)
                leaky = str(fx.cfg.mailboxes_dir / mid / "blobs" / "x.blob")
                err = OSError(2, "No such file or directory", leaky)
                with mock.patch.object(fx.store, "add_blob", side_effect=err):
                    with helper.LogCapture() as cap:
                        resp = put_blob(fx, mid, b"x", wcap)
            finally:
                fx.close()
        self.assertEqual(resp.status, 500)
        joined = "\n".join(cap.records)
        self.assertNotIn(mid, joined)
        self.assertNotIn(leaky, joined)
        unhandled = [l for l in cap.records if l.startswith("UNHANDLED")]
        self.assertEqual(len(unhandled), 1)

    def test_redactor_collapses_the_filesystem_form(self):
        mid = "a" * 32
        red = relay.redact_path("/var/lib/keyweave-relay/mailboxes/%s/blobs/y" % mid)
        self.assertNotIn(mid, red)
        self.assertIn("<redacted>", red)


# ---------------------------------------------------------------------------
# Fix 7 [MED] - CORS preflight + ACAO from an origin allowlist (never '*').
# ---------------------------------------------------------------------------

class CorsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.origin = "https://keyweave.example"
        self.fx = helper.RelayFixture(self.tmp.name, allowed_origins=self.origin)

    def tearDown(self):
        self.fx.close()
        self.tmp.cleanup()

    def test_preflight_from_allowed_origin_is_answered(self):
        resp = request(self.fx.base, "OPTIONS", "/v1/mailboxes",
                       headers={"Origin": self.origin,
                                "Access-Control-Request-Method": "POST"})
        self.assertEqual(resp.status, 204)
        h = ci_headers(resp)
        self.assertEqual(h.get("access-control-allow-origin"), self.origin)
        self.assertNotEqual(h.get("access-control-allow-origin"), "*")
        self.assertIn("POST", h.get("access-control-allow-methods", ""))
        self.assertIn("authorization",
                      h.get("access-control-allow-headers", "").lower())
        self.assertIn("access-control-max-age", h)

    def test_preflight_from_disallowed_origin_gets_no_acao(self):
        resp = request(self.fx.base, "OPTIONS", "/v1/mailboxes",
                       headers={"Origin": "https://evil.example",
                                "Access-Control-Request-Method": "POST"})
        self.assertEqual(resp.status, 204)
        self.assertIsNone(ci_headers(resp).get("access-control-allow-origin"))

    def test_real_response_carries_acao_for_allowed_origin(self):
        resp = request(self.fx.base, "POST", "/v1/mailboxes",
                       headers={"Origin": self.origin})
        self.assertEqual(resp.status, 201)
        self.assertEqual(ci_headers(resp).get("access-control-allow-origin"),
                         self.origin)

    def test_preflight_for_the_real_blob_put_allows_both_headers(self):
        # The request the split-origin topology actually makes (work package 7):
        # PUT /v1/mailboxes/<mid>/blobs with Authorization and
        # Content-Type: application/octet-stream. NEITHER header is CORS-safelisted
        # (only text/plain, application/x-www-form-urlencoded and multipart/form-data
        # are), so the browser sends this OPTIONS first and will not send the PUT at
        # all unless the answer names both. The POST case above does not cover it:
        # POST is a different method on a different path and the client sends it with
        # no Authorization and no body.
        mid, _cap, _pull = create_mailbox(self.fx)
        resp = request(self.fx.base, "OPTIONS",
                       "/v1/mailboxes/%s/blobs" % mid,
                       headers={"Origin": self.origin,
                                "Access-Control-Request-Method": "PUT",
                                "Access-Control-Request-Headers":
                                    "authorization,content-type"})
        self.assertEqual(resp.status, 204)
        h = ci_headers(resp)
        self.assertEqual(h.get("access-control-allow-origin"), self.origin)
        self.assertEqual(h.get("vary"), "Origin")

        methods = {m.strip().upper()
                   for m in h.get("access-control-allow-methods", "").split(",")}
        # Every method the client uses: create, write, list/pull, delete-on-pull.
        self.assertTrue({"POST", "PUT", "GET", "DELETE"} <= methods, methods)

        allowed = {v.strip().lower()
                   for v in h.get("access-control-allow-headers", "").split(",")}
        self.assertIn("authorization", allowed)
        self.assertIn("content-type", allowed)
        # Not a wildcard, deliberately. Since 2023 the Fetch standard excludes
        # Authorization from what "*" covers, so a relay that answered "*" here
        # would fail exactly this request and pass a careless test.
        self.assertNotIn("*", allowed)

    def test_the_put_that_follows_the_preflight_carries_acao(self):
        # A preflight that says yes followed by a real response with no
        # Access-Control-Allow-Origin is still a blocked request, and the browser
        # reports it as a CORS error on the PUT rather than on the OPTIONS.
        mid, cap, _pull = create_mailbox(self.fx)
        resp = request(self.fx.base, "PUT", "/v1/mailboxes/%s/blobs" % mid,
                       token=cap, data=b"x" * 32,
                       content_type="application/octet-stream",
                       headers={"Origin": self.origin})
        self.assertEqual(resp.status, 201)
        self.assertEqual(ci_headers(resp).get("access-control-allow-origin"),
                         self.origin)

    def test_no_allow_credentials_on_either_path(self):
        # The relay authenticates with a bearer capability in the Authorization header. It
        # sets no cookie and reads none, and the browser client sends credentials 'omit',
        # so allowing credentialed cross-origin requests grants a privilege nothing uses.
        # Both the preflight and the real response are checked: an earlier version sent the
        # header from two separate places and only one would have been noticed.
        pre = request(self.fx.base, "OPTIONS", "/v1/mailboxes",
                      headers={"Origin": self.origin,
                               "Access-Control-Request-Method": "POST"})
        self.assertEqual(pre.status, 204)
        self.assertIsNone(
            ci_headers(pre).get("access-control-allow-credentials"))

        real = request(self.fx.base, "POST", "/v1/mailboxes",
                       headers={"Origin": self.origin})
        self.assertEqual(real.status, 201)
        # Positive control: ACAO IS present, so this is not passing because CORS is off.
        self.assertEqual(ci_headers(real).get("access-control-allow-origin"),
                         self.origin)
        self.assertIsNone(
            ci_headers(real).get("access-control-allow-credentials"))


# ---------------------------------------------------------------------------
# Fix 8 [MED] - the write path locks per-mailbox, not globally.
# ---------------------------------------------------------------------------

class WritePathLockTests(unittest.TestCase):
    def test_put_to_b_proceeds_while_a_write_holds_a_mailbox_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp)
            try:
                mid_a, wa, _pa = create_mailbox(fx)
                mid_b, wb, _pb = create_mailbox(fx)

                reached = threading.Event()
                release = threading.Event()

                def hook(mid):
                    # Called inside add_blob while holding ONLY this mailbox's
                    # write lock (before the ledger lock). Block A's write.
                    if mid == mid_a:
                        reached.set()
                        release.wait(timeout=10)

                fx.store.add_hook = hook
                a_thread = threading.Thread(
                    target=lambda: put_blob(fx, mid_a, b"blockA", wa),
                    daemon=True)
                a_thread.start()
                self.assertTrue(reached.wait(timeout=5),
                                "add_blob never entered the per-mailbox section")

                # A global write lock would make this block until we release.
                start = time.monotonic()
                resp_b = put_blob(fx, mid_b, b"toB", wb)
                elapsed = time.monotonic() - start
                self.assertEqual(resp_b.status, 201)
                self.assertLess(elapsed, 5.0,
                                "PUT to B stalled behind A's write -> global lock")
                release.set()
                a_thread.join(timeout=5)
            finally:
                fx.store.add_hook = None
                fx.close()


# ---------------------------------------------------------------------------
# Fix 9 [LOW] - orphan .*.tmp files are swept by purge and reconcile.
# ---------------------------------------------------------------------------

class OrphanTmpTests(unittest.TestCase):
    def test_purge_unlinks_old_orphan_tmp_but_keeps_a_fresh_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp)
            try:
                mid, _w, _p = create_mailbox(fx)
                bdir = fx.cfg.mailboxes_dir / mid / "blobs"
                orphan = bdir / ".deadbeefdeadbeef.tmp"
                orphan.write_bytes(b"partial")
                old = time.time() - (relay._TMP_ORPHAN_GRACE_S + 60)
                os.utime(orphan, (old, old))
                fresh = bdir / ".c0ffeec0ffee.tmp"      # an in-flight write
                fresh.write_bytes(b"in-flight")
                fx.store.purge_mailbox(mid)
                self.assertFalse(orphan.exists(), "stale tmp not swept")
                self.assertTrue(fresh.exists(), "swept a live in-flight tmp")
            finally:
                fx.close()

    def test_reconcile_deletes_orphan_tmp_and_does_not_count_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp)
            try:
                mid, wcap, _p = create_mailbox(fx)
                put_blob(fx, mid, b"y" * 10, wcap)
                bdir = fx.cfg.mailboxes_dir / mid / "blobs"
                (bdir / ".orphaned99.tmp").write_bytes(b"z" * 999)
                fresh = relay.Store(fx.cfg)
                total = fresh.reconcile()
                self.assertEqual(total, 10, "uncommitted tmp counted into ledger")
                self.assertEqual(list(bdir.glob(".*.tmp")), [])
            finally:
                fx.close()


# ---------------------------------------------------------------------------
# Fix 10 [LOW] - listen backlog raised above the stdlib default of 5.
# ---------------------------------------------------------------------------

class BacklogTests(unittest.TestCase):
    def test_request_queue_size_is_raised(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp)
            try:
                self.assertIsInstance(fx.server, relay.RelayHTTPServer)
                self.assertEqual(fx.server.request_queue_size, 128)
                self.assertGreater(relay.RelayHTTPServer.request_queue_size, 5)
            finally:
                fx.close()


# ---------------------------------------------------------------------------
# Fix 12 [LOW] - a non-IP forwarded value falls back to the socket peer.
# ---------------------------------------------------------------------------

class NonIpForwardedTests(unittest.TestCase):
    def test_failkey_non_ip_is_a_bounded_constant_not_a_raw_keyspace(self):
        self.assertFalse(relay.failkey("some-garbage").startswith("raw:"))
        # Distinct garbage values collapse to ONE bucket (bounded keyspace).
        self.assertEqual(relay.failkey("garbage-a"), relay.failkey("garbage-b"))

    def test_non_ip_forwarded_values_collapse_to_the_socket_peer(self):
        # trust_forwarded_for=1, but each request forwards a DIFFERENT non-IP
        # token. The old 'raw:'+value branch minted a fresh key per token, so the
        # flood never hit the budget. Now they all fall back to the socket peer:
        # one key, one state file, budget spent.
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, trust_forwarded_for=1,
                                     auth_fail_limit_per_hour=3)
            try:
                mid, _w, _p = create_mailbox(fx)
                path = "/v1/mailboxes/%s/blobs" % mid
                codes = [request(fx.base, "GET", path, token="bad",
                                 headers={"X-Forwarded-For": "not-an-ip-%d" % i}
                                 ).status for i in range(5)]
                files = list(Path(fx.cfg.state_dir).glob("authfail-*.json"))
            finally:
                fx.close()
        self.assertEqual(codes, [401, 401, 401, 429, 429])
        self.assertEqual(len(files), 1, "a non-IP forwarded value minted keys")


# ===========================================================================
# ROUND 2 - regressions the re-verifier found in the round-1 fixes.
# ===========================================================================

# ---------------------------------------------------------------------------
# R2-1 [MED] - a SOURCE-level auth-failure wall bounds the per-(source,mailbox)
# keyspace, so rotating mailbox ids cannot mint one state file per request.
# ---------------------------------------------------------------------------

class SourceAuthFailWallTests(unittest.TestCase):
    def test_mailbox_id_rotation_trips_source_wall_and_bounds_state_files(self):
        # An attacker rotates a fresh (non-existent, well-formed) mailbox id per
        # request, so the per-(source,mailbox) key never repeats. Without a
        # source-level wall EVERY request would mint a new authfail state file
        # (the unbounded-keyspace / inode-growth class the limiter exists to
        # prevent). The per-source budget (keyed on the source alone, higher
        # limit) must trip and stop new files being minted past it.
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(
                tmp,
                auth_fail_source_limit_per_hour=10,   # the source wall
                auth_fail_limit_per_hour=60)          # per-mailbox: 1/box, never trips
            try:
                codes = []
                for _ in range(30):
                    mid = os.urandom(16).hex()  # 32 lowercase hex, non-existent
                    path = "/v1/mailboxes/%s/blobs" % mid
                    codes.append(
                        request(fx.base, "GET", path, token="bad").status)
                files = list(Path(fx.cfg.state_dir).glob("authfail*.json"))
            finally:
                fx.close()
        # 30 bad-token requests to 30 random mailbox ids from ONE source:
        # the source wall trips -> 429s appear (this was 0 before the fix).
        self.assertIn(429, codes)
        self.assertEqual(codes[:10], [401] * 10)
        self.assertTrue(all(c == 429 for c in codes[10:]), codes)
        # State-file count stays BOUNDED (<= the files minted before the wall,
        # plus the single per-source file), NOT one-per-rotated-id (30).
        self.assertLessEqual(len(files), 11, len(files))
        self.assertLess(len(files), 30)

    def test_per_mailbox_allowance_survives_for_the_legitimate_single_box(self):
        # The source wall must NOT punish the legitimate case: repeated failures
        # against ONE mailbox are still governed by the per-mailbox budget, and a
        # correct token on that same mailbox always works up to it.
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(
                tmp, auth_fail_source_limit_per_hour=100,
                auth_fail_limit_per_hour=3)
            try:
                mid, wcap, _ptok = create_mailbox(fx)
                path = "/v1/mailboxes/%s/blobs" % mid
                # Per-mailbox budget (3) trips before the source budget (100).
                codes = [request(fx.base, "GET", path, token="bad").status
                         for _ in range(5)]
                self.assertEqual(codes, [401, 401, 401, 429, 429])
            finally:
                fx.close()


# ---------------------------------------------------------------------------
# R2-2 [LOW] - the module docstring defers to the shipped deploy files as the
# single source of truth (no divergent inline snippets).
# ---------------------------------------------------------------------------

class DocstringDeploySsotTests(unittest.TestCase):
    def test_docstring_points_at_shipped_files_without_divergent_snippets(self):
        doc = relay.__doc__ or ""
        # Names the shipped deploy files as the source of truth.
        self.assertIn("keyweave-relay.service", doc)
        self.assertIn("nginx-location.conf", doc)
        # The divergent inline values the round-1 snippets carried must not be
        # re-embedded (they contradicted the shipped files).
        self.assertNotIn("LogRateLimitBurst=0", doc)
        self.assertNotIn("LogRateLimitIntervalSec=0", doc)
        self.assertNotIn("zone=keyweave ", doc)  # shipped nginx uses keyweave_req
        # The shipped files carry the real, coherent values.
        svc = (RELAY_DIR / "keyweave-relay.service").read_text()
        ngx = (RELAY_DIR / "nginx-location.conf").read_text()
        self.assertIn("LogRateLimitBurst=10000", svc)
        self.assertIn("zone=keyweave_req", ngx)


# ---------------------------------------------------------------------------
# R3-2 [LOW] - the per-source byte budget is a per-CLIENT rate limit; the global
# byte cap is an AVAILABILITY boundary, NOT a per-tenant guarantee. SUPERSEDES
# R2-3: an earlier round tried to size the default so one source could not fill
# the global cap over a TTL -- explicitly no longer a goal. The default is a
# generous per-client rate for a text messenger, and the distributed-flood
# residual + deferred eviction are named in the docstring and RELAY-RESIDUALS.md.
# ---------------------------------------------------------------------------

class SourceByteRateFramingTests(unittest.TestCase):
    def test_default_is_a_generous_per_client_rate(self):
        c = relay.Config()
        # 8 MiB/h == exactly 128 max-size (64 KiB) blobs/hour: generous for a
        # text messenger, and a per-CLIENT rate under the coherent deploy.
        self.assertEqual(c.max_source_write_bytes_per_hour, 8 * 1024 * 1024)
        self.assertEqual(
            c.max_source_write_bytes_per_hour // c.max_blob_bytes, 128)

    def test_global_cap_is_framed_as_availability_with_named_residual(self):
        # The reframing is written down in BOTH the module docstring and the
        # residuals file, and NAMES the distributed-flood residual + deferred
        # eviction rather than falsely claiming one source cannot fill the cap.
        doc = relay.__doc__ or ""
        self.assertIn("AVAILABILITY boundary", doc)
        self.assertIn("DISTRIBUTED flood", doc)
        # RELAY-RESIDUALS.md is a pointer at the canonical residual list
        # (docs/NAMED-RESIDUALS.md, R10) -- follow it instead of pinning the
        # same prose in two places.
        pointer = (RELAY_DIR / "RELAY-RESIDUALS.md").read_text()
        self.assertIn("named-residuals.md", pointer.lower())
        # This is the ONE file the suite reads from outside relay/, so it is
        # the one that a relay-subtree-only export leaves behind. Missing from
        # a FULL checkout it is a real regression and must fail; missing from
        # an export it is a packaging gap, and erroring there taught an
        # operator to read a packaging problem as a broken relay.
        target = RELAY_DIR.parent / "docs" / "NAMED-RESIDUALS.md"
        if not target.exists():
            if is_full_checkout():
                self.fail(
                    "%s is missing from a FULL checkout. R10's canonical text"
                    " has no other home; this wall is real." % target)
            raise unittest.SkipTest(
                "PACKAGING, not Python and not the relay: %s sits outside"
                " relay/ and this tree is a relay-only export. Ship it with:"
                " git archive HEAD relay docs/NAMED-RESIDUALS.md" % target)
        residuals = target.read_text()
        self.assertIn("distributed flood", residuals.lower())
        self.assertIn("eviction is deferred", residuals.lower())


# ===========================================================================
# ROUND 3 - third-order regressions the re-verifier found in the round-2 fixes.
# ===========================================================================

# ---------------------------------------------------------------------------
# R3-1 [MED] - the per-SOURCE auth-fail wall is consulted/recorded ONLY for a
# NON-EXISTENT target, so under shared attribution (trust_forwarded_for=0 behind
# nginx) a flood against EXISTING mailboxes cannot 429 the whole relay. This
# restores the per-(source,mailbox) isolation an earlier round built while still
# walling id-rotation against non-existent ids.
# ---------------------------------------------------------------------------

class SourceWallIsolationTests(unittest.TestCase):
    def test_flood_of_existing_mailboxes_does_not_deny_an_unrelated_existing_one(self):
        # trust_forwarded_for=0 (default): every request shares the one proxy-peer
        # source key. A LOW source wall plus bad-token floods against EXISTING
        # mailboxes A,B,C must NOT trip a shared wall that then 429s a VALID pull
        # on an unrelated EXISTING mailbox D. Existing mailboxes are governed by
        # the per-(source,mailbox) budget alone; the source wall is reserved for
        # NON-EXISTENT (id-rotation) targets. BEFORE the fix the source wall was
        # consulted/recorded for existing mailboxes too, so the A/B/C floods
        # tripped it and D's valid pull got a 429 (isolation broken).
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(
                tmp, auth_fail_source_limit_per_hour=5,
                auth_fail_limit_per_hour=60)
            try:
                boxes = {name: create_mailbox(fx)
                         for name in ("A", "B", "C", "D")}
                for name in ("A", "B", "C"):
                    mid = boxes[name][0]
                    path = "/v1/mailboxes/%s/blobs" % mid
                    for _ in range(2):  # 6 bad GETs total -> would trip a 5-wall
                        request(fx.base, "GET", path, token="bad")
                # D is a DIFFERENT existing mailbox with a CORRECT pull token.
                mid_d, _wd, ptok_d = boxes["D"]
                resp = list_blobs(fx, mid_d, ptok_d)
                self.assertEqual(resp.status, 200,
                                 "a shared source wall denied an unrelated"
                                 " existing mailbox (isolation broken)")
                # The existing-mailbox floods minted NO per-source state file:
                # the source wall belongs to non-existent targets only.
                srcfiles = list(
                    Path(fx.cfg.state_dir).glob("authfailsrc-*.json"))
                self.assertEqual(srcfiles, [],
                                 "existing-mailbox floods touched the source wall")
            finally:
                fx.close()

    def test_id_rotation_still_trips_source_wall_with_bounded_state_files(self):
        # The source wall still bounds id-rotation against NON-EXISTENT ids: many
        # bad-token GETs to random non-existent mailbox ids from one source trip
        # the source wall (429 appears) and the state-file count stays BOUNDED
        # (NOT one file per rotated id).
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(
                tmp, auth_fail_source_limit_per_hour=5,
                auth_fail_limit_per_hour=60)
            try:
                codes = []
                for _ in range(20):
                    mid = os.urandom(16).hex()  # non-existent, well-formed
                    path = "/v1/mailboxes/%s/blobs" % mid
                    codes.append(
                        request(fx.base, "GET", path, token="bad").status)
                files = list(Path(fx.cfg.state_dir).glob("authfail*.json"))
            finally:
                fx.close()
        self.assertIn(429, codes)             # the source wall tripped
        # <= (per-mailbox files minted before the wall tripped) + 1 source file,
        # never one-per-rotated-id (20).
        self.assertLessEqual(len(files), 6, len(files))
        self.assertLess(len(files), 20)


# ---------------------------------------------------------------------------
# R3-3 [MED] - the deploy client-address story is coherent: nginx-location.conf,
# the module docstring, and the startup warning all name the ONE mechanism that
# actually reaches a loopback relay (trust_forwarded_for=1 + nginx OVERWRITE of
# X-Forwarded-For), and the old "Option A" (nginx realip + trust_forwarded_for=0)
# is debunked, not offered -- it rewrites nginx's own $remote_addr, never the
# relay's TCP peer, so it can't reach the relay.
# ---------------------------------------------------------------------------

class DeployClientAddrCoherenceTests(unittest.TestCase):
    OVERWRITE = "proxy_set_header X-Forwarded-For $remote_addr"

    def test_nginx_recommends_only_the_xff_overwrite_and_debunks_realip(self):
        ngx = (RELAY_DIR / "nginx-location.conf").read_text()
        # The overwrite is the active, recommended relay-address config.
        self.assertIn(self.OVERWRITE, ngx)
        # ...and it is ACTIVE, not merely quoted in the header comments. The
        # file's own comments name both forms, so a substring check alone
        # passes on a file whose real directive was deleted or swapped for the
        # appending form. Count DIRECTIVES, with the comments stripped.
        active = active_conf_lines(ngx)
        self.assertEqual(
            active.count(self.OVERWRITE + ";"), 1,
            "nginx-location.conf must carry exactly one ACTIVE"
            " '%s;' directive" % self.OVERWRITE)
        self.assertEqual(
            active.count("$proxy_add_x_forwarded_for"), 0,
            "the APPENDING XFF form is ACTIVE in nginx-location.conf; a"
            " client could then choose the last hop the relay trusts")
        # The spoofable append form is explicitly ruled out.
        self.assertIn("never $proxy_add_x_forwarded_for", ngx)
        # realip is debunked as a standalone mechanism, not offered as "Option A".
        self.assertIn("does NOT change the TCP peer", ngx)
        self.assertNotIn("OPTION A", ngx)

    def test_startup_warning_states_the_one_coherent_remedy(self):
        with tempfile.TemporaryDirectory() as tmp:
            _p, cfg = helper.write_env(tmp, trust_forwarded_for=0)
            with helper.LogCapture() as cap:
                server = relay.build_server(cfg)
                server.server_close()
        warns = [l for l in cap.records if l.startswith("STARTUP")]
        self.assertEqual(len(warns), 1, cap.records)
        w = warns[0]
        self.assertIn("trust_forwarded_for=1", w)
        self.assertIn(self.OVERWRITE, w)
        # The old incoherent "set nginx real_ip" remedy is gone.
        self.assertNotIn("real_ip", w)

    def test_docstring_names_the_same_single_mechanism(self):
        doc = relay.__doc__ or ""
        self.assertIn(self.OVERWRITE, doc)
        self.assertIn("real_ip ALONE does not work", doc)


if __name__ == "__main__":
    unittest.main()
