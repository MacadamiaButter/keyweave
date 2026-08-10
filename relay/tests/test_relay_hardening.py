"""The three RELAY must-fixes from the hardened spec, plus the carry-forwards,
each with a reproducible check:

  MF1  global byte-cap enforcement is REAL: a durable locked ledger updated in
       the same critical section as add/delete, plus a startup reconciliation
       sweep that recomputes from disk (fill -> refuse -> delete-frees ->
       survives a simulated restart -> corrects drift).
  MF2  per-mailbox locking + bounded purge: no request path holds a global lock
       across a full-store walk (a concurrent op proceeds while purge holds one
       mailbox's lock).
  MF3  GC of limiter state files (inline unlink when a window empties + a mtime
       sweep) and IPv6 auth-fail keys bucketed to /64.

Carry-forwards: rate-limit BEFORE auth (unauth flood hits a disk 429 wall and
does not deafen fail2ban), X-Forwarded-For distrust by default + last-hop when
trusted, constant-time mailbox existence, and no mailbox ids in the relay's own
logs.
"""
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from . import helper
from .helper import (create_mailbox, list_blobs, put_blob, request, relay)


def read_ledger(cfg):
    return int(Path(cfg.ledger_path).read_text(encoding="utf-8").strip() or "0")


# ---------------------------------------------------------------------------
# MF1 - the global byte-cap ledger is real, durable, and reconciled.
# ---------------------------------------------------------------------------

class ByteCapLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # Only the global ledger cap binds: room for exactly two 100-byte blobs.
        self.fx = helper.RelayFixture(self.tmp.name, max_total_bytes=250,
                                      max_blob_bytes=1000,
                                      max_mailbox_bytes=1000000,
                                      max_blobs_per_mailbox=1000)
        self.mid, self.wcap, self.ptok = create_mailbox(self.fx)

    def tearDown(self):
        self.fx.close()
        self.tmp.cleanup()

    def test_fill_refuse_delete_frees_and_ledger_reconciles_on_restart(self):
        body = b"x" * 100
        first = put_blob(self.fx, self.mid, body, self.wcap)
        second = put_blob(self.fx, self.mid, body, self.wcap)
        self.assertEqual((first.status, second.status), (201, 201))
        self.assertEqual(read_ledger(self.fx.cfg), 200)

        # Global cap binds: the third add is refused and the ledger is unchanged.
        third = put_blob(self.fx, self.mid, body, self.wcap)
        self.assertEqual(third.status, 507)
        self.assertEqual(third.json["error"], "relay storage full")
        self.assertEqual(read_ledger(self.fx.cfg), 200)

        # Deleting frees bytes in the SAME critical section as the file removal,
        # so a fresh add now fits again.
        blob_id = list_blobs(self.fx, self.mid, self.ptok).json["blobs"][0]["blob_id"]
        gone = request(self.fx.base, "DELETE",
                       "/v1/mailboxes/%s/blobs/%s" % (self.mid, blob_id),
                       token=self.ptok)
        self.assertEqual(gone.status, 204)
        self.assertEqual(read_ledger(self.fx.cfg), 100)
        again = put_blob(self.fx, self.mid, body, self.wcap)
        self.assertEqual(again.status, 201)
        self.assertEqual(read_ledger(self.fx.cfg), 200)

        # Simulated restart / drift: corrupt the ledger to a fiction, then a
        # fresh Store's reconciliation recomputes the truth from disk (2 blobs).
        Path(self.fx.cfg.ledger_path).write_text("999999", encoding="utf-8")
        reconciled = relay.Store(self.fx.cfg)
        total = reconciled.reconcile()
        self.assertEqual(total, 200)
        self.assertEqual(read_ledger(self.fx.cfg), 200)

    def test_ledger_is_not_a_fiction_delete_decrements_by_exact_size(self):
        # Direct store-level check that add and delete move the ledger by the
        # exact blob size, atomically with the file op.
        store = self.fx.store
        bid, size = store.add_blob(self.mid, b"y" * 42)
        self.assertEqual(size, 42)
        self.assertEqual(read_ledger(self.fx.cfg), 42)
        self.assertTrue(store.delete_blob(self.mid, bid))
        self.assertEqual(read_ledger(self.fx.cfg), 0)


class PerMailboxCapTests(unittest.TestCase):
    def test_per_mailbox_byte_and_count_caps_are_independent_walls(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, max_total_bytes=10_000_000,
                                     max_blob_bytes=1000,
                                     max_mailbox_bytes=150,
                                     max_blobs_per_mailbox=1000)
            try:
                mid, wcap, _ptok = create_mailbox(fx)
                self.assertEqual(put_blob(fx, mid, b"z" * 100, wcap).status, 201)
                # 100 + 100 > 150 per-mailbox byte cap -> 507, ledger far from full
                self.assertEqual(put_blob(fx, mid, b"z" * 100, wcap).status, 507)
            finally:
                fx.close()

    def test_blob_count_cap_is_a_wall(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, max_total_bytes=10_000_000,
                                     max_blob_bytes=1000,
                                     max_mailbox_bytes=1000000,
                                     max_blobs_per_mailbox=2)
            try:
                mid, wcap, _ptok = create_mailbox(fx)
                self.assertEqual(put_blob(fx, mid, b"a", wcap).status, 201)
                self.assertEqual(put_blob(fx, mid, b"a", wcap).status, 201)
                self.assertEqual(put_blob(fx, mid, b"a", wcap).status, 507)
            finally:
                fx.close()


# ---------------------------------------------------------------------------
# MF2 - purge is bounded and per-mailbox; no global lock across a store walk.
# ---------------------------------------------------------------------------

class BoundedPurgeTests(unittest.TestCase):
    def test_concurrent_ops_proceed_while_purge_holds_one_mailbox_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp)
            try:
                # A handful of mailboxes so purge has something to walk.
                boxes = [create_mailbox(fx) for _ in range(5)]
                mids = [b[0] for b in boxes]
                caps = {b[0]: (b[1], b[2]) for b in boxes}

                reached = threading.Event()
                release = threading.Event()
                blocked_mid = {}

                def hook(mid):
                    # Called while holding ONLY this mailbox's lock, and BEFORE
                    # purge takes the global ledger lock. Block the first one.
                    if not blocked_mid:
                        blocked_mid["mid"] = mid
                        reached.set()
                        release.wait(timeout=10)

                fx.store.purge_hook = hook
                purge = threading.Thread(
                    target=lambda: fx.store.purge_tick(budget=100), daemon=True)
                purge.start()

                self.assertTrue(reached.wait(timeout=5),
                                "purge never entered a per-mailbox section")
                held = blocked_mid["mid"]
                target = next(m for m in mids if m != held)
                wcap, ptok = caps[target]

                # If a global store lock (or the ledger lock) were held across
                # the purge walk, this would block until we release and time out.
                start = time.monotonic()
                put = put_blob(fx, target, b"live-during-purge", wcap, )
                listed = list_blobs(fx, target, ptok)
                # And a create (index lock) must proceed too.
                extra = request(fx.base, "POST", "/v1/mailboxes", timeout=8)
                elapsed = time.monotonic() - start

                self.assertEqual(put.status, 201)
                self.assertEqual(listed.status, 200)
                self.assertEqual(extra.status, 201)
                self.assertLess(elapsed, 5.0,
                                "ops stalled behind the purge -> a global lock"
                                " is held across the walk")
                release.set()
                purge.join(timeout=5)
            finally:
                fx.store.purge_hook = None
                fx.close()

    def test_purge_removes_only_expired_blobs_per_mailbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, ttl_days=14)
            try:
                mid, wcap, ptok = create_mailbox(fx)
                blobs_dir = fx.cfg.mailboxes_dir / mid / "blobs"
                # A fresh blob (kept) and a hand-planted expired-id blob (purged).
                fresh_id = put_blob(fx, mid, b"fresh", wcap).json["blob_id"]
                old = blobs_dir / "bl-20200101T000000Z.0011223344ff.blob"
                old.write_bytes(b"ancient")
                removed = fx.store.purge_mailbox(mid)
                self.assertEqual(removed, 1)
                self.assertFalse(old.exists())
                ids = [r["blob_id"]
                       for r in list_blobs(fx, mid, ptok).json["blobs"]]
                self.assertEqual(ids, [fresh_id])
            finally:
                fx.close()


# ---------------------------------------------------------------------------
# MF3 - limiter-file GC and IPv6 /64 auth-fail bucketing.
# ---------------------------------------------------------------------------

class LimiterGcTests(unittest.TestCase):
    def test_failure_file_unlinked_inline_when_window_empties(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            lim = relay.FailureLimiter(state, limit_per_hour=5, window_s=100)
            lim.record("v4:203.0.113.7", now=1000.0)
            files = list(state.glob("authfail-*.json"))
            self.assertEqual(len(files), 1)
            # Long after the window: blocked() sees an empty window and reclaims.
            blocked, _ = lim.blocked("v4:203.0.113.7", now=1000.0 + 100 + 50)
            self.assertFalse(blocked)
            self.assertEqual(list(state.glob("authfail-*.json")), [])

    def test_mtime_sweep_unlinks_stale_keeps_fresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            rate = relay.RateLimiter(state, limit_per_hour=10, window_s=100)
            rate.allow("write:aaa", now=1000.0)
            rate.allow("write:bbb", now=1000.0)
            paths = sorted(state.glob("rate-*.json"))
            self.assertEqual(len(paths), 2)
            # Backdate one file's mtime past the window; the other stays fresh.
            import os
            stale = paths[0]
            old = time.time() - 200
            os.utime(stale, (old, old))
            removed = rate.sweep_stale(now=time.time())
            self.assertEqual(removed, 1)
            self.assertFalse(stale.exists())
            self.assertTrue(paths[1].exists())

    def test_sweep_budget_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            rate = relay.RateLimiter(state, limit_per_hour=10, window_s=100)
            for i in range(6):
                rate.allow("write:%d" % i, now=1000.0)
            old = time.time() - 200
            import os
            for p in state.glob("rate-*.json"):
                os.utime(p, (old, old))
            # One bounded tick only touches `budget` files.
            removed = rate.sweep_stale(now=time.time(), budget=2)
            self.assertEqual(removed, 2)
            self.assertEqual(len(list(state.glob("rate-*.json"))), 4)


class IPv6BucketTests(unittest.TestCase):
    def test_failkey_collapses_a_64_to_one_key(self):
        a = relay.failkey("2001:db8:1:2::1")
        b = relay.failkey("2001:db8:1:2:ffff:ffff:dead:beef")
        c = relay.failkey("2001:db8:1:3::1")  # different /64
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertTrue(a.startswith("v6:/64:"))
        # IPv4 keys per address.
        self.assertEqual(relay.failkey("203.0.113.5"), "v4:203.0.113.5")

    def test_two_v6_addresses_in_one_64_share_one_authfail_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, trust_forwarded_for=1,
                                     auth_fail_limit_per_hour=1000)
            try:
                mid, _wcap, _ptok = create_mailbox(fx)
                path = "/v1/mailboxes/%s/blobs" % mid
                # Same /64, different hosts -> one key -> one state file.
                for addr in ("2001:db8:1:2::1",
                             "2001:db8:1:2:aaaa:bbbb:cccc:dddd"):
                    request(fx.base, "GET", path, token="bad-token",
                            headers={"X-Forwarded-For": addr})
                files = list(Path(fx.cfg.state_dir).glob("authfail-*.json"))
                self.assertEqual(len(files), 1)
                # A different /64 mints a second file.
                request(fx.base, "GET", path, token="bad-token",
                        headers={"X-Forwarded-For": "2001:db8:1:3::9"})
                files = list(Path(fx.cfg.state_dir).glob("authfail-*.json"))
                self.assertEqual(len(files), 2)
            finally:
                fx.close()


# ---------------------------------------------------------------------------
# Carry-forward: rate-limit BEFORE auth (fail2ban stays audible).
# ---------------------------------------------------------------------------

class RateBeforeAuthTests(unittest.TestCase):
    def test_bad_token_flood_hits_429_and_leaves_one_state_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, auth_fail_limit_per_hour=5)
            try:
                mid, _wcap, _ptok = create_mailbox(fx)
                path = "/v1/mailboxes/%s/blobs" % mid
                codes = [request(fx.base, "GET", path, token="bad").status
                         for _ in range(8)]
                state = list(Path(fx.cfg.state_dir).glob("authfail-*.json"))
            finally:
                fx.close()
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[5:], [429] * 3)
        self.assertEqual(len(state), 1)

    def test_block_applies_before_the_compare_even_for_a_good_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, auth_fail_limit_per_hour=1)
            try:
                mid, wcap, _ptok = create_mailbox(fx)
                path = "/v1/mailboxes/%s/blobs" % mid
                request(fx.base, "GET", path, token="burn-the-budget")
                # Correct write_cap on a write, but the source is over budget:
                resp = put_blob(fx, mid, b"x", wcap)
            finally:
                fx.close()
        self.assertEqual(resp.status, 429)
        self.assertGreater(int(resp.headers.get("Retry-After")), 0)

    def test_missing_auth_header_flood_also_spends_the_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, auth_fail_limit_per_hour=3)
            try:
                mid, _wcap, _ptok = create_mailbox(fx)
                path = "/v1/mailboxes/%s/blobs" % mid
                codes = [request(fx.base, "GET", path).status for _ in range(5)]
            finally:
                fx.close()
        self.assertEqual(codes, [401, 401, 401, 429, 429])

    def test_authfail_journal_volume_is_capped_at_the_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, auth_fail_limit_per_hour=5)
            try:
                mid, _wcap, _ptok = create_mailbox(fx)
                path = "/v1/mailboxes/%s/blobs" % mid
                with helper.LogCapture() as cap:
                    for _ in range(20):
                        request(fx.base, "GET", path, token="noisy")
            finally:
                fx.close()
        warn = [l for l in cap.records if l.startswith("AUTHFAIL")]
        self.assertEqual(len(warn), 5)

    def test_valid_token_never_spends_the_failure_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, auth_fail_limit_per_hour=2)
            try:
                mid, wcap, ptok = create_mailbox(fx)
                for _ in range(4):
                    self.assertEqual(put_blob(fx, mid, b"ok", wcap).status, 201)
                for _ in range(4):
                    self.assertEqual(list_blobs(fx, mid, ptok).status, 200)
                state = list(Path(fx.cfg.state_dir).glob("authfail-*.json"))
                self.assertEqual(state, [])
            finally:
                fx.close()

    def test_failure_budget_survives_a_real_process_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            port = helper.free_port()
            config_path, cfg = helper.write_env(
                tmp, bind_port=port, auth_fail_limit_per_hour=2)
            base = "http://127.0.0.1:%d" % port

            def start():
                proc = subprocess.Popen(
                    [sys.executable, str(helper.RELAY_SCRIPT),
                     "--config", str(config_path), "serve"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.time() + 10
                while time.time() < deadline:
                    try:
                        request(base, "POST", "/v1/mailboxes", timeout=5)
                        return proc
                    except OSError:
                        time.sleep(0.05)
                proc.terminate()
                raise AssertionError("relay subprocess never came up")

            # A well-formed but unknown mailbox: uniform 401, spends the budget.
            unknown = "/v1/mailboxes/%s/blobs" % ("0" * 32)
            proc = start()
            try:
                for _ in range(2):
                    self.assertEqual(
                        request(base, "GET", unknown, token="bad").status, 401)
                self.assertEqual(
                    request(base, "GET", unknown, token="bad").status, 429)
            finally:
                proc.terminate()
                proc.wait(timeout=10)

            proc = start()  # simulated restart: fresh process, same disk
            try:
                self.assertEqual(
                    request(base, "GET", unknown, token="bad").status, 429,
                    "auth-failure budget reset across restart")
            finally:
                proc.terminate()
                proc.wait(timeout=10)


# ---------------------------------------------------------------------------
# Carry-forward: X-Forwarded-For distrust + last-hop when trusted.
# ---------------------------------------------------------------------------

class ForwardedForTests(unittest.TestCase):
    def test_xff_not_trusted_by_default(self):
        self.assertEqual(relay.Config().trust_forwarded_for, 0)

    def test_untrusted_xff_cannot_dodge_the_budget(self):
        # With XFF ignored, rotating forged addresses all land on the socket
        # peer, so they cannot each mint a fresh budget.
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, auth_fail_limit_per_hour=3)
            try:
                mid, _wcap, _ptok = create_mailbox(fx)
                path = "/v1/mailboxes/%s/blobs" % mid
                codes = []
                for i in range(5):
                    codes.append(request(
                        fx.base, "GET", path, token="bad",
                        headers={"X-Forwarded-For":
                                 "203.0.113.%d" % (i + 1)}).status)
            finally:
                fx.close()
        self.assertEqual(codes, [401, 401, 401, 429, 429])

    def test_trusted_xff_uses_last_hop(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp, trust_forwarded_for=1)
            try:
                mid, _wcap, _ptok = create_mailbox(fx)
                path = "/v1/mailboxes/%s/blobs" % mid
                with helper.LogCapture() as cap:
                    request(fx.base, "GET", path, token="bad",
                            headers={"X-Forwarded-For": "6.6.6.6, 203.0.113.9"})
            finally:
                fx.close()
        lines = [l for l in cap.records if l.startswith("AUTHFAIL")]
        self.assertEqual(len(lines), 1)
        self.assertIn("client=203.0.113.9", lines[0])
        self.assertNotIn("6.6.6.6", lines[0])


# ---------------------------------------------------------------------------
# Carry-forward: mailbox ids never appear in the relay's own logs.
# ---------------------------------------------------------------------------

class LogHygieneTests(unittest.TestCase):
    def test_no_mailbox_or_blob_id_in_any_log_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp)
            try:
                with helper.LogCapture() as cap:
                    mid, wcap, ptok = create_mailbox(fx)
                    blob_id = put_blob(fx, mid, b"secret", wcap).json["blob_id"]
                    list_blobs(fx, mid, ptok)
                    # an auth failure whose request path CONTAINS the mailbox id
                    request(fx.base, "GET", "/v1/mailboxes/%s/blobs" % mid,
                            token="bad")
                    request(fx.base, "GET",
                            "/v1/mailboxes/%s/blobs/%s" % (mid, blob_id),
                            token=ptok)  # delete-on-pull
            finally:
                fx.close()
            joined = "\n".join(cap.records)
            self.assertNotIn(mid, joined)
            self.assertNotIn(blob_id, joined)
            self.assertNotIn("/v1/mailboxes/", joined)


class BlanketGuardTests(unittest.TestCase):
    def test_unexpected_handler_exception_is_500_without_traceback(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp)
            try:
                mid, wcap, _ptok = create_mailbox(fx)
                with mock.patch.object(fx.store, "add_blob",
                                       side_effect=RuntimeError("boom")):
                    with helper.LogCapture() as cap:
                        resp = put_blob(fx, mid, b"x", wcap)
            finally:
                fx.close()
        self.assertEqual(resp.status, 500)
        self.assertNotIn(b"Traceback", resp.raw)
        self.assertNotIn(b"boom", resp.raw)
        unhandled = [l for l in cap.records if l.startswith("UNHANDLED")]
        self.assertEqual(len(unhandled), 1)
        self.assertNotIn("\n", unhandled[0])


if __name__ == "__main__":
    unittest.main()
