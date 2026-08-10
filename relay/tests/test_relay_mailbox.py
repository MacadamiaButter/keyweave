"""Core mailbox behaviour: the capability split, opaque-blob round-trip,
delete-on-pull, size caps, id validators, and config refusals."""
import os
import stat
import tempfile
import unittest
from pathlib import Path

from . import helper
from .helper import (create_mailbox, delete_blob, list_blobs, pull_blob,
                     put_blob, request, relay)


class CapabilitySplitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = helper.RelayFixture(self.tmp.name)
        self.mid, self.wcap, self.ptok = create_mailbox(self.fx)

    def tearDown(self):
        self.fx.close()
        self.tmp.cleanup()

    def test_create_returns_three_distinct_secrets(self):
        self.assertRegex(self.mid, r"\A[0-9a-f]{32}\Z")
        self.assertNotEqual(self.wcap, self.ptok)
        self.assertGreater(len(self.wcap), 20)
        self.assertGreater(len(self.ptok), 20)

    def test_write_cap_can_write(self):
        resp = put_blob(self.fx, self.mid, b"opaque-1", self.wcap)
        self.assertEqual(resp.status, 201)
        self.assertRegex(resp.json["blob_id"], r"\Abl-\d{8}T\d{6}Z\.[0-9a-f]{12}\Z")

    def test_write_cap_cannot_read(self):
        put_blob(self.fx, self.mid, b"opaque-2", self.wcap)
        listed = list_blobs(self.fx, self.mid, self.wcap)
        self.assertEqual(listed.status, 401)
        # and cannot pull an individual blob either
        blob_id = list_blobs(self.fx, self.mid, self.ptok).json["blobs"][0]["blob_id"]
        pulled = pull_blob(self.fx, self.mid, blob_id, self.wcap)
        self.assertEqual(pulled.status, 401)

    def test_pull_token_cannot_write(self):
        resp = put_blob(self.fx, self.mid, b"opaque-3", self.ptok)
        self.assertEqual(resp.status, 401)

    def test_pull_token_can_read(self):
        put_blob(self.fx, self.mid, b"opaque-4", self.wcap)
        listed = list_blobs(self.fx, self.mid, self.ptok)
        self.assertEqual(listed.status, 200)
        self.assertEqual(len(listed.json["blobs"]), 1)

    def test_only_digests_are_stored_never_the_tokens(self):
        meta_path = self.fx.cfg.mailboxes_dir / self.mid / "meta.json"
        text = meta_path.read_text()
        self.assertNotIn(self.wcap, text)
        self.assertNotIn(self.ptok, text)
        self.assertIn("write_digest", text)
        self.assertIn("pull_digest", text)


class OpaqueBlobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = helper.RelayFixture(self.tmp.name, max_blob_bytes=64)
        self.mid, self.wcap, self.ptok = create_mailbox(self.fx)

    def tearDown(self):
        self.fx.close()
        self.tmp.cleanup()

    def test_arbitrary_bytes_round_trip_exactly(self):
        # Non-JSON, embedded NULs, invalid UTF-8, and a gzip magic header the
        # relay must NEVER try to decompress. A byte-exact round trip proves the
        # blob was treated as opaque (never decoded/parsed/decompressed).
        blob = b"\x1f\x8b\x08\x00not-json{[\x00\xff\xfe raw ciphertext"
        put = put_blob(self.fx, self.mid, blob, self.wcap)
        self.assertEqual(put.status, 201)
        blob_id = put.json["blob_id"]
        got = pull_blob(self.fx, self.mid, blob_id, self.ptok)
        self.assertEqual(got.status, 200)
        self.assertEqual(got.raw, blob)
        self.assertEqual(got.headers.get("Content-Type"),
                         "application/octet-stream")

    def test_oversize_blob_rejected_by_content_length_and_never_parsed(self):
        # Content-Length alone triggers 413; the (would-be malformed) body is
        # drained, never read into memory, never parsed. Nothing is stored.
        big = b"A" * 200
        resp = put_blob(self.fx, self.mid, big, self.wcap)
        self.assertEqual(resp.status, 413)
        self.assertEqual(resp.json["limit_bytes"], 64)
        listed = list_blobs(self.fx, self.mid, self.ptok)
        self.assertEqual(listed.json["blobs"], [])

    def test_empty_blob_is_accepted_opaque(self):
        resp = put_blob(self.fx, self.mid, b"", self.wcap)
        self.assertEqual(resp.status, 201)
        self.assertEqual(resp.json["size"], 0)


class DeleteOnPullTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = helper.RelayFixture(self.tmp.name)
        self.mid, self.wcap, self.ptok = create_mailbox(self.fx)

    def tearDown(self):
        self.fx.close()
        self.tmp.cleanup()

    def test_pull_deletes_the_blob(self):
        blob_id = put_blob(self.fx, self.mid, b"once", self.wcap).json["blob_id"]
        first = pull_blob(self.fx, self.mid, blob_id, self.ptok)
        self.assertEqual(first.status, 200)
        self.assertEqual(first.raw, b"once")
        second = pull_blob(self.fx, self.mid, blob_id, self.ptok)
        self.assertEqual(second.status, 404)

    def test_explicit_delete_without_reading(self):
        blob_id = put_blob(self.fx, self.mid, b"discard", self.wcap).json["blob_id"]
        resp = delete_blob(self.fx, self.mid, blob_id, self.ptok)
        self.assertEqual(resp.status, 204)
        self.assertEqual(delete_blob(self.fx, self.mid, blob_id, self.ptok).status,
                         404)

    def test_list_is_metadata_only_and_does_not_delete(self):
        put_blob(self.fx, self.mid, b"stays", self.wcap)
        listed = list_blobs(self.fx, self.mid, self.ptok).json["blobs"]
        self.assertEqual(len(listed), 1)
        self.assertIn("size", listed[0])
        self.assertIn("received", listed[0])
        # bodies are never in a listing
        self.assertNotIn("blob", json_keys(listed[0]))
        # still present after listing
        self.assertEqual(len(list_blobs(self.fx, self.mid, self.ptok).json["blobs"]),
                         1)


def json_keys(d):
    return set(d.keys())


class FileModeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = helper.RelayFixture(self.tmp.name)
        self.mid, self.wcap, self.ptok = create_mailbox(self.fx)

    def tearDown(self):
        self.fx.close()
        self.tmp.cleanup()

    def test_blob_files_are_0600(self):
        put_blob(self.fx, self.mid, b"x", self.wcap)
        blobs_dir = self.fx.cfg.mailboxes_dir / self.mid / "blobs"
        blob = next(blobs_dir.glob("bl-*.blob"))
        self.assertEqual(stat.S_IMODE(os.stat(blob).st_mode), 0o600)

    def test_mailbox_dirs_are_0700(self):
        for d in (self.fx.cfg.mailboxes_dir / self.mid,
                  self.fx.cfg.mailboxes_dir / self.mid / "blobs"):
            self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700, d)


class IdValidatorTests(unittest.TestCase):
    def test_mailbox_id_regex_is_anchored_with_capital_Z_not_dollar(self):
        good = "a" * 32
        self.assertIsNotNone(relay.MAILBOX_ID_RE.match(good))
        # A trailing newline would slip past a $-anchored pattern; \Z rejects it.
        self.assertIsNone(relay.MAILBOX_ID_RE.match(good + "\n"))
        self.assertIsNone(relay.MAILBOX_ID_RE.match(good + "x"))
        self.assertIsNone(relay.MAILBOX_ID_RE.match("A" * 32))  # not lowercase

    def test_blob_id_regex_is_anchored_with_capital_Z_not_dollar(self):
        good = "bl-20260808T120000Z.0123456789ab"
        self.assertIsNotNone(relay.BLOB_ID_RE.match(good))
        self.assertIsNone(relay.BLOB_ID_RE.match(good + "\n"))

    def test_malformed_ids_route_to_404_without_touching_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp)
            try:
                # too short, wrong charset -> no route match -> 404
                resp = request(fx.base, "GET", "/v1/mailboxes/xyz/blobs",
                               token="whatever")
                self.assertEqual(resp.status, 404)
            finally:
                fx.close()

    def test_wellformed_but_nonexistent_mailbox_is_401_not_404(self):
        # Constant-time existence: a well-formed but unknown mailbox answers the
        # SAME 401 as a wrong token, never a distinguishing 404.
        with tempfile.TemporaryDirectory() as tmp:
            fx = helper.RelayFixture(tmp)
            try:
                resp = request(fx.base, "GET",
                               "/v1/mailboxes/%s/blobs" % ("0" * 32),
                               token="whatever")
                self.assertEqual(resp.status, 401)
            finally:
                fx.close()


class ConfigRefusalTests(unittest.TestCase):
    def _load(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "relay.conf"
            path.write_text(text)
            return relay.load_config(path)

    def test_unknown_config_key_refuses(self):
        with self.assertRaises(relay.ConfigError):
            self._load("no_such_key = 1\n")

    def test_property_shadow_keys_refuse(self):
        for key in ("mailboxes_dir", "state_dir", "ledger_path"):
            with self.assertRaises(relay.ConfigError, msg=key):
                self._load("%s = /tmp/z\n" % key)

    def test_non_integer_value_refuses(self):
        with self.assertRaises(relay.ConfigError):
            self._load("max_blob_bytes = not-a-number\n")

    def test_non_loopback_bind_refuses(self):
        for host in ("0.0.0.0", "203.0.113.5", "::"):
            with self.assertRaises(relay.ConfigError, msg=host):
                self._load("bind_host = %s\n" % host)

    def test_loopback_binds_accepted(self):
        for host in ("127.0.0.1", "::1", "localhost"):
            self.assertEqual(self._load("bind_host = %s\n" % host).bind_host, host)


if __name__ == "__main__":
    unittest.main()
