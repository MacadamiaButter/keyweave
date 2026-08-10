"""Shared fixtures for the Keyweave relay tests.

Imports the relay by path so the tests never touch anything else in the repo,
and builds HTTP requests through an EXPLICIT empty ProxyHandler so proxy
environment variables (Tor or otherwise) can never redirect a loopback test
request.
"""
from __future__ import annotations

import json
import logging
import socket
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

_RELAY_DIR = Path(__file__).resolve().parents[1]
if str(_RELAY_DIR) not in sys.path:
    sys.path.insert(0, str(_RELAY_DIR))

import keyweave_relay as relay  # noqa: E402

# Tests assert on captured records; keep uncaptured warnings off the console.
relay.LOG.addHandler(logging.NullHandler())

RELAY_SCRIPT = _RELAY_DIR / "keyweave_relay.py"

# Proxy env vars must never touch loopback test traffic.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def write_env(tmp, **overrides):
    """Create a data dir and a config file under tmp. Returns (config_path, cfg)."""
    tmp = Path(tmp)
    data_dir = tmp / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    values = {
        "bind_host": "127.0.0.1",
        "bind_port": 0,
        "data_dir": str(data_dir),
        "purge_interval_s": 0,
    }
    values.update(overrides)
    config_path = tmp / "relay.conf"
    lines = ["%s = %s" % (k, v) for k, v in values.items()]
    config_path.write_text("\n".join(lines) + "\n")
    return config_path, relay.load_config(config_path)


class RelayFixture:
    """A live relay server on an ephemeral loopback port, in a thread."""

    def __init__(self, tmp, **overrides):
        self.config_path, self.cfg = write_env(tmp, **overrides)
        self.server = relay.build_server(self.cfg)
        self.store = self.server.store
        self.port = self.server.server_address[1]
        self.base = "http://127.0.0.1:%d" % self.port
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def request(base, method, path, token=None, data=None, headers=None,
            content_type="application/json", timeout=30):
    """One HTTP request via the proxy-free opener. Returns a namespace with
    .status, .headers, .json (None when the body is not JSON) and .raw."""
    req = urllib.request.Request(base + path, data=data, method=method)
    if token is not None:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", content_type)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            body = resp.read()
            status, hdrs = resp.status, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        with exc:
            body = exc.read()
            status, hdrs = exc.code, dict(exc.headers)
    try:
        parsed = json.loads(body.decode("utf-8")) if body else None
    except (ValueError, UnicodeDecodeError):
        parsed = None
    return SimpleNamespace(status=status, headers=hdrs, json=parsed, raw=body)


def create_mailbox(fx):
    """POST /v1/mailboxes. Returns (mailbox_id, write_cap, pull_token)."""
    resp = request(fx.base, "POST", "/v1/mailboxes")
    assert resp.status == 201, resp.status
    body = resp.json
    return body["mailbox_id"], body["write_cap"], body["pull_token"]


def put_blob(fx, mid, data, token):
    return request(fx.base, "PUT", "/v1/mailboxes/%s/blobs" % mid,
                   token=token, data=data,
                   content_type="application/octet-stream")


def list_blobs(fx, mid, token):
    return request(fx.base, "GET", "/v1/mailboxes/%s/blobs" % mid, token=token)


def pull_blob(fx, mid, blob_id, token):
    return request(fx.base, "GET",
                   "/v1/mailboxes/%s/blobs/%s" % (mid, blob_id), token=token)


def delete_blob(fx, mid, blob_id, token):
    return request(fx.base, "DELETE",
                   "/v1/mailboxes/%s/blobs/%s" % (mid, blob_id), token=token)


class LogCapture(logging.Handler):
    """Collects fully formatted log lines from the relay logger."""

    def __init__(self):
        super().__init__()
        self.records = []
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        self.records.append(self.format(record))

    def __enter__(self):
        relay.LOG.addHandler(self)
        self._old_level = relay.LOG.level
        relay.LOG.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        relay.LOG.removeHandler(self)
        relay.LOG.setLevel(self._old_level)
        return False


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
