"""Tests for the OpenHail store, MIME parser, and JSON-RPC surface.

Run: python -m pytest tests -q
No network required. Everything here is local and deterministic.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from openhail import __version__
from openhail.mime import build_message, parse_message
from openhail.server import RpcServer
from openhail.store import Store

SAMPLE_RAW = (
    b"From: Alice Example <alice@example.com>\r\n"
    b"To: bob@example.org\r\n"
    b"Subject: Invoice 4471 attached\r\n"
    b"Date: Tue, 10 Nov 2026 14:22:31 +0000\r\n"
    b"Message-ID: <abc123@example.com>\r\n"
    b"MIME-Version: 1.0\r\n"
    b'Content-Type: text/plain; charset="utf-8"\r\n'
    b"\r\n"
    b"Hello Bob,\r\n\r\nPlease find invoice 4471 attached.\r\n\r\nThanks,\r\nAlice\r\n"
)

MULTIPART_RAW = (
    b"From: carol@example.com\r\n"
    b"To: dave@example.com\r\n"
    b"Subject: multipart test\r\n"
    b"Date: Wed, 11 Nov 2026 09:00:00 -0500\r\n"
    b"Message-ID: <mp1@example.com>\r\n"
    b"MIME-Version: 1.0\r\n"
    b'Content-Type: multipart/alternative; boundary="BOUND"\r\n'
    b"\r\n"
    b"--BOUND\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"plain version\r\n"
    b"--BOUND\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n\r\n"
    b"<p>html version</p>\r\n"
    b"--BOUND--\r\n"
)


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "mail.db")
    yield s
    s.close()


def test_schema_creates_and_persists(tmp_path: Path) -> None:
    p = tmp_path / "x.db"
    s = Store(p)
    s.close()
    assert p.exists()
    s2 = Store(p)
    row = s2.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    assert row["value"] == "1"
    s2.close()


def test_account_roundtrip(store: Store) -> None:
    acc = store.add_account(
        name="fastmail",
        imap_host="imap.fastmail.com",
        smtp_host="smtp.fastmail.com",
        username="me@fastmail.com",
    )
    assert acc.id >= 1
    got = store.get_account("fastmail")
    assert got is not None
    assert got.imap_port == 993
    assert got.smtp_port == 587
    assert got.to_dict()["username"] == "me@fastmail.com"
    assert "password" not in got.to_dict()


def test_folder_uid_tracking(store: Store) -> None:
    acc = store.add_account("a", "i", "s", "u")
    fid = store.ensure_folder(acc.id, "INBOX")
    assert store.get_last_uid(fid) == 0
    store.set_last_uid(fid, 42)
    assert store.get_last_uid(fid) == 42
    assert store.ensure_folder(acc.id, "INBOX") == fid  # idempotent


def test_parse_simple_message() -> None:
    rec = parse_message(SAMPLE_RAW, account_id=1, folder_id=1, uid=7)
    assert rec["uid"] == 7
    assert rec["subject"] == "Invoice 4471 attached"
    assert rec["from_addr"] == "alice@example.com"
    assert rec["to_addr"] == "bob@example.org"
    assert rec["message_id"] == "<abc123@example.com>"
    assert rec["date_utc"].startswith("2026-11-10T14:22:31")
    assert "invoice 4471" in rec["body_text"].lower()
    assert rec["size"] == len(SAMPLE_RAW)
    assert len(rec["raw_sha256"]) == 64


def test_parse_multipart_message() -> None:
    rec = parse_message(MULTIPART_RAW, account_id=1, folder_id=1, uid=8)
    assert "plain version" in rec["body_text"]
    assert "html version" in rec["body_html"]


def test_parse_bad_message_does_not_raise() -> None:
    rec = parse_message(b"not a real email at all", account_id=1, folder_id=1, uid=9)
    assert rec["uid"] == 9
    assert rec["subject"] == ""


def test_insert_and_dedupe(store: Store) -> None:
    acc = store.add_account("a", "i", "s", "u")
    fid = store.ensure_folder(acc.id, "INBOX")
    rec = parse_message(SAMPLE_RAW, acc.id, fid, uid=1)
    first = store.insert_message(rec)
    assert first is not None
    second = store.insert_message(rec)  # same (account, folder, uid)
    assert second is None
    assert store.count_messages() == 1


def test_list_orders_newest_first(store: Store) -> None:
    acc = store.add_account("a", "i", "s", "u")
    fid = store.ensure_folder(acc.id, "INBOX")
    for i, date in enumerate(
        [b"Tue, 10 Nov 2026 10:00:00 +0000", b"Tue, 10 Nov 2026 12:00:00 +0000"], start=1
    ):
        raw = (
            b"From: x@y.z\r\nTo: a@b.c\r\nSubject: m%d\r\nDate: %s\r\n\r\nbody\r\n"
            % (i, date)
        )
        store.insert_message(parse_message(raw, acc.id, fid, uid=i))
    msgs = store.list_messages(acc.id, limit=10)
    assert len(msgs) == 2
    assert msgs[0].subject == "m2"


def test_search_finds_body_text(store: Store) -> None:
    acc = store.add_account("a", "i", "s", "u")
    fid = store.ensure_folder(acc.id, "INBOX")
    store.insert_message(parse_message(SAMPLE_RAW, acc.id, fid, uid=1))
    hits = store.search(acc.id, "invoice")
    assert len(hits) == 1
    assert hits[0].subject.startswith("Invoice")


def test_search_malformed_query_falls_back(store: Store) -> None:
    acc = store.add_account("a", "i", "s", "u")
    fid = store.ensure_folder(acc.id, "INBOX")
    store.insert_message(parse_message(SAMPLE_RAW, acc.id, fid, uid=1))
    hits = store.search(acc.id, '"unbalanced')  # invalid FTS syntax
    assert isinstance(hits, list)


def test_build_message_roundtrips() -> None:
    raw = build_message(
        "me@example.com", ["you@example.com"], "subj", "body text",
        cc=["cc@example.com"], in_reply_to="<x@y>", references=["<x@y>"],
    )
    rec = parse_message(raw, 1, 1, 1)
    assert rec["subject"] == "subj"
    assert rec["from_addr"] == "me@example.com"
    assert "body text" in rec["body_text"]


def test_rpc_version_and_methods(tmp_path: Path) -> None:
    srv = RpcServer(str(tmp_path / "r.db"))
    resp = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "system.version"})
    assert resp is not None
    assert resp["result"]["version"] == __version__
    resp = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "system.methods"})
    assert resp is not None
    names = [m["name"] for m in resp["result"]]
    assert "mail.sync" in names and "mail.send" in names
    srv.store.close()


def test_rpc_rejects_bad_envelope(tmp_path: Path) -> None:
    srv = RpcServer(str(tmp_path / "r.db"))
    r = srv.handle({"jsonrpc": "1.0", "id": 1, "method": "system.version"})
    assert r is not None and r["error"]["code"] == -32600
    r = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "no.such"})
    assert r is not None and r["error"]["code"] == -32601
    r = srv.handle("not an object")
    assert r is not None and r["error"]["code"] == -32600
    srv.store.close()


def test_rpc_account_add_and_list(tmp_path: Path) -> None:
    srv = RpcServer(str(tmp_path / "r.db"))
    r = srv.handle({
        "jsonrpc": "2.0", "id": 1, "method": "account.add",
        "params": {"name": "fs", "imap_host": "i", "smtp_host": "s", "username": "u"},
    })
    assert r is not None and "error" not in r
    assert r["result"]["account"]["name"] == "fs"
    r = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "account.list"})
    assert r is not None and len(r["result"]) == 1
    srv.store.close()


def test_rpc_notification_returns_none(tmp_path: Path) -> None:
    srv = RpcServer(str(tmp_path / "r.db"))
    r = srv.handle({"jsonrpc": "2.0", "method": "system.version"})
    assert r is None
    srv.store.close()


def test_rpc_stdio_roundtrip(tmp_path: Path) -> None:
    import io

    srv = RpcServer(str(tmp_path / "r.db"))
    stdin = io.StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "system.version"}) + "\n"
        + "garbage not json\n"
        + "\n"
    )
    stdout = io.StringIO()
    srv.serve_stdio(stdin, stdout)
    lines = [ln for ln in stdout.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 2
    assert json.loads(lines[0])["result"]["version"] == __version__
    assert json.loads(lines[1])["error"]["code"] == -32700
    srv.store.close()


def test_plaintext_imap_is_refused() -> None:
    from openhail.imap import ImapClient, ImapError

    with pytest.raises(ImapError):
        ImapClient("example.com", 143, use_tls=False).connect()
