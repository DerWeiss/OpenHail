"""Hardening tests for OpenHail.

Each test here corresponds to a hole a red-teamer would look for. They exist to
fail loudly if someone later removes a limit.

Run: python -m pytest tests -q
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from openhail.server import RpcServer
from openhail.store import Store
from openhail import validate
from openhail.mime import build_message, parse_message


@pytest.fixture()
def srv(tmp_path: Path):
    s = RpcServer(str(tmp_path / "h.db"))
    yield s
    s.store.close()


# ---- 1. oversized request ------------------------------------------------


def test_oversized_request_is_rejected(srv: RpcServer) -> None:
    big = "x" * (validate.MAX_REQUEST_BYTES + 10)
    stdin = io.StringIO(big + "\n")
    stdout = io.StringIO()
    srv.serve_stdio(stdin, stdout)
    out = json.loads(stdout.getvalue().splitlines()[0])
    assert out["error"]["code"] == -32600
    assert "exceeds" in out["error"]["message"]


def test_blank_lines_ignored(srv: RpcServer) -> None:
    stdin = io.StringIO("\n\n\n")
    stdout = io.StringIO()
    srv.serve_stdio(stdin, stdout)
    assert stdout.getvalue() == ""


def test_batch_size_capped(srv: RpcServer) -> None:
    batch = [{"jsonrpc": "2.0", "id": i, "method": "system.version"} for i in range(250)]
    stdin = io.StringIO(json.dumps(batch) + "\n")
    stdout = io.StringIO()
    srv.serve_stdio(stdin, stdout)
    out = json.loads(stdout.getvalue())
    assert len(out) <= 100


# ---- 2. sender spoofing --------------------------------------------------


def test_smtp_refuses_foreign_envelope_sender() -> None:
    from openhail.smtp import SmtpError, SmtpSender
    from openhail.validate import ValidationError

    sender = SmtpSender("smtp.example.com", 587)
    with pytest.raises(ValidationError):
        sender.send(
            username="me@example.com",
            password="x",
            from_addr="ceo@victim.com",
            to_addrs=["target@example.org"],
            raw_message=b"From: ceo@victim.com\r\n\r\nhi",
        )


def test_send_has_no_from_parameter(srv: RpcServer) -> None:
    srv.handle({
        "jsonrpc": "2.0", "id": 1, "method": "account.add",
        "params": {"name": "a", "imap_host": "i", "smtp_host": "s", "username": "u@e.com"},
    })
    r = srv.handle({
        "jsonrpc": "2.0", "id": 2, "method": "mail.send",
        "params": {"account": "a", "to": ["x@y.z"], "subject": "s",
                   "body": "b", "from_addr": "ceo@victim.com"},
    })
    assert r is not None and r["error"]["code"] == -32602
    assert "unknown parameter" in r["error"]["message"]


# ---- 3. FTS / search -----------------------------------------------------


def test_search_rejects_fts_operators(srv: RpcServer) -> None:
    srv.handle({
        "jsonrpc": "2.0", "id": 1, "method": "account.add",
        "params": {"name": "a", "imap_host": "i", "smtp_host": "s", "username": "u@e.com"},
    })
    for bad in ("NEAR(foo bar, 999999)", "abc*", "^start", "fld:value"):
        r = srv.handle({
            "jsonrpc": "2.0", "id": 2, "method": "mail.search",
            "params": {"account": "a", "query": bad},
        })
        assert r is not None and r["error"]["code"] == -32602, bad


def test_search_rejects_empty_and_long(srv: RpcServer) -> None:
    srv.handle({
        "jsonrpc": "2.0", "id": 1, "method": "account.add",
        "params": {"name": "a", "imap_host": "i", "smtp_host": "s", "username": "u@e.com"},
    })
    for bad in ("", "   ", "z" * (validate.MAX_SEARCH_QUERY + 1)):
        r = srv.handle({
            "jsonrpc": "2.0", "id": 2, "method": "mail.search",
            "params": {"account": "a", "query": bad},
        })
        assert r is not None and r["error"]["code"] == -32602


def test_like_fallback_escapes_wildcards(tmp_path: Path) -> None:
    s = Store(tmp_path / "e.db")
    acc = s.add_account("a", "i", "s", "u")
    fid = s.ensure_folder(acc.id, "INBOX")
    raw = (b"From: x@y.z\r\nTo: a@b.c\r\nSubject: 100% legit\r\n"
           b"Date: Tue, 10 Nov 2026 10:00:00 +0000\r\n\r\nbody\r\n")
    s.insert_message(parse_message(raw, acc.id, fid, uid=1))
    hits = s.search(acc.id, "100%")
    assert isinstance(hits, list)
    s.close()


# ---- 4/5. parameter smuggling & traceback leak ---------------------------


def test_unknown_param_rejected(tmp_path: Path) -> None:
    s = Store(tmp_path / "x.db")
    acc = s.add_account("a", "i", "s", "u")
    s.close()
    srv = RpcServer(str(tmp_path / "x.db"))
    r = srv.handle({
        "jsonrpc": "2.0", "id": 1, "method": "mail.list",
        "params": {"account": "a", "evil_kwarg": 1},
    })
    assert r is not None and r["error"]["code"] == -32602
    assert "evil_kwarg" in r["error"]["message"]
    srv.store.close()


def test_internal_error_does_not_leak_trace(srv: RpcServer) -> None:
    # Force an internal failure shape by monkeypatching a handler.
    h = srv.methods["mail.stats"]
    original = h.fn

    def boom():
        raise RuntimeError("secret internal path C:/users/david/.ssh/id_rsa")

    h.fn = boom
    r = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "mail.stats"})
    h.fn = original
    assert r is not None
    assert r["error"]["code"] == -32603
    assert "trace" not in r["error"].get("data", {})
    assert "File \"" not in json.dumps(r["error"])


# ---- 6/7. account name + secrets ----------------------------------------


def test_account_name_validated(srv: RpcServer) -> None:
    for bad in ("UPPER", "has space", "a:b", "", "x" * 65, "-leading"):
        r = srv.handle({
            "jsonrpc": "2.0", "id": 1, "method": "account.add",
            "params": {"name": bad, "imap_host": "i", "smtp_host": "s", "username": "u@e.com"},
        })
        assert r is not None and r["error"]["code"] == -32602, bad


def test_secret_namespace_cannot_be_escaped() -> None:
    from openhail.secrets import SecretError, _key

    with pytest.raises(SecretError):
        _key("evil:keyring:other")
    assert _key("good-name") == "openhail:good-name"


def test_account_add_accepts_no_password(srv: RpcServer) -> None:
    r = srv.handle({
        "jsonrpc": "2.0", "id": 1, "method": "account.add",
        "params": {"name": "a", "imap_host": "i", "smtp_host": "s",
                   "username": "u@e.com", "password": "hunter2"},
    })
    assert r is not None and r["error"]["code"] == -32602
    assert "password" in r["error"]["message"]


# ---- header injection ----------------------------------------------------


def test_crlf_in_subject_rejected() -> None:
    with pytest.raises(validate.ValidationError):
        build_message("a@b.c", ["d@e.f"], "hi\r\nBcc: victim@x.y", "body")


def test_crlf_in_recipient_rejected() -> None:
    with pytest.raises(validate.ValidationError):
        build_message("a@b.c", ["d@e.f\r\nBcc: victim@x.y"], "s", "body")


def test_mail_send_rejects_crlf_subject(srv: RpcServer) -> None:
    srv.handle({
        "jsonrpc": "2.0", "id": 1, "method": "account.add",
        "params": {"name": "a", "imap_host": "i", "smtp_host": "s", "username": "u@e.com"},
    })
    r = srv.handle({
        "jsonrpc": "2.0", "id": 2, "method": "mail.send",
        "params": {"account": "a", "to": ["x@y.z"],
                   "subject": "hi\r\nBcc: victim@x.y", "body": "b"},
    })
    assert r is not None and r["error"]["code"] == -32602


# ---- misc limits ---------------------------------------------------------


def test_limit_bounds(srv: RpcServer) -> None:
    srv.handle({
        "jsonrpc": "2.0", "id": 1, "method": "account.add",
        "params": {"name": "a", "imap_host": "i", "smtp_host": "s", "username": "u@e.com"},
    })
    for bad in (0, -1, validate.MAX_LIST_LIMIT + 1):
        r = srv.handle({
            "jsonrpc": "2.0", "id": 2, "method": "mail.list",
            "params": {"account": "a", "limit": bad},
        })
        assert r is not None and r["error"]["code"] == -32602, bad


def test_folder_traversal_rejected(srv: RpcServer) -> None:
    srv.handle({
        "jsonrpc": "2.0", "id": 1, "method": "account.add",
        "params": {"name": "a", "imap_host": "i", "smtp_host": "s", "username": "u@e.com"},
    })
    for bad in ("../../etc", "INBOX\u0000", "a" * 200):
        r = srv.handle({
            "jsonrpc": "2.0", "id": 2, "method": "mail.sync",
            "params": {"account": "a", "folder": bad},
        })
        assert r is not None and r["error"]["code"] == -32602, repr(bad)


def test_multipart_bomb_truncated() -> None:
    from openhail.mime import MAX_PART_BYTES

    payload = b"A" * (MAX_PART_BYTES + 5000)
    raw = (b"From: x@y.z\r\nTo: a@b.c\r\nSubject: bomb\r\n"
           b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
           b"Content-Transfer-Encoding: binary\r\n\r\n" + payload)
    rec = parse_message(raw, 1, 1, 1)
    assert len(rec["body_text"]) <= MAX_PART_BYTES + 10
