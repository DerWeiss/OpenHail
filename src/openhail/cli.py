"""Command-line interface for OpenHail."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .server import RpcServer


def _default_db() -> str:
    env = os.environ.get("OPENHAIL_DB")
    if env:
        return env
    return str(Path.home() / ".openhail" / "mail.db")


def _client(db: str) -> RpcServer:
    return RpcServer(db)


def _call(db: str, method: str, **params: Any) -> Any:
    srv = _client(db)
    resp = srv.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    srv.store.close()
    if resp is None:
        return None
    if "error" in resp:
        err = resp["error"]
        print(f"error: {err['message']}", file=sys.stderr)
        sys.exit(1)
    return resp["result"]


def _print(obj: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, ensure_ascii=False))
        return
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                print(" | ".join(f"{k}={v}" for k, v in item.items() if v not in (None, "")))
            else:
                print(item)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            print(f"{k}: {v}")
        return
    print(obj)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="openhail",
        description="OpenHail - open-source, local-first mail client.",
    )
    p.add_argument("--version", action="version", version=f"openhail {__version__}")
    p.add_argument("--db", default=_default_db(), help="path to mail.db")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("account", help="manage accounts")
    a_sub = a.add_subparsers(dest="action", required=True)
    a_add = a_sub.add_parser("add")
    a_add.add_argument("--name", required=True)
    a_add.add_argument("--imap", required=True, help="host[:port]")
    a_add.add_argument("--smtp", required=True, help="host[:port]")
    a_add.add_argument("--user", required=True)
    a_sub.add_parser("list")
    a_setpw = a_sub.add_parser(
        "set-password",
        help="store a password in the OS keyring (never passed on the command line)",
    )
    a_setpw.add_argument("--name", required=True)
    a_oauth = a_sub.add_parser(
        "add-oauth",
        help="add an account that signs in with OAuth2 (Gmail / Microsoft 365)",
    )
    a_oauth.add_argument("--name", required=True)
    a_oauth.add_argument("--provider", required=True, choices=["google", "microsoft"])
    a_oauth.add_argument("--user", required=True, help="the email address")

    s = sub.add_parser("sync", help="pull mail from IMAP")
    s.add_argument("--account", required=True)
    s.add_argument("--folder", default="INBOX")
    s.add_argument("--limit", type=int, default=100)

    ls = sub.add_parser("list", help="list stored messages")
    ls.add_argument("--account", required=True)
    ls.add_argument("--limit", type=int, default=20)
    ls.add_argument("--folder", default=None)

    rd = sub.add_parser("read", help="read a message by id")
    rd.add_argument("id", type=int)

    se = sub.add_parser("search", help="full-text search")
    se.add_argument("--account", required=True)
    se.add_argument("--query", required=True)
    se.add_argument("--limit", type=int, default=20)

    sd = sub.add_parser("send", help="send a message")
    sd.add_argument("--account", required=True)
    sd.add_argument("--to", required=True)
    sd.add_argument("--cc", default=None)
    sd.add_argument("--subject", required=True)
    sd.add_argument("--body", required=True)

    sub.add_parser("stats", help="local store statistics")

    oa = sub.add_parser("oauth", help="OAuth2 / XOAUTH2 sign-in (Gmail, Microsoft 365)")
    oa_sub = oa.add_subparsers(dest="action", required=True)
    oa_sub.add_parser("providers", help="list supported providers")
    oa_login = oa_sub.add_parser(
        "login", help="device-code sign-in; prints a URL and code to visit"
    )
    oa_login.add_argument("--account", required=True)
    oa_login.add_argument("--provider", required=True, choices=["google", "microsoft"])
    oa_login.add_argument("--client-id", required=True)
    oa_status = oa_sub.add_parser("status", help="is a token stored for this account?")
    oa_status.add_argument("--account", required=True)
    oa_refresh = oa_sub.add_parser("refresh", help="force a token refresh now")
    oa_refresh.add_argument("--account", required=True)
    oa_refresh.add_argument("--provider", required=True, choices=["google", "microsoft"])
    oa_refresh.add_argument("--client-id", required=True)

    sv = sub.add_parser("serve", help="run the JSON-RPC server on stdio")
    sv.add_argument("--stdio", action="store_true", default=True)

    return p


def _split_hostport(value: str, default_port: int) -> tuple[str, int]:
    if ":" in value:
        host, _, port = value.rpartition(":")
        return host, int(port)
    return value, default_port


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    db = args.db

    if args.cmd == "serve":
        RpcServer(db).serve_stdio()
        return 0

    if args.cmd == "oauth":
        if args.action == "providers":
            _print(_call(db, "oauth.providers"), args.json)
            return 0
        if args.action == "status":
            _print(_call(db, "oauth.status", account=args.account), args.json)
            return 0
        if args.action == "login":
            start = _call(
                db, "oauth.device-start",
                account=args.account, provider=args.provider, client_id=args.client_id,
            )
            print()
            print(f"  1. open:  {start['verification_uri']}")
            print(f"  2. enter: {start['user_code']}")
            print()
            print("  waiting for you to finish in the browser...")
            done = _call(
                db, "oauth.device-poll",
                account=args.account, provider=args.provider,
                client_id=args.client_id, device_code=start["device_code"],
                interval=start["interval"], expires_at=start["expires_at"],
            )
            _print(done, args.json)
            return 0
        if args.action == "refresh":
            _print(_call(
                db, "oauth.refresh",
                account=args.account, provider=args.provider, client_id=args.client_id,
            ), args.json)
            return 0

    if args.cmd == "account":
        if args.action == "list":
            _print(_call(db, "account.list"), args.json)
            return 0
        if args.action == "set-password":
            pw = os.environ.get("OPENHAIL_PASSWORD") or getpass.getpass(
                "password (not echoed): "
            )
            if not pw:
                print("error: empty password", file=sys.stderr)
                return 1
            _print(_call(db, "account.set-password", name=args.name, password=pw), args.json)
            return 0
        imap_host, imap_port = _split_hostport(args.imap, 993)
        smtp_host, smtp_port = _split_hostport(args.smtp, 587)
        out = _call(
            db, "account.add",
            name=args.name, imap_host=imap_host, imap_port=imap_port,
            smtp_host=smtp_host, smtp_port=smtp_port,
            username=args.user,
        )
        _print(out, args.json)
        return 0

    if args.cmd == "sync":
        _print(_call(db, "mail.sync", account=args.account,
                     folder=args.folder, limit=args.limit), args.json)
        return 0

    if args.cmd == "list":
        _print(_call(db, "mail.list", account=args.account,
                     limit=args.limit, folder=args.folder), args.json)
        return 0

    if args.cmd == "read":
        _print(_call(db, "mail.read", id=args.id), args.json)
        return 0

    if args.cmd == "search":
        _print(_call(db, "mail.search", account=args.account,
                     query=args.query, limit=args.limit), args.json)
        return 0

    if args.cmd == "send":
        cc = [c.strip() for c in args.cc.split(",")] if args.cc else None
        to = [t.strip() for t in args.to.split(",")]
        _print(_call(db, "mail.send", account=args.account, to=to,
                     subject=args.subject, body=args.body, cc=cc), args.json)
        return 0

    if args.cmd == "stats":
        _print(_call(db, "mail.stats"), args.json)
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
