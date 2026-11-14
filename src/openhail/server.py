"""JSON-RPC 2.0 control surface for OpenHail.

Agent-friendly: one JSON object per line over stdio. No HTTP server, no auth
theatre, no CORS. The caller owns the process.

Methods mirror the store/transport API one-to-one so the schema is learnable
and stable.
"""

from __future__ import annotations

import json
import sys
import traceback
from dataclasses import dataclass
from typing import Any, Callable

from . import __version__
from .imap import ImapClient, ImapError
from .mime import build_message, parse_message
from .secrets import SecretError, get_password, set_password
from .smtp import SmtpError, SmtpSender
from .store import Store

JSONRPC = "2.0"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
APP_ERROR = -32000


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _ok(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC, "id": req_id, "result": result}


def _err(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    e: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    return {"jsonrpc": JSONRPC, "id": req_id, "error": e}


@dataclass
class Handler:
    name: str
    params: tuple[str, ...]
    fn: Callable[..., Any]
    doc: str


class RpcServer:
    """Dispatch JSON-RPC requests onto the OpenHail core."""

    def __init__(self, db_path: str = "mail.db") -> None:
        self.store = Store(db_path)
        self.methods: dict[str, Handler] = {}
        self._register()

    # ---- registration ---------------------------------------------------

    def _add(self, name: str, params: tuple[str, ...], doc: str):
        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.methods[name] = Handler(name, params, fn, doc)
            return fn
        return deco

    def _register(self) -> None:
        add = self._add

        @add("system.version", (), "Return the OpenHail version.")
        def _version() -> dict[str, Any]:
            return {"version": __version__, "jsonrpc": JSONRPC}

        @add("system.methods", (), "List available RPC methods and their params.")
        def _methods() -> list[dict[str, Any]]:
            return [
                {"name": h.name, "params": list(h.params), "doc": h.doc}
                for h in sorted(self.methods.values(), key=lambda x: x.name)
            ]

        @add("account.add", ("name", "imap_host", "smtp_host", "username"), "Add an account.")
        def _account_add(
            name: str,
            imap_host: str,
            smtp_host: str,
            username: str,
            imap_port: int = 993,
            smtp_port: int = 587,
            password: str | None = None,
        ) -> dict[str, Any]:
            acc = self.store.add_account(
                name=name,
                imap_host=imap_host,
                smtp_host=smtp_host,
                username=username,
                imap_port=int(imap_port),
                smtp_port=int(smtp_port),
            )
            stored_secret = False
            if password:
                try:
                    set_password(name, username, password)
                    stored_secret = True
                except SecretError as exc:
                    raise RpcError(APP_ERROR, str(exc))
            return {"account": acc.to_dict(), "password_stored": stored_secret}

        @add("account.list", (), "List configured accounts.")
        def _account_list() -> list[dict[str, Any]]:
            return [a.to_dict() for a in self.store.list_accounts()]

        @add("folder.list", ("account",), "List folders for an account (local only).")
        def _folder_list(account: str) -> list[str]:
            acc = self.store.get_account(account)
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {account}")
            cur = self.store.conn.execute(
                "SELECT name FROM folders WHERE account_id=? ORDER BY name", (acc.id,)
            )
            return [r["name"] for r in cur.fetchall()]

        @add("mail.sync", ("account",), "Pull new messages from IMAP into the local store.")
        def _mail_sync(account: str, folder: str = "INBOX", limit: int = 100) -> dict[str, Any]:
            acc = self.store.get_account(account)
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {account}")
            password = get_password(acc.name, acc.username)
            if password is None:
                raise RpcError(APP_ERROR, f"no password available for {account}")
            folder_id = self.store.ensure_folder(acc.id, folder)
            last_uid = self.store.get_last_uid(folder_id)
            added = 0
            max_uid = last_uid
            try:
                with ImapClient(acc.imap_host, acc.imap_port, acc.use_tls) as client:
                    client.login(acc.username, password)
                    uv = client.uid_validity()
                    if uv:
                        self.store.set_uidvalidity(folder_id, uv)
                    client.select(folder, readonly=True)
                    for fetched in client.fetch_since_uid(last_uid, limit=limit):
                        rec = parse_message(fetched.raw, acc.id, folder_id, fetched.uid)
                        if self.store.insert_message(rec) is not None:
                            added += 1
                        max_uid = max(max_uid, fetched.uid)
            except ImapError as exc:
                raise RpcError(APP_ERROR, f"imap: {exc}")
            if max_uid > last_uid:
                self.store.set_last_uid(folder_id, max_uid)
            return {"added": added, "last_uid": max_uid}

        @add("mail.list", ("account",), "List recent messages, newest first.")
        def _mail_list(account: str, limit: int = 20, folder: str | None = None):
            acc = self.store.get_account(account)
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {account}")
            msgs = self.store.list_messages(acc.id, limit=int(limit), folder=folder)
            return [m.to_dict() for m in msgs]

        @add("mail.read", ("id",), "Read one message by local row id.")
        def _mail_read(id: int) -> dict[str, Any]:
            msg = self.store.get_message(int(id))
            if msg is None:
                raise RpcError(INVALID_PARAMS, f"no message with id {id}")
            row = self.store.conn.execute(
                "SELECT body_html, cc_addr, in_reply_to FROM messages WHERE id=?", (int(id),)
            ).fetchone()
            d = msg.to_dict()
            if row:
                d["body_html"] = row["body_html"]
                d["cc_addr"] = row["cc_addr"]
                d["in_reply_to"] = row["in_reply_to"]
            return d

        @add("mail.search", ("account", "query"), "Full-text search over stored mail.")
        def _mail_search(account: str, query: str, limit: int = 20):
            acc = self.store.get_account(account)
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {account}")
            return [m.to_dict() for m in self.store.search(acc.id, query, int(limit))]

        @add("mail.send", ("account", "to", "subject", "body"), "Send mail over SMTP STARTTLS.")
        def _mail_send(
            account: str,
            to: list[str] | str,
            subject: str,
            body: str,
            cc: list[str] | None = None,
        ) -> dict[str, Any]:
            acc = self.store.get_account(account)
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {account}")
            password = get_password(acc.name, acc.username)
            if password is None:
                raise RpcError(APP_ERROR, f"no password available for {account}")
            to_list = [to] if isinstance(to, str) else list(to)
            raw = build_message(acc.username, to_list, subject, body, cc=cc)
            try:
                result = SmtpSender(acc.smtp_host, acc.smtp_port).send(
                    acc.username, password, acc.username, to_list, raw, cc=cc
                )
            except SmtpError as exc:
                raise RpcError(APP_ERROR, f"smtp: {exc}")
            return result.to_dict()

        @add("mail.stats", (), "Local store statistics.")
        def _mail_stats() -> dict[str, Any]:
            return {
                "messages": self.store.count_messages(),
                "accounts": len(self.store.list_accounts()),
                "db_path": str(self.store.path),
            }

    # ---- dispatch -------------------------------------------------------

    def handle(self, request: Any) -> dict[str, Any] | None:
        if not isinstance(request, dict):
            return _err(None, INVALID_REQUEST, "request must be a JSON object")
        req_id = request.get("id")
        if request.get("jsonrpc") != JSONRPC:
            return _err(req_id, INVALID_REQUEST, 'jsonrpc must be "2.0"')
        method = request.get("method")
        if not isinstance(method, str):
            return _err(req_id, INVALID_REQUEST, "method must be a string")
        handler = self.methods.get(method)
        if handler is None:
            return _err(req_id, METHOD_NOT_FOUND, f"unknown method: {method}")
        params = request.get("params") or {}
        try:
            if isinstance(params, list):
                result = handler.fn(*params)
            elif isinstance(params, dict):
                result = self._call_kw(handler, params)
            else:
                return _err(req_id, INVALID_PARAMS, "params must be object or array")
        except RpcError as exc:
            return _err(req_id, exc.code, exc.message, exc.data)
        except TypeError as exc:
            return _err(req_id, INVALID_PARAMS, str(exc))
        except Exception as exc:
            return _err(
                req_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}",
                {"trace": traceback.format_exc(limit=4)},
            )
        if req_id is None:
            return None  # notification
        return _ok(req_id, result)

    @staticmethod
    def _call_kw(handler: Handler, params: dict[str, Any]) -> Any:
        # Accept display names rather than raw Python signatures.
        for key in ("id", "to", "cc", "from"):
            if key in params and key == "from":
                params["from_addr"] = params.pop("from")
        return handler.fn(**params)

    def serve_stdio(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError as exc:
                resp = _err(None, PARSE_ERROR, f"parse error: {exc}")
            else:
                if isinstance(request, list):
                    batch = []
                    for item in request:
                        r = self.handle(item)
                        if r is not None:
                            batch.append(r)
                    resp = batch if batch else None
                else:
                    resp = self.handle(request)
            if resp is not None:
                stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                stdout.flush()
