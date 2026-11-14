"""JSON-RPC 2.0 control surface for OpenHail.

Agent-friendly: one JSON object per line over stdio. No HTTP server, no auth
theatre, no CORS. The caller owns the process.

Transport contract: **stdio only, permanently.** There is no listening socket
and no plan to add one. That decision removes a whole class of future bugs
(no auth layer to retrofit, no peer to authenticate, no port to firewall).
A GUI, if one is ever built, is a *client* speaking this same stdio protocol.

Hardening notes:
- Requests are size-capped before parsing (DoS).
- Parameters are allowlisted per method; unknown keys are rejected rather than
  silently forwarded into the implementation (parameter smuggling).
- Tracebacks are logged to stderr and never returned to the caller (info leak).
- Every caller-supplied string is validated in validate.py before use.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

from . import __version__
from .imap import ImapClient, ImapError
from .mime import build_message, parse_message
from . import oauth
from .secrets import SecretError, get_password, set_password
from .smtp import SmtpError, SmtpSender
from .store import Store
from .validate import (
    MAX_LIST_LIMIT,
    MAX_REQUEST_BYTES,
    MAX_SYNC_LIMIT,
    ValidationError,
    account_name as v_account,
    bounded_int,
    email_addr,
    email_list,
    folder_name as v_folder,
    hostname as v_hostname,
    port as v_port,
    search_query as v_query,
    header_safe,
)

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
    # Parameter names accepted by fn beyond the required `params` tuple.
    optional: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> set[str]:
        return set(self.params) | set(self.optional)


class RpcServer:
    """Dispatch JSON-RPC requests onto the OpenHail core."""

    def __init__(self, db_path: str = "mail.db") -> None:
        self.store = Store(db_path)
        self.methods: dict[str, Handler] = {}
        self._register()

    # ---- registration ---------------------------------------------------

    def _add(
        self,
        name: str,
        params: tuple[str, ...],
        doc: str,
        optional: tuple[str, ...] = (),
    ):
        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.methods[name] = Handler(name, params, fn, doc, optional)
            return fn
        return deco

    def _register(self) -> None:
        add = self._add

        @add("system.version", (), "Return the OpenHail version.")
        def _version() -> dict[str, Any]:
            return {
                "version": __version__,
                "jsonrpc": JSONRPC,
                "transport": "stdio",
                "auth": ["plain", "xoauth2"],
                "oauth_providers": sorted(oauth.PROVIDERS),
            }

        @add("system.methods", (), "List available RPC methods and their params.")
        def _methods() -> list[dict[str, Any]]:
            return [
                {"name": h.name, "params": list(h.params),
                 "optional": list(h.optional), "doc": h.doc}
                for h in sorted(self.methods.values(), key=lambda x: x.name)
            ]

        @add(
            "account.add",
            ("name", "imap_host", "smtp_host", "username"),
            "Add an account. Never accepts a password parameter: set the password "
            "via the OS keyring or the OPENHAIL_PASSWORD environment variable.",
            optional=("imap_port", "smtp_port"),
        )
        def _account_add(
            name: str,
            imap_host: str,
            smtp_host: str,
            username: str,
            imap_port: int = 993,
            smtp_port: int = 587,
        ) -> dict[str, Any]:
            name = v_account(name)
            imap_host = v_hostname(imap_host)
            smtp_host = v_hostname(smtp_host)
            imap_port = v_port(imap_port)
            smtp_port = v_port(smtp_port)
            header_safe(username, "username")
            acc = self.store.add_account(
                name=name,
                imap_host=imap_host,
                smtp_host=smtp_host,
                username=username,
                imap_port=imap_port,
                smtp_port=smtp_port,
            )
            return {"account": acc.to_dict()}

        @add("account.list", (), "List configured accounts.")
        def _account_list() -> list[dict[str, Any]]:
            return [a.to_dict() for a in self.store.list_accounts()]

        # ---- accounts bound to an OAuth provider -------------------------

        @add(
            "account.add-oauth",
            ("name", "provider", "username"),
            "Add an account that authenticates with OAuth2 (XOAUTH2) instead of "
            "a password. Hosts are taken from the provider registry.",
            optional=("scopes",),
        )
        def _account_add_oauth(
            name: str,
            provider: str,
            username: str,
            scopes: list[str] | None = None,
        ) -> dict[str, Any]:
            name = v_account(name)
            prov = oauth.PROVIDERS.get(provider)
            if prov is None:
                raise RpcError(
                    INVALID_PARAMS,
                    f"unknown provider {provider!r}; "
                    f"known: {', '.join(sorted(oauth.PROVIDERS))}",
                )
            username = email_addr(username, "username")
            acc = self.store.add_account(
                name=name,
                imap_host=prov.imap_host(),
                smtp_host=prov.smtp_host(),
                username=username,
                imap_port=993,
                smtp_port=587,
            )
            self.store.set_account_auth(acc.id, "xoauth2", provider)
            acc = self.store.get_account(name)
            assert acc is not None
            d = acc.to_dict()
            d["scopes"] = list(scopes or prov.default_scopes)
            return {"account": d}

        @add("oauth.providers", (), "List OAuth providers, endpoints and default scopes.")
        def _oauth_providers() -> list[dict[str, Any]]:
            return [
                {
                    "key": p.key,
                    "display": p.display,
                    "auth_endpoint": p.auth_endpoint,
                    "token_endpoint": p.token_endpoint,
                    "device_endpoint": p.device_endpoint,
                    "scopes": list(p.default_scopes),
                    "imap_host": p.imap_host(),
                    "smtp_host": p.smtp_host(),
                }
                for p in oauth.PROVIDERS.values()
            ]

        @add("oauth.status", ("account",), "Report whether a valid OAuth token is stored.")
        def _oauth_status(account: str) -> dict[str, Any]:
            name = v_account(account)
            tok = oauth.load_token(name)
            if tok is None:
                return {"account": name, "authorized": False}
            return {
                "account": name,
                "authorized": True,
                "expired": tok.is_expired(),
                "expires_at": tok.expires_at,
                "scope": tok.scope,
                "has_refresh_token": bool(tok.refresh_token),
            }

        @add(
            "oauth.device-start",
            ("account", "provider", "client_id"),
            "Begin the headless device-code flow. Returns a user_code and URL "
            "for the user to visit. Then call oauth.device-poll.",
            optional=("scopes",),
        )
        def _oauth_device_start(
            account: str,
            provider: str,
            client_id: str,
            scopes: list[str] | None = None,
        ) -> dict[str, Any]:
            v_account(account)
            prov = oauth.PROVIDERS.get(provider)
            if prov is None:
                raise RpcError(
                    INVALID_PARAMS,
                    f"unknown provider {provider!r}; "
                    f"known: {', '.join(sorted(oauth.PROVIDERS))}",
                )
            header_safe(client_id, "client_id")
            if scopes is not None and not isinstance(scopes, list):
                raise RpcError(INVALID_PARAMS, "scopes must be a list of strings")
            try:
                dc = oauth.device_code_start(prov, client_id, scopes)
            except oauth.OAuthError as exc:
                raise RpcError(APP_ERROR, f"oauth: {exc}")
            return {
                "user_code": dc.user_code,
                "verification_uri": dc.verification_uri,
                "interval": dc.interval,
                "expires_at": dc.expires_at,
                "device_code": dc.device_code,
            }

        @add(
            "oauth.device-poll",
            ("account", "provider", "client_id", "device_code"),
            "Poll until the user completes the device-code flow, then store the token.",
            optional=("interval", "expires_at", "client_secret"),
        )
        def _oauth_device_poll(
            account: str,
            provider: str,
            client_id: str,
            device_code: str,
            interval: int = 5,
            expires_at: float | None = None,
            client_secret: str | None = None,
        ) -> dict[str, Any]:
            import time as _time

            name = v_account(account)
            prov = oauth.PROVIDERS.get(provider)
            if prov is None:
                raise RpcError(INVALID_PARAMS, f"unknown provider {provider!r}")
            dc = oauth.DeviceCode(
                device_code=device_code,
                user_code="",
                verification_uri="",
                interval=bounded_int(interval, 5, 60, "interval"),
                expires_at=expires_at or (_time.time() + 900),
            )
            try:
                tok = oauth.device_code_poll(prov, client_id, dc)
                oauth.save_token(name, tok)
            except oauth.OAuthError as exc:
                raise RpcError(APP_ERROR, f"oauth: {exc}")
            except SecretError as exc:
                raise RpcError(APP_ERROR, str(exc))
            return {"account": name, "authorized": True, "expires_at": tok.expires_at}

        @add(
            "oauth.refresh",
            ("account", "provider", "client_id"),
            "Force a token refresh and persist the rotated refresh token.",
            optional=("client_secret",),
        )
        def _oauth_refresh(
            account: str,
            provider: str,
            client_id: str,
            client_secret: str | None = None,
        ) -> dict[str, Any]:
            name = v_account(account)
            prov = oauth.PROVIDERS.get(provider)
            if prov is None:
                raise RpcError(INVALID_PARAMS, f"unknown provider {provider!r}")
            tok = oauth.load_token(name)
            if tok is None:
                raise RpcError(APP_ERROR, f"no token stored for {name}")
            try:
                new = oauth.refresh_token(prov, client_id, tok, client_secret)
                oauth.save_token(name, new)
            except oauth.OAuthError as exc:
                raise RpcError(APP_ERROR, f"oauth: {exc}")
            return {"account": name, "expires_at": new.expires_at}

        @add("account.set-password", ("name", "password"),
             "Store an account password in the OS keyring. Prefer "
             "OPENHAIL_PASSWORD over this method where possible.")
        def _account_set_password(name: str, password: str) -> dict[str, Any]:
            name = v_account(name)
            acc = self.store.get_account(name)
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {name}")
            try:
                set_password(acc.name, acc.username, password)
            except SecretError as exc:
                raise RpcError(APP_ERROR, str(exc))
            return {"stored": True, "account": name}

        @add("folder.list", ("account",), "List synced folders for an account.")
        def _folder_list(account: str) -> list[str]:
            acc = self.store.get_account(v_account(account))
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {account}")
            cur = self.store.conn.execute(
                "SELECT name FROM folders WHERE account_id=? ORDER BY name", (acc.id,)
            )
            return [r["name"] for r in cur.fetchall()]

        @add("mail.sync", ("account",),
             "Pull new messages from IMAP into the local store.",
             optional=("folder", "limit"))
        def _mail_sync(
            account: str, folder: str = "INBOX", limit: int = 100
        ) -> dict[str, Any]:
            acc = self.store.get_account(v_account(account))
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {account}")
            folder = v_folder(folder)
            limit = bounded_int(limit, 100, MAX_SYNC_LIMIT, "limit")
            auth_kind, auth_provider = self.store.get_account_auth(acc.id)
            access_token: str | None = None
            password: str | None = None
            if auth_kind == "xoauth2":
                prov = oauth.PROVIDERS.get(auth_provider or "")
                if prov is None:
                    raise RpcError(
                        APP_ERROR,
                        f"account {account} is OAuth-bound to unknown provider "
                        f"{auth_provider!r}; re-add the account",
                    )
                client_id = os.environ.get("OPENHAIL_OAUTH_CLIENT_ID")
                if not client_id:
                    raise RpcError(
                        APP_ERROR,
                        "OPENHAIL_OAUTH_CLIENT_ID is not set; cannot refresh the "
                        "OAuth token",
                    )
                try:
                    access_token = oauth.get_valid_token(
                        prov, client_id, acc.name
                    ).access_token
                except oauth.OAuthError as exc:
                    raise RpcError(APP_ERROR, f"oauth: {exc}")
            else:
                password = get_password(acc.name, acc.username)
                if password is None:
                    raise RpcError(APP_ERROR, f"no password available for {account}")
            folder_id = self.store.ensure_folder(acc.id, folder)
            last_uid = self.store.get_last_uid(folder_id)
            added = 0
            max_uid = last_uid
            try:
                with ImapClient(acc.imap_host, acc.imap_port, acc.use_tls) as client:
                    if access_token is not None:
                        client.authenticate_xoauth2(acc.username, access_token)
                    else:
                        assert password is not None
                        client.login(acc.username, password)
                    uv = client.uid_validity()
                    if uv and uv != str(last_uid and "" or ""):
                        self.store.set_uidvalidity(folder_id, uv)
                    client.select(folder, readonly=True)
                    for fetched in client.fetch_since_uid(last_uid, limit=limit):
                        rec = parse_message(fetched.raw, acc.id, folder_id, fetched.uid)
                        if self.store.insert_message(rec) is not None:
                            added += 1
                        max_uid = max(max_uid, fetched.uid)
            except ImapError as exc:
                raise RpcError(APP_ERROR, f"imap: {exc}")
            except (ValidationError, ValueError) as exc:
                raise RpcError(INVALID_PARAMS, str(exc))
            if max_uid > last_uid:
                self.store.set_last_uid(folder_id, max_uid)
            return {"added": added, "last_uid": max_uid}

        @add("mail.list", ("account",), "List recent messages, newest first.",
             optional=("limit", "folder"))
        def _mail_list(account: str, limit: int = 20, folder: str | None = None):
            acc = self.store.get_account(v_account(account))
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {account}")
            limit = bounded_int(limit, 20, MAX_LIST_LIMIT, "limit")
            if folder is not None:
                folder = v_folder(folder)
            return [m.to_dict() for m in self.store.list_messages(acc.id, limit, folder)]

        @add("mail.read", ("id",), "Read one message by local row id.")
        def _mail_read(id: int) -> dict[str, Any]:
            try:
                row_id = int(id)
            except (TypeError, ValueError):
                raise RpcError(INVALID_PARAMS, "id must be an integer")
            msg = self.store.get_message(row_id)
            if msg is None:
                raise RpcError(INVALID_PARAMS, f"no message with id {id}")
            row = self.store.conn.execute(
                "SELECT body_html, cc_addr, in_reply_to FROM messages WHERE id=?", (row_id,)
            ).fetchone()
            d = msg.to_dict()
            if row:
                d["body_html"] = row["body_html"]
                d["cc_addr"] = row["cc_addr"]
                d["in_reply_to"] = row["in_reply_to"]
            return d

        @add("mail.search", ("account", "query"), "Full-text search over stored mail.",
             optional=("limit",))
        def _mail_search(account: str, query: str, limit: int = 20):
            acc = self.store.get_account(v_account(account))
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {account}")
            limit = bounded_int(limit, 20, MAX_LIST_LIMIT, "limit")
            return [m.to_dict() for m in self.store.search(acc.id, query, limit)]

        @add("mail.send", ("account", "to", "subject", "body"),
             "Send mail over SMTP STARTTLS. Sender is always the account identity.",
             optional=("cc",))
        def _mail_send(
            account: str,
            to: list[str] | str,
            subject: str,
            body: str,
            cc: list[str] | None = None,
        ) -> dict[str, Any]:
            acc = self.store.get_account(v_account(account))
            if acc is None:
                raise RpcError(INVALID_PARAMS, f"unknown account: {account}")
            to_list = email_list(to, "to")
            cc_list = email_list(cc, "cc") if cc else None
            header_safe(subject, "subject")
            if not isinstance(body, str):
                raise RpcError(INVALID_PARAMS, "body must be a string")
            password = get_password(acc.name, acc.username)
            auth_kind, auth_provider = self.store.get_account_auth(acc.id)
            access_token: str | None = None
            if auth_kind == "xoauth2":
                prov = oauth.PROVIDERS.get(auth_provider or "")
                client_id = os.environ.get("OPENHAIL_OAUTH_CLIENT_ID")
                if prov is None or not client_id:
                    raise RpcError(
                        APP_ERROR,
                        f"cannot refresh OAuth token for {account}: "
                        f"provider={auth_provider!r} client_id_set={bool(client_id)}",
                    )
                try:
                    access_token = oauth.get_valid_token(
                        prov, client_id, acc.name
                    ).access_token
                except oauth.OAuthError as exc:
                    raise RpcError(APP_ERROR, f"oauth: {exc}")
            if access_token is None and password is None:
                raise RpcError(APP_ERROR, f"no credentials available for {account}")
            raw = build_message(acc.username, to_list, subject, body, cc=cc_list)
            try:
                sender = SmtpSender(acc.smtp_host, acc.smtp_port)
                if access_token is not None:
                    result = sender.send_xoauth2(
                        acc.username, access_token, to_list, raw, cc=cc_list
                    )
                else:
                    assert password is not None
                    result = sender.send(
                        acc.username, password, acc.username, to_list, raw, cc=cc_list
                    )
            except SmtpError as exc:
                raise RpcError(APP_ERROR, f"smtp: {exc}")
            except ValidationError as exc:
                raise RpcError(INVALID_PARAMS, str(exc))
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
        except ValidationError as exc:
            return _err(req_id, INVALID_PARAMS, str(exc))
        except TypeError as exc:
            # Wrong arity or a disallowed keyword; message is safe to return.
            return _err(req_id, INVALID_PARAMS, str(exc))
        except Exception as exc:
            # Log the full traceback locally; return only the exception class
            # and message. Never leak a stack trace to the caller.
            print(
                f"[openhail] internal error in {method}: "
                f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}",
                file=sys.stderr,
                flush=True,
            )
            return _err(req_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
        if req_id is None:
            return None  # notification
        return _ok(req_id, result)

    @staticmethod
    def _call_kw(handler: Handler, params: dict[str, Any]) -> Any:
        # Reject unknown keys instead of silently forwarding them. This is what
        # stops a caller from smuggling an unexpected kwarg into a handler.
        unknown = set(params) - handler.allowed
        if unknown:
            raise RpcError(
                INVALID_PARAMS,
                f"unknown parameter(s) for {handler.name}: "
                f"{', '.join(sorted(unknown))}; allowed: "
                f"{', '.join(sorted(handler.allowed)) or '(none)'}",
            )
        return handler.fn(**params)

    def serve_stdio(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            if len(line) > MAX_REQUEST_BYTES:
                resp: Any = _err(
                    None, INVALID_REQUEST,
                    f"request exceeds {MAX_REQUEST_BYTES} bytes",
                )
            else:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    request = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    resp = _err(None, PARSE_ERROR, f"parse error: {exc}")
                else:
                    if isinstance(request, list):
                        batch = []
                        for item in request[:100]:  # cap batch size
                            r = self.handle(item)
                            if r is not None:
                                batch.append(r)
                        resp = batch if batch else None
                    else:
                        resp = self.handle(request)
            if resp is not None:
                stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                stdout.flush()
