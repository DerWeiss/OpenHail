"""IMAP4rev1 client for OpenHail.

Wraps stdlib `imaplib` with TLS enforcement, explicit error types, and a
streaming fetch interface that hands raw bytes to the caller for parsing.

Design note: this module never touches the database. It yields raw messages;
the caller decides what to persist. That keeps transport and storage independently
testable.
"""

from __future__ import annotations

import imaplib
import re
import ssl
from dataclasses import dataclass
from typing import Iterator

UID_RE = re.compile(rb"UID (\d+)")
FETCH_SIZE_RE = re.compile(rb"\{(\d+)\}", re.DOTALL)


class ImapError(RuntimeError):
    """Any IMAP-level failure the caller should handle explicitly."""


@dataclass
class FetchedMessage:
    uid: int
    raw: bytes


class ImapClient:
    """A minimal, TLS-only IMAP4 client."""

    def __init__(
        self,
        host: str,
        port: int = 993,
        use_tls: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self._conn: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None

    # ---- lifecycle ------------------------------------------------------

    def connect(self) -> None:
        if self._conn is not None:
            return
        if self.use_tls:
            ctx = ssl.create_default_context()
            try:
                self._conn = imaplib.IMAP4_SSL(
                    self.host, self.port, ssl_context=ctx, timeout=self.timeout
                )
            except Exception as exc:  # pragma: no cover - network dependent
                raise ImapError(f"TLS connect to {self.host}:{self.port} failed: {exc}") from exc
        else:
            raise ImapError(
                "Refusing plaintext IMAP. Set use_tls=True or use a localhost bridge "
                "(e.g. Proton Bridge) that terminates TLS."
            )

    def login(self, username: str, password: str) -> None:
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        try:
            typ, data = self._conn.login(username, password)
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"LOGIN rejected for {username}: {exc}") from exc
        if typ != "OK":
            raise ImapError(f"LOGIN returned {typ!r}: {data!r}")

    def authenticate_xoauth2(self, username: str, access_token: str) -> None:
        """SASL XOAUTH2 auth — required by Gmail and Microsoft 365.

        Neither provider accepts LOGIN with a password any more, so this is the
        only path that works against them.
        """
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        payload = f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode()
        try:
            typ, data = self._conn.authenticate("XOAUTH2", lambda _c: payload)
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"XOAUTH2 rejected for {username}: {exc}") from exc
        if typ != "OK":
            raise ImapError(f"XOAUTH2 returned {typ!r}: {data!r}")

    def logout(self) -> None:
        if self._conn is None:
            return
        try:
            self._conn.logout()
        except Exception:
            pass
        finally:
            self._conn = None

    # ---- folders --------------------------------------------------------

    def list_folders(self) -> list[str]:
        conn = self._require()
        typ, data = conn.list()
        if typ != "OK":
            raise ImapError(f"LIST failed: {data!r}")
        names: list[str] = []
        for line in data:
            if not isinstance(line, bytes):
                continue
            # format: (\HasNoChildren) "/" "INBOX"
            parts = line.decode("utf-8", errors="replace").split(' "')
            if len(parts) >= 2:
                name = parts[-1].rstrip('"')
                names.append(name)
        return names

    def select(self, folder: str = "INBOX", readonly: bool = True) -> int:
        conn = self._require()
        # Folder names must be escaped or a name containing a quote can break
        # out of the quoted string and inject IMAP commands. Names also arrive
        # from the server via list_folders(), so they cannot be trusted.
        quoted = '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'
        typ, data = conn.select(quoted, readonly=readonly)
        if typ != "OK":
            raise ImapError(f"SELECT {folder} failed: {data!r}")
        try:
            return int(data[0])
        except (TypeError, ValueError, IndexError):
            return 0

    def uid_validity(self) -> str:
        conn = self._require()
        typ, data = conn.response("UIDVALIDITY")
        if typ != "UIDVALIDITY" or not data or data[0] is None:
            return ""
        return data[0].decode() if isinstance(data[0], bytes) else str(data[0])

    # ---- messages -------------------------------------------------------

    def search_uids(self, criteria: str = "ALL") -> list[int]:
        conn = self._require()
        typ, data = conn.uid("SEARCH", None, criteria)
        if typ != "OK":
            raise ImapError(f"UID SEARCH failed: {data!r}")
        if not data or data[0] is None:
            return []
        raw = data[0]
        if isinstance(raw, bytes):
            tokens = raw.split()
            return [int(t) for t in tokens if t.isdigit()]
        return []

    def fetch_since_uid(self, last_uid: int, limit: int = 100) -> Iterator[FetchedMessage]:
        """Fetch messages with UID > last_uid, oldest first, up to `limit`."""
        uids = [u for u in self.search_uids("ALL") if u > last_uid]
        uids.sort()
        for uid in uids[:limit]:
            yield from self.fetch_uid(uid)

    def fetch_uid(self, uid: int) -> Iterator[FetchedMessage]:
        conn = self._require()
        typ, data = conn.uid("FETCH", str(uid), "(RFC822)")
        if typ != "OK":
            raise ImapError(f"UID FETCH {uid} failed: {data!r}")
        for item in data:
            if not isinstance(item, tuple):
                continue
            meta, payload = item[0], item[1]
            if not isinstance(payload, (bytes, bytearray)):
                continue
            # Prefer the server-reported UID when present.
            found = UID_RE.search(meta if isinstance(meta, bytes) else b"")
            real_uid = int(found.group(1)) if found else uid
            yield FetchedMessage(uid=real_uid, raw=bytes(payload))

    def store_flags(self, uid: int, flags: str, mode: str = "+") -> None:
        """mode '+' adds flags, '-' removes them."""
        conn = self._require()
        typ, data = conn.uid("STORE", str(uid), f"{mode}FLAGS", f"({flags})")
        if typ != "OK":
            raise ImapError(f"UID STORE {uid} failed: {data!r}")

    def mark_seen(self, uid: int) -> None:
        self.store_flags(uid, "\\Seen", "+")

    def _require(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        if self._conn is None:
            raise ImapError("Not connected. Call connect() and login() first.")
        return self._conn

    def __enter__(self) -> "ImapClient":
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.logout()
