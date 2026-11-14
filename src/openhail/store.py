"""SQLite message store for OpenHail.

Local-first: mail lives in a single SQLite file the user owns.
FTS5 provides search. No network access happens in this module.

Hardening notes:
- A busy timeout is set so a pathological query cannot hang the process forever.
- Search queries are sanitized before reaching FTS5 (see validate.search_query).
- The LIKE fallback escapes its own wildcards so a user-supplied '%' is literal.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .validate import (
    ValidationError,
    bounded_int,
    search_query as validate_search_query,
)

SCHEMA_VERSION = 1

# Seconds SQLite will wait on a locked database before erroring.
BUSY_TIMEOUT_S = 5.0

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL UNIQUE,
    imap_host TEXT NOT NULL,
    imap_port INTEGER NOT NULL DEFAULT 993,
    smtp_host TEXT NOT NULL,
    smtp_port INTEGER NOT NULL DEFAULT 587,
    username TEXT NOT NULL,
    use_tls  INTEGER NOT NULL DEFAULT 1,
    created  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS folders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    uid_validity TEXT,
    last_uid   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(account_id, name)
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    folder_id   INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid         INTEGER,
    message_id  TEXT,
    in_reply_to TEXT,
    references_ TEXT,
    subject     TEXT,
    from_addr   TEXT,
    to_addr     TEXT,
    cc_addr     TEXT,
    date_utc    TEXT,
    body_text   TEXT,
    body_html   TEXT,
    flags       TEXT NOT NULL DEFAULT '',
    size        INTEGER NOT NULL DEFAULT 0,
    raw_sha256  TEXT,
    created     TEXT NOT NULL,
    UNIQUE(account_id, folder_id, uid)
);

CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date_utc DESC);
CREATE INDEX IF NOT EXISTS idx_messages_folder ON messages(folder_id, uid);
CREATE INDEX IF NOT EXISTS idx_messages_msgid ON messages(message_id);

CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    subject, body_text, from_addr, to_addr,
    content='messages', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, subject, body_text, from_addr, to_addr)
    VALUES (new.id, new.subject, new.body_text, new.from_addr, new.to_addr);
END;

CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, subject, body_text, from_addr, to_addr)
    VALUES ('delete', old.id, old.subject, old.body_text, old.from_addr, old.to_addr);
END;

CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, subject, body_text, from_addr, to_addr)
    VALUES ('delete', old.id, old.subject, old.body_text, old.from_addr, old.to_addr);
    INSERT INTO messages_fts(rowid, subject, body_text, from_addr, to_addr)
    VALUES (new.id, new.subject, new.body_text, new.from_addr, new.to_addr);
END;
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Account:
    id: int
    name: str
    imap_host: str
    imap_port: int
    smtp_host: str
    smtp_port: int
    username: str
    use_tls: bool

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("password", None)  # never serialize secrets
        return d


@dataclass
class Message:
    id: int
    account_id: int
    folder_id: int
    uid: int | None
    message_id: str | None
    subject: str | None
    from_addr: str | None
    to_addr: str | None
    date_utc: str | None
    body_text: str | None
    flags: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _escape_like(value: str) -> str:
    """Escape LIKE wildcards so user input is matched literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class Store:
    """A SQLite-backed mail store. One file, no server, no daemon."""

    def __init__(self, path: str | os.PathLike[str] = "mail.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=BUSY_TIMEOUT_S)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        cur = self.conn.execute("SELECT value FROM meta WHERE key='schema_version'")
        row = cur.fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        self.conn.commit()

    # ---- accounts -------------------------------------------------------

    def add_account(
        self,
        name: str,
        imap_host: str,
        smtp_host: str,
        username: str,
        imap_port: int = 993,
        smtp_port: int = 587,
        use_tls: bool = True,
    ) -> Account:
        self.conn.execute(
            """INSERT INTO accounts
               (name, imap_host, imap_port, smtp_host, smtp_port, username, use_tls, created)
               VALUES (?,?,?,?,?,?,?,?)""",
            (name, imap_host, imap_port, smtp_host, smtp_port, username, int(use_tls), _now()),
        )
        self.conn.commit()
        acc = self.get_account(name)
        assert acc is not None
        return acc

    def get_account(self, name: str) -> Account | None:
        cur = self.conn.execute("SELECT * FROM accounts WHERE name=?", (name,))
        row = cur.fetchone()
        return self._row_to_account(row) if row else None

    def list_accounts(self) -> list[Account]:
        cur = self.conn.execute("SELECT * FROM accounts ORDER BY name")
        return [self._row_to_account(r) for r in cur.fetchall()]

    @staticmethod
    def _row_to_account(row: sqlite3.Row) -> Account:
        return Account(
            id=row["id"],
            name=row["name"],
            imap_host=row["imap_host"],
            imap_port=row["imap_port"],
            smtp_host=row["smtp_host"],
            smtp_port=row["smtp_port"],
            username=row["username"],
            use_tls=bool(row["use_tls"]),
        )

    # ---- folders --------------------------------------------------------

    def ensure_folder(self, account_id: int, name: str) -> int:
        cur = self.conn.execute(
            "SELECT id FROM folders WHERE account_id=? AND name=?", (account_id, name)
        )
        row = cur.fetchone()
        if row:
            return int(row["id"])
        cur = self.conn.execute(
            "INSERT INTO folders (account_id, name) VALUES (?,?)", (account_id, name)
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def set_uidvalidity(self, folder_id: int, uid_validity: str) -> None:
        self.conn.execute(
            "UPDATE folders SET uid_validity=? WHERE id=?", (str(uid_validity), folder_id)
        )
        self.conn.commit()

    def get_last_uid(self, folder_id: int) -> int:
        cur = self.conn.execute("SELECT last_uid FROM folders WHERE id=?", (folder_id,))
        row = cur.fetchone()
        return int(row["last_uid"]) if row else 0

    def set_last_uid(self, folder_id: int, uid: int) -> None:
        self.conn.execute("UPDATE folders SET last_uid=? WHERE id=?", (uid, folder_id))
        self.conn.commit()

    # ---- messages -------------------------------------------------------

    def insert_message(self, msg: dict[str, Any]) -> int | None:
        """Insert one message. Returns row id, or None if it already exists."""
        cols = (
            "account_id", "folder_id", "uid", "message_id", "in_reply_to",
            "references_", "subject", "from_addr", "to_addr", "cc_addr",
            "date_utc", "body_text", "body_html", "flags", "size", "raw_sha256",
        )
        values = tuple(msg.get(c) for c in cols) + (_now(),)
        try:
            cur = self.conn.execute(
                f"INSERT INTO messages ({','.join(cols)}, created) "
                f"VALUES ({','.join('?' * (len(cols) + 1))})",
                values,
            )
            self.conn.commit()
            return int(cur.lastrowid)
        except sqlite3.IntegrityError:
            # duplicate (account, folder, uid) — expected on re-sync
            return None

    def list_messages(
        self, account_id: int, limit: int = 20, folder: str | None = None
    ) -> list[Message]:
        limit = bounded_int(limit, 20, 1000, "limit")
        sql = (
            "SELECT m.* FROM messages m JOIN folders f ON f.id = m.folder_id "
            "WHERE m.account_id=? "
        )
        params: list[Any] = [account_id]
        if folder:
            sql += "AND f.name=? "
            params.append(folder)
        sql += "ORDER BY m.date_utc DESC, m.id DESC LIMIT ?"
        params.append(limit)
        cur = self.conn.execute(sql, params)
        return [self._row_to_message(r) for r in cur.fetchall()]

    def get_message(self, row_id: int) -> Message | None:
        cur = self.conn.execute("SELECT * FROM messages WHERE id=?", (row_id,))
        row = cur.fetchone()
        return self._row_to_message(row) if row else None

    def search(self, account_id: int, query: str, limit: int = 20) -> list[Message]:
        """FTS5 search. Query is sanitized and passed as a bound parameter."""
        query = validate_search_query(query)
        limit = bounded_int(limit, 20, 1000, "limit")
        sql = (
            "SELECT m.* FROM messages_fts fts "
            "JOIN messages m ON m.id = fts.rowid "
            "WHERE messages_fts MATCH ? AND m.account_id=? "
            "ORDER BY m.date_utc DESC LIMIT ?"
        )
        try:
            cur = self.conn.execute(sql, (query, account_id, limit))
            return [self._row_to_message(r) for r in cur.fetchall()]
        except sqlite3.OperationalError:
            # malformed FTS query — fall back to LIKE with escaped wildcards
            like = f"%{_escape_like(query)}%"
            cur = self.conn.execute(
                "SELECT * FROM messages WHERE account_id=? AND "
                "(subject LIKE ? ESCAPE '\\' OR body_text LIKE ? ESCAPE '\\') "
                "ORDER BY date_utc DESC LIMIT ?",
                (account_id, like, like, limit),
            )
            return [self._row_to_message(r) for r in cur.fetchall()]

    def count_messages(self, account_id: int | None = None) -> int:
        if account_id is None:
            cur = self.conn.execute("SELECT COUNT(*) AS n FROM messages")
        else:
            cur = self.conn.execute(
                "SELECT COUNT(*) AS n FROM messages WHERE account_id=?", (account_id,)
            )
        return int(cur.fetchone()["n"])

    @staticmethod
    def _row_to_message(row: sqlite3.Row) -> Message:
        return Message(
            id=row["id"],
            account_id=row["account_id"],
            folder_id=row["folder_id"],
            uid=row["uid"],
            message_id=row["message_id"],
            subject=row["subject"],
            from_addr=row["from_addr"],
            to_addr=row["to_addr"],
            date_utc=row["date_utc"],
            body_text=row["body_text"],
            flags=row["flags"] or "",
            size=row["size"] or 0,
        )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
