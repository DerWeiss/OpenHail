# Architecture

## Layers

```
                 +---------------------------+
   JSON-RPC ---> |  server.py (dispatch)     |  stdio, one JSON object per line
   CLI      ---> |  cli.py                   |
                 +-------------+-------------+
                               |
        +----------------------+----------------------+
        |                      |                      |
   +----v----+            +----v----+            +----v----+
   | imap.py |            | smtp.py |            |store.py |
   | client  |            | sender  |            | sqlite  |
   +----+----+            +---------+            +----+----+
        |                                             |
    TLS 993                                    mail.db (WAL, FTS5)
        |
   mime.py  <- parses raw bytes into store rows
```

## Why the layers are split this way

**Transport knows nothing about storage.** `ImapClient.fetch_uid()` yields raw `bytes`.
`parse_message()` turns bytes into a dict. `Store.insert_message()` persists the dict.
Any of the three can be tested alone, and any can be replaced:

- swap `store.py` for a different backend (Postgres, a filesystem maildir) without
  touching IMAP
- swap `imap.py` for JMAP or a Graph API client without touching the store
- swap `server.py` for a GUI's native bindings without touching either

**No third-party runtime dependencies.** `imaplib`, `smtplib`, `email`, `sqlite3`, `ssl`,
`json`, `hashlib` — all stdlib. That is a deliberate constraint: a mail client holds the
user's credentials and reads all their correspondence. Every dependency would be a
supply-chain risk on that surface. The one exception is `keyring` (optional), and if it is
absent we refuse to store secrets rather than degrade to plaintext.

## Security posture

| Concern | Decision |
|---|---|
| Plaintext IMAP | Refused at connect time. `use_tls=False` raises. |
| Plaintext SMTP auth | Refused. Sender checks `STARTTLS` in EHLO before login. |
| Credential storage | OS keyring, or `OPENHAIL_PASSWORD` env for one session. Never in `mail.db`. |
| SQL injection | Every query parameterized. FTS query passed as a bound parameter. |
| HTML rendering | Not implemented. `body_html` is stored, never rendered in-process. A future UI must sandbox it. |
| Telemetry | None. The only sockets opened are to configured mail servers. |

## Data model

```sql
accounts(id, name UNIQUE, imap_host, imap_port, smtp_host, smtp_port, username, use_tls, created)
folders(id, account_id, name, uid_validity, last_uid)   -- UNIQUE(account_id, name)
messages(id, account_id, folder_id, uid, message_id, ..., raw_sha256)
       -- UNIQUE(account_id, folder_id, uid)  <- this is the idempotency key
messages_fts USING fts5(subject, body_text, from_addr, to_addr)  -- external content
```

`UNIQUE(account_id, folder_id, uid)` is the whole sync-safety story: re-running `sync`
inserts nothing twice, and `insert_message` returns `None` on the duplicate instead of
raising. `last_uid` on `folders` means each sync only walks new messages.

## IDLE / push

Not implemented. Current sync is polling (`mail.sync` on demand). The IMAP `IDLE` command
requires a persistent connection and a notification path into the UI; it belongs in a
long-lived process, not the request/response RPC server. Planned as a separate
`openhail-daemon`.

## What is deliberately missing

- **OAuth2 / XOAUTH2.** Gmail and Microsoft 365 now require it. This is the #1 blocker
  for real-world use and is the next milestone.
- **Attachments.** Parsed out and discarded today. Storing blobs needs a content-addressed
  blob store so dedupe works across accounts.
- **Threading.** `In-Reply-To` and `References` are stored but not assembled into threads.
- **Message body rendering / UI.** By design, out of scope for the core.

## Interop note

`analysis/REA-FINDINGS.md` documents what a proprietary client on this machine actually
does at the binary level. The relevant conclusion for architecture: that client is a
process supervisor over a webview, so its network stack is not reusable and not
observable through native imports. OpenHail goes the other way — protocol-first, no
embedded browser, no supervisor process tree.
