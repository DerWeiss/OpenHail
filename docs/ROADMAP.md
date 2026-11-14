# Roadmap

Ordered by what actually blocks real use, not by what's fun to build.

## M1 — working mail client for IMAP/SMTP providers ✅ (this commit)

- IMAP4rev1 over TLS: LIST, SELECT, UID SEARCH, UID FETCH, UID STORE
- MIME parse into store-ready rows (multipart, charset, addresses, dates)
- SQLite store, WAL, FTS5 search, `UNIQUE(account, folder, uid)` idempotency
- SMTP STARTTLS submission, AUTH LOGIN
- JSON-RPC 2.0 over stdio
- CLI
- 17 tests passing, zero third-party runtime deps

Covers: Fastmail, Dovecot, self-hosted, Proton Bridge, Gmail with an app password.

## M2 — OAuth2 / XOAUTH2 (the real gate) ✅

Gmail and Microsoft 365 have both killed basic auth. Without this, OpenHail could not talk
to the two largest mail providers on earth. Everything else was decoration next to it.

- Google OAuth device flow + `XOAUTH2` SASL for IMAP and SMTP
- Microsoft identity platform device code flow
- Authorization-code + PKCE flow for clients with a redirect URI
- Token refresh with rotation, persisted to the keyring alongside the refresh token
- Per-account auth kind (`plain` | `xoauth2`), chosen automatically at sync/send time
- 33 OAuth tests passing, all offline. See `docs/OAUTH.md`.

Not covered: Google Workspace domain-wide delegation (needs RS256 service-account
JWT signing).

## M2.5 — hardening ✅

Done before M3, because the repo is public and red-teamers read faster than
maintainers write.

- Every caller-supplied value validated in one module (`validate.py`)
- Envelope sender pinned to the authenticated identity
- CRLF rejected in all headers (injection)
- Request / MIME part / send size caps (DoS)
- Unknown RPC params rejected (smuggling)
- Tracebacks logged to stderr, never returned
- No credential accepted via argv
- 36 hardening + core tests

## M3 — attachments

- Content-addressed blob store (`blobs/<sha256[0:2]>/<sha256>`) so the same PDF across ten
  threads costs one copy
- Parts table linking message → blob with filename, content-type, size, disposition
- Streaming download/upload so a 40 MB attachment doesn't hit RAM twice

## M4 — threading and conversation view

- Build thread trees from `References` + `In-Reply-To`, fall back to normalized subject
- Store a `thread_id` on messages so listing a conversation is one index hit

## M5 — IDLE daemon

- Long-lived `openhail-daemon` holding one IMAP connection per account in IDLE
- Push new mail over a local unix socket / named pipe to the UI or RPC
- Reconnect with backoff; `UIDVALIDITY` change wipes and re-syncs that folder

## M6 — user interface

Two candidates, both avoiding an embedded browser:

1. **TUI** (stdlib `curses` on POSIX, `rich` optional) — fastest to ship, ugly, honest
2. **Native window** via a thin webview *for rendering only*, with the RPC core doing all
   network and storage work

The interface must never receive the account password. It talks RPC to the core.

## Explicitly not on the roadmap

- **Reimplementing the proprietary Outlook client.** Closed-source IP, and see
  `analysis/REA-FINDINGS.md` — its transport lives inside a webview, so there is nothing
  to port even if that were lawful.
- **Proprietary sync protocols** (MAPI/EMS MDB). Documented publicly enough to be
  observed, not adopted; IMAP/Graph is the interoperable path.
- **Telemetry, accounts, cloud sync.** Not negotiable.
