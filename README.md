# OpenHail

**An open-source mail client. Local-first. IMAP/SMTP over any provider. No telemetry.**

OpenHail exists because the desktop mail client market collapsed into two options: a
webview wrapper that phones home, or a terminal tool that expects you to live in `mutt`.

OpenHail is neither. It is a small, auditable core that speaks **IMAP4rev1** and **SMTP**
directly, stores mail in **SQLite** on your disk, and exposes a plain **JSON-RPC** surface
so a UI (or an AI agent) can drive it without embedding a browser engine.

## Status

**Pre-alpha.** The IMAP client, MIME parser, SQLite store, and SMTP sender are implemented
and tested. No GUI yet.

| Component | State |
|---|---|
| IMAP4rev1 client (TLS, LOGIN, SELECT, FETCH, STORE) | working |
| MIME / RFC 5322 parser | working |
| SQLite message store + full-text search | working |
| SMTP submission (STARTTLS, AUTH LOGIN) | working |
| JSON-RPC control surface | working |
| CLI | working |
| GUI | not started |
| OAuth2 / XOAUTH2 | not started |
| JMAP / Graph-native | not started |

## Why not just use IMAP everywhere?

Because Exchange and Outlook.com de-emphasize IMAP, and Microsoft is retiring basic auth.
OpenHail's roadmap is IMAP/SMTP first (works with Fastmail, Proton Bridge, Gmail app
passwords, Dovecot, self-hosted), then XOAUTH2, then provider-native APIs.

The `analysis/` directory contains reverse-engineering notes about how the *new Outlook*
client is built, used **only** to understand which protocols an interoperable client must
speak. See `analysis/REA-FINDINGS.md`. No Microsoft code is copied or redistributed.

## Design principles

1. **Local-first.** Mail lives in a SQLite file you own. No cloud sync, no account required.
2. **No telemetry.** The binary makes network connections only to the servers you configure.
3. **Auditable core.** Small dependency surface. Standard library where possible.
4. **Agent-friendly.** JSON-RPC over stdio, plus a stable schema, so an LLM can read and
   send mail without browser automation.
5. **No credential theatre.** Passwords go to the OS keyring, never to a config file.

## Install

From source:

```
git clone https://github.com/<you>/openhail.git
cd openhail
python -m venv .venv
.venv\Scripts\activate      # Windows
# or: source .venv/bin/activate
pip install -e .
```

Requires **Python 3.11+**. No third-party runtime dependencies — everything is stdlib
(`imaplib`, `smtplib`, `email`, `sqlite3`, `ssl`, `json`). `keyring` is optional and only
used for password storage.

## Usage

```
openhail account add --name fastmail --imap imap.fastmail.com:993 \
    --smtp smtp.fastmail.com:587 --user you@fastmail.com
openhail sync --account fastmail
openhail list --account fastmail --limit 20
openhail read 1
openhail send --account fastmail --to someone@example.com \
    --subject "hello" --body "from openhail"
openhail search --account fastmail --query "invoice"
```

JSON-RPC mode — one JSON object per line over stdio:

```
echo '{"jsonrpc":"2.0","id":1,"method":"system.version"}' | openhail serve
```

## Tests

```
pip install pytest
python -m pytest tests -q
```

17 tests, no network required.

## Architecture

```
                 +-------------------+
   JSON-RPC ---> |      server       |  stdio
   CLI      ---> |   (rpc layer)     |
                 +---------+---------+
                           |
           +---------------+---------------+
           |               |               |
      +----v----+     +----v----+     +----v----+
      |  imap   |     |   smtp  |     |  store  |
      | client  |     | sender  |     | sqlite  |
      +---------+     +---------+     +---------+
           |               |               |
        TLS/993         TLS/587        mail.db
```

Each layer is replaceable. The store has no knowledge of IMAP; the IMAP client streams
into it as parsed messages. The RPC layer is a thin serializer over store + transport.

## Security posture

| Concern | Decision |
|---|---|
| Plaintext IMAP | Refused at connect time |
| Plaintext SMTP auth | Refused; STARTTLS required |
| Credential storage | OS keyring or `OPENHAIL_PASSWORD` env; never in `mail.db` |
| SQL injection | Every query parameterized |
| HTML rendering | Not implemented; `body_html` stored, never rendered in-process |
| Telemetry | None |

## Roadmap

See `docs/ROADMAP.md`. Short version: **OAuth2/XOAUTH2 is the gate** — Gmail and
Microsoft 365 killed basic auth, so without it OpenHail can't talk to the two biggest
providers on earth.

## License

MIT. See `LICENSE`.

## Contributing

Read `analysis/REA-FINDINGS.md` for the interop context, then `docs/ARCHITECTURE.md`.
We are not accepting code derived from decompiled proprietary software. Findings about
protocols and file formats are welcome; copied implementation is not.
