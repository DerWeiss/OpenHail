# The OpenHail GUI

`src/openhail/gui.py` — a desktop client in one file, standard library only
(`tkinter`, `subprocess`, `json`, `threading`, `queue`).

```
openhail-gui
openhail-gui --db C:\path\to\mail.db
```

Or, from a source checkout without installing:

```
set PYTHONPATH=src
python -m openhail.gui
```

## The one design decision that matters

**The GUI is a separate process from the server, and it never opens the
database or the keyring.**

```
   +-----------+        stdio JSON-RPC        +------------------+
   |  gui.py   | <--------------------------> |  openhail serve  |
   |  (Tk)     |   stdin / stdout, one        |  (rpc layer)     |
   +-----------+   JSON object per line       +--------+---------+
         |                                            |
   no DB access                                store + keyring
   no keyring access
```

`RpcClient` spawns `sys.executable -m openhail.cli serve` and speaks JSON-RPC
over that child's stdin and stdout. Three consequences, all deliberate:

1. **The transport stays stdio-only.** OpenHail declares stdio as its permanent
   transport contract — never a listening socket. A GUI that spoke to a TCP
   port would quietly create one. This one cannot: it is just another stdio
   peer, exactly like the CLI.
2. **The credential holder stays in one place.** The keyring and the database
   are touched by the server process only. A GUI crash or a Tk bug cannot
   corrupt the store, because the GUI has no handle to it.
3. **The GUI cannot invent RPC methods.** The server's per-method parameter
   allowlist is left in charge of validating every request. The client relays
   and reports errors; it does not second-guess or pre-validate.

## Threading model

Tk is not thread-safe — calling into it from a worker thread is a crash on
Windows, not a warning. So:

- Network and RPC work runs on daemon worker threads (via `run_async`).
- Results come back through a `queue.Queue`.
- `after(50, self._pump)` drains that queue on the Tk main thread.
- **Every widget mutation happens on the main thread.** A slow IMAP fetch
  cannot freeze the window, and a fetch that finishes cannot crash it either.

`RpcClient` itself is thread-safe: writes to the child's stdin are serialised
under a lock, and each request gets its own single-slot response queue keyed by
request id, so concurrent calls cannot deliver results to each other.

## Untrusted content

Mail subject lines and bodies are attacker-controlled. Every string that comes
back from the server is passed through `validate.strip_control()` before it
reaches a widget — the same fix shipped for the CLI in `1bb4e4d`, aimed at a
different sink. A crafted subject cannot smuggle terminal escape sequences into
a `Text` widget, a listbox, or the status bar.

`strip_control()` is display-only: the stored and transmitted bytes are
untouched, so message fidelity is preserved.

## What the compose window refuses to do

There is **no `From` field.** `mail.send` refuses any envelope sender that is
not the authenticated account identity — spoofing is blocked at both the RPC
layer and the SMTP layer. Offering a `From` box would be a control that cannot
work, so it does not exist. You pick the account; the server pins the identity.

## Stderr handling

The child's stderr goes to `DEVNULL`, deliberately not merged into stdout.
Merging the streams would interleave server log lines and tracebacks into the
JSON-RPC framing and break every request after the first stray byte.

## What's missing

- No attachments UI (the RPC layer can carry them; the window does not offer it).
- No OAuth device-code prompts — use `openhail oauth` on the CLI for first-time
  sign-in, then the GUI picks the account up.
- No offline queue; sends fail loudly rather than silently deferring.
- No HTML rendering. Body is shown as text.

## Tests

The GUI has no automated UI test — driving Tk headlessly across three operating
systems in CI is more machinery than this earns right now. What *is* verified
is the part that breaks in practice: the subprocess stdio round-trip. A headless
check constructs `RpcClient` against a temp database, calls `system.version`,
`system.methods`, `account.list` and `mail.stats` through the real child
process, and asserts the three error paths (unknown method, disallowed
parameter, timeout) each raise `RpcError` instead of hanging. No window is
created.

That check matters more than it sounds: the unit suite has twice been fully
green while the RPC wiring was broken in ways only a live round-trip catches.
