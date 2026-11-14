"""OpenHail desktop GUI - a thin, stdlib-only Tk client over the JSON-RPC server.

Design contract
---------------
This module is a *thin client*. It does not import ``openhail.store``, never opens
the SQLite database itself, and never reads the keyring. All mail access goes
through a child process (``python -m openhail.cli serve``) speaking
line-delimited JSON-RPC 2.0 over that child's stdin/stdout.

That preserves OpenHail's permanent transport contract: stdio only, never a
listening socket. The GUI is therefore just another stdio peer, exactly like the
CLI.

Threat notes
------------
Mail content is attacker-controlled. Every string that comes back from the
server is passed through :func:`openhail.validate.strip_control` before it
reaches a Tk widget, so a crafted subject cannot smuggle terminal/ANSI escape
sequences into anything that later prints it. The RPC layer's own per-method
parameter allowlist is left in charge of validating requests - this module
relays, it does not second-guess.

Standard library only: no third-party packages, so ``pip install openhail``
never pulls a GUI dependency tree onto a machine that holds mail credentials.
"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Callable

from . import validate

__all__ = ["RpcClient", "RpcError", "App", "main"]

# Timeouts (seconds). Sync talks to a real IMAP server over the network and is
# allowed to be slow; everything else is local SQLite and has no excuse.
TIMEOUT_SYNC = 60.0
TIMEOUT_DEFAULT = 15.0


# --------------------------------------------------------------------------
# JSON-RPC client
# --------------------------------------------------------------------------


class RpcError(Exception):
    """A JSON-RPC level failure, either transport or server-reported."""


class RpcClient:
    """Line-delimited JSON-RPC 2.0 client over a child process's stdio.

    Thread-safety: :meth:`call` may be invoked from any thread. Writes are
    serialised by an internal lock and each request gets its own response queue,
    so concurrent calls cannot mis-deliver results to each other.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else None
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._pending: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._next_id = 0
        self._reader: threading.Thread | None = None
        self._closed = False

    # -- process lifecycle -------------------------------------------------

    def _cmd(self) -> list[str]:
        cmd = [sys.executable, "-m", "openhail.cli"]
        if self.db_path is not None:
            cmd += ["--db", str(self.db_path.absolute())]
        cmd.append("serve")
        return cmd

    def start(self) -> None:
        if self._proc is not None:
            return
        # stderr goes to DEVNULL, NOT to stdout. Merging the two streams would
        # interleave server log noise and tracebacks into the JSON-RPC framing
        # and break every request after the first stray byte.
        self._proc = subprocess.Popen(
            self._cmd(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._reader = threading.Thread(
            target=self._read_loop, name="openhail-rpc-reader", daemon=True
        )
        self._reader.start()

    def _read_loop(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        while True:
            line = proc.stdout.readline()
            if not line:
                break  # EOF: child exited or closed its stdout
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                # One malformed line must not kill the GUI's only reader.
                continue
            if not isinstance(msg, dict):
                continue
            req_id = msg.get("id")
            if req_id is None:
                continue  # server notification; nothing to route
            with self._lock:
                slot = self._pending.pop(req_id, None)
            if slot is not None:
                slot.put(msg)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except OSError:
                pass
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except (ProcessLookupError, OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass

    def __enter__(self) -> "RpcClient":
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # -- requests ----------------------------------------------------------

    def call(self, method: str, timeout: float = TIMEOUT_DEFAULT, **params: Any) -> Any:
        """Send one request and block until its response arrives."""
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise RpcError("RPC client is not started")

        slot: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        with self._lock:
            self._next_id += 1
            req_id = self._next_id
            self._pending[req_id] = slot

        payload = json.dumps(
            {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
            ensure_ascii=False,
        )
        try:
            with self._lock:
                proc.stdin.write(payload + "\n")
                proc.stdin.flush()
        except (OSError, ValueError) as exc:
            with self._lock:
                self._pending.pop(req_id, None)
            raise RpcError(f"could not send {method}: {exc}") from exc

        try:
            response = slot.get(timeout=timeout)
        except queue.Empty:
            with self._lock:
                self._pending.pop(req_id, None)
            raise RpcError(f"{method} timed out after {timeout:g}s") from None

        error = response.get("error")
        if error is not None:
            if isinstance(error, dict):
                detail = error.get("message") or json.dumps(error, ensure_ascii=False)
            else:
                detail = str(error)
            raise RpcError(f"{method}: {detail}")
        return response.get("result")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def safe(value: Any) -> str:
    """Render a server-supplied value for display with escapes stripped."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return validate.strip_control(value)


def _short(text: str, limit: int = 80) -> str:
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 1] + "\u2026"
    return text


def _fmt_size(num: Any) -> str:
    try:
        size = int(num)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} GB"


# --------------------------------------------------------------------------
# application window
# --------------------------------------------------------------------------


class App(tk.Tk):
    """Three-pane mail client: accounts/folders, message list, message body."""

    def __init__(self, client: RpcClient) -> None:
        super().__init__()
        self.client = client
        self.title("OpenHail")
        self.geometry("1100x680")
        self.minsize(820, 480)

        # Queue of (callable, args) to run on the Tk main thread.
        self._ui_queue: queue.Queue[tuple[Callable[..., Any], tuple[Any, ...]]] = queue.Queue()
        self._busy = 0

        self._folders: list[str] = []
        self._messages: list[dict[str, Any]] = []
        self._current_folder: str | None = None
        self._current_uid: Any = None

        self._build_toolbar()
        self._build_body()
        self._build_status()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(50, self._pump)
        self.after(120, self.refresh_accounts)

    # -- layout ------------------------------------------------------------

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(6, 6, 6, 3))
        bar.pack(side=tk.TOP, fill=tk.X)

        self.btn_sync = ttk.Button(bar, text="Sync", command=self.on_sync)
        self.btn_sync.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(bar, text="Search", command=self.on_search).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="New", command=self.on_compose).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Reply", command=self.on_reply).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Refresh", command=self.on_refresh).pack(side=tk.LEFT, padx=4)

        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)
        ttk.Label(bar, text="Find:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.search_var, width=32)
        entry.pack(side=tk.LEFT, padx=4)
        entry.bind("<Return>", lambda _e: self.on_search())

    def _build_body(self) -> None:
        outer = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        outer.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=3)

        # left: accounts + folders
        left = ttk.Frame(outer)
        outer.add(left, weight=1)

        ttk.Label(left, text="Accounts").pack(anchor="w", padx=4, pady=(2, 0))
        self.account_box = tk.Listbox(left, height=6, exportselection=False)
        self.account_box.pack(fill=tk.X, padx=4, pady=(2, 6))

        ttk.Label(left, text="Folders").pack(anchor="w", padx=4)
        self.folder_box = tk.Listbox(left, exportselection=False)
        self.folder_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=(2, 4))
        self.folder_box.bind("<<ListboxSelect>>", self._on_folder_select)

        # middle: message list
        middle = ttk.Frame(outer)
        outer.add(middle, weight=2)
        cols = ("from", "subject", "date")
        self.tree = ttk.Treeview(middle, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("from", text="From")
        self.tree.heading("subject", text="Subject")
        self.tree.heading("date", text="Date")
        self.tree.column("from", width=180, stretch=False)
        self.tree.column("subject", width=280)
        self.tree.column("date", width=130, stretch=False, anchor="e")
        scroll = ttk.Scrollbar(middle, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self._on_message_select)

        # right: headers + body
        right = ttk.Frame(outer)
        outer.add(right, weight=3)

        self.headers = tk.Text(right, height=6, wrap=tk.WORD, state=tk.DISABLED,
                               background="#f7f7f7")
        self.headers.pack(fill=tk.X, padx=2, pady=(0, 3))

        self.body = tk.Text(right, wrap=tk.WORD, state=tk.DISABLED)
        body_scroll = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.body.yview)
        self.body.configure(yscrollcommand=body_scroll.set)
        self.body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        body_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_status(self) -> None:
        self.status_var = tk.StringVar(value="starting\u2026")
        ttk.Label(self, textvariable=self.status_var, anchor="w",
                  relief=tk.SUNKEN).pack(side=tk.BOTTOM, fill=tk.X)

    # -- threading glue ----------------------------------------------------

    def run_async(self, fn: Callable[[], Any],
                  on_done: Callable[[Any], None] | None = None,
                  on_error: Callable[[Exception], None] | None = None) -> None:
        """Run ``fn`` on a worker thread; deliver results on the Tk thread."""
        self._busy += 1
        self._set_status("working\u2026")

        def worker() -> None:
            try:
                result = fn()
            except Exception as exc:  # noqa: BLE001 - reported to the UI below
                self._ui_queue.put((self._finish_error, (exc, on_error)))
            else:
                self._ui_queue.put((self._finish_ok, (result, on_done)))

        threading.Thread(target=worker, name="openhail-worker", daemon=True).start()

    def _finish_ok(self, result: Any, on_done: Callable[[Any], None] | None) -> None:
        self._busy = max(0, self._busy - 1)
        if self._busy == 0:
            self._set_status("ready")
        if on_done is not None:
            try:
                on_done(result)
            except Exception as exc:  # noqa: BLE001
                self._report(exc)

    def _finish_error(self, exc: Exception,
                      on_error: Callable[[Exception], None] | None) -> None:
        self._busy = max(0, self._busy - 1)
        if self._busy == 0:
            self._set_status("ready")
        if on_error is not None:
            on_error(exc)
        else:
            self._report(exc)

    def _pump(self) -> None:
        """Drain UI callbacks on the Tk thread. Never block here."""
        while True:
            try:
                fn, args = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn(*args)
            except Exception as exc:  # noqa: BLE001 - a bad callback must not stop the pump
                self._report(exc)
        self.after(50, self._pump)

    def _report(self, exc: Exception) -> None:
        self._set_status(f"error: {safe(exc)}")
        messagebox.showerror("OpenHail", safe(exc))

    def _set_status(self, text: str) -> None:
        self.status_var.set(safe(text))

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", safe(text))
        widget.configure(state=tk.DISABLED)

    # -- data loading ------------------------------------------------------

    def refresh_accounts(self) -> None:
        self.run_async(
            lambda: self.client.call("account.list"),
            on_done=self._show_accounts,
        )
        self.refresh_folders()

    def _show_accounts(self, accounts: Any) -> None:
        self.account_box.delete(0, tk.END)
        if not isinstance(accounts, list):
            return
        for acct in accounts:
            if not isinstance(acct, dict):
                continue
            name = safe(acct.get("name") or acct.get("email") or "?")
            kind = safe(acct.get("auth_kind") or "")
            label = name + (f"  [{kind}]" if kind else "")
            self.account_box.insert(tk.END, label)
        if self.account_box.size() == 0:
            self._set_status("no accounts configured - use 'openhail account add'")

    def refresh_folders(self) -> None:
        self.run_async(
            lambda: self.client.call("folder.list"),
            on_done=self._show_folders,
            on_error=lambda exc: self._set_status(f"folders unavailable: {safe(exc)}"),
        )

    def _show_folders(self, folders: Any) -> None:
        self.folder_box.delete(0, tk.END)
        self._folders = []
        names: list[str] = []
        if isinstance(folders, list):
            for item in folders:
                if isinstance(item, dict):
                    name = item.get("name")
                else:
                    name = item
                if isinstance(name, str) and name:
                    names.append(name)
        elif isinstance(folders, dict):
            for key in ("folders", "names"):
                val = folders.get(key)
                if isinstance(val, list):
                    names = [v for v in val if isinstance(v, str)]
                    break
        for name in names:
            self._folders.append(name)
            self.folder_box.insert(tk.END, safe(name))
        if self._folders and self._current_folder is None:
            self.folder_box.selection_set(0)
            self._select_folder(self._folders[0])

    def _on_folder_select(self, _event: Any = None) -> None:
        sel = self.folder_box.curselection()
        if not sel:
            return
        idx = int(sel[0])
        if idx < len(self._folders):
            self._select_folder(self._folders[idx])

    def _select_folder(self, folder: str) -> None:
        self._current_folder = folder
        self._current_uid = None
        self._set_text(self.headers, "")
        self._set_text(self.body, "")
        self.load_messages(folder)

    def load_messages(self, folder: str) -> None:
        def work() -> Any:
            return self.client.call("mail.list", folder=folder, limit=200)

        self.run_async(work, on_done=self._show_messages)

    def _show_messages(self, result: Any) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._messages = []
        rows = result if isinstance(result, list) else (
            result.get("messages") if isinstance(result, dict) else None
        )
        if not isinstance(rows, list):
            return
        for msg in rows:
            if not isinstance(msg, dict):
                continue
            self._messages.append(msg)
            self.tree.insert(
                "", tk.END,
                values=(
                    safe(msg.get("from_addr") or msg.get("from") or ""),
                    safe(_short(str(msg.get("subject") or "(no subject)"))),
                    safe(msg.get("date") or msg.get("internal_date") or ""),
                ),
            )
        self._set_status(f"{len(self._messages)} message(s) in {safe(self._current_folder or '')}")

    def _on_message_select(self, _event: Any = None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx >= len(self._messages):
            return
        uid = self._messages[idx].get("uid") or self._messages[idx].get("id")
        if uid is None:
            return
        self._current_uid = uid
        folder = self._current_folder
        if folder is None:
            return

        def work() -> Any:
            return self.client.call("mail.read", folder=folder, uid=uid)

        self.run_async(work, on_done=self._show_message)

    def _show_message(self, msg: Any) -> None:
        if not isinstance(msg, dict):
            return
        header_lines = []
        for label, keys in (
            ("From", ("from_addr", "from")),
            ("To", ("to_addr", "to")),
            ("Cc", ("cc_addr", "cc")),
            ("Subject", ("subject",)),
            ("Date", ("date", "internal_date")),
        ):
            for key in keys:
                val = msg.get(key)
                if val:
                    header_lines.append(f"{label}: {safe(val)}")
                    break
        self._set_text(self.headers, "\n".join(header_lines))
        body = msg.get("body") or msg.get("text") or msg.get("snippet") or ""
        self._set_text(self.body, str(body))

    # -- actions -----------------------------------------------------------

    def on_sync(self) -> None:
        self.run_async(
            lambda: self.client.call("mail.sync", timeout=TIMEOUT_SYNC),
            on_done=lambda _r: (self._set_status("sync complete"), self.refresh_folders()),
        )

    def on_refresh(self) -> None:
        self.refresh_accounts()
        if self._current_folder:
            self.load_messages(self._current_folder)

    def on_search(self) -> None:
        query = self.search_var.get().strip()
        if not query:
            self._set_status("enter something to search for")
            return

        def work() -> Any:
            return self.client.call("mail.search", query=query, limit=200)

        self.run_async(work, on_done=self._show_messages)

    def on_compose(self) -> None:
        ComposeWindow(self, self.client, reply_to=None)

    def on_reply(self) -> None:
        if self._current_uid is None or self._current_folder is None:
            self._set_status("select a message first")
            return
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx >= len(self._messages):
            return
        ComposeWindow(self, self.client, reply_to=self._messages[idx])

    def _on_close(self) -> None:
        try:
            self.client.close()
        finally:
            self.destroy()


# --------------------------------------------------------------------------
# compose window
# --------------------------------------------------------------------------


class ComposeWindow(tk.Toplevel):
    """Compose/send dialog. Deliberately has no From field.

    ``mail.send`` refuses any envelope sender that is not the authenticated
    account identity, so offering a From field would be a control that cannot
    work. The account is chosen from configured accounts instead.
    """

    def __init__(self, master: App, client: RpcClient,
                 reply_to: dict[str, Any] | None = None) -> None:
        super().__init__(master)
        self.client = client
        self.app = master
        self.reply_to = reply_to
        self.title("Reply" if reply_to else "New Message")
        self.geometry("640x520")

        form = ttk.Frame(self, padding=8)
        form.pack(fill=tk.BOTH, expand=True)

        self.account_var = tk.StringVar()
        ttk.Label(form, text="Account").grid(row=0, column=0, sticky="w")
        self.account_combo = ttk.Combobox(form, textvariable=self.account_var,
                                          state="readonly")
        self.account_combo.grid(row=0, column=1, sticky="ew", pady=2)
        accounts = list(master.account_box.get(0, tk.END))
        self.account_combo["values"] = accounts
        if accounts:
            self.account_combo.current(0)

        self.to_var = tk.StringVar()
        ttk.Label(form, text="To").grid(row=1, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.to_var).grid(row=1, column=1, sticky="ew", pady=2)

        self.cc_var = tk.StringVar()
        ttk.Label(form, text="Cc").grid(row=2, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.cc_var).grid(row=2, column=1, sticky="ew", pady=2)

        self.subject_var = tk.StringVar()
        ttk.Label(form, text="Subject").grid(row=3, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.subject_var).grid(row=3, column=1, sticky="ew", pady=2)

        form.columnconfigure(1, weight=1)
        self.text = tk.Text(form, wrap=tk.WORD)
        self.text.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=(6, 6))
        form.rowconfigure(4, weight=1)

        buttons = ttk.Frame(form)
        buttons.grid(row=5, column=0, columnspan=2, sticky="e")
        self.send_btn = ttk.Button(buttons, text="Send", command=self.on_send)
        self.send_btn.pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side=tk.RIGHT)

        if reply_to:
            sender = reply_to.get("from_addr") or reply_to.get("from") or ""
            self.to_var.set(safe(sender))
            subj = str(reply_to.get("subject") or "")
            if subj and not subj.lower().startswith("re:"):
                subj = "Re: " + subj
            self.subject_var.set(safe(subj))

    def on_send(self) -> None:
        to_addr = self.to_var.get().strip()
        subject = self.subject_var.get().strip()
        body = self.text.get("1.0", tk.END).rstrip("\n")
        cc_raw = self.cc_var.get().strip()

        if not to_addr:
            messagebox.showerror("OpenHail", "A recipient is required.", parent=self)
            return
        if not subject and not body:
            messagebox.showerror("OpenHail", "Nothing to send.", parent=self)
            return

        cc = [part.strip() for part in cc_raw.replace(";", ",").split(",")
              if part.strip()]
        params: dict[str, Any] = {"to": to_addr, "subject": subject, "body": body}
        if cc:
            params["cc"] = cc

        self.send_btn.configure(state=tk.DISABLED)
        self.app._set_status("sending\u2026")

        def work() -> Any:
            return self.client.call("mail.send", timeout=TIMEOUT_SYNC, **params)

        def done(_result: Any) -> None:
            self.app._set_status("sent")
            self.destroy()

        def failed(exc: Exception) -> None:
            self.send_btn.configure(state=tk.NORMAL)
            self.app._set_status(f"send failed: {safe(exc)}")
            messagebox.showerror("OpenHail", safe(exc), parent=self)

        self.app.run_async(work, on_done=done, on_error=failed)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Console entry point: ``openhail-gui [--db PATH]``."""
    args = list(sys.argv[1:] if argv is None else argv)
    db_path: str | None = None
    while args:
        arg = args.pop(0)
        if arg in ("-h", "--help"):
            print("usage: openhail-gui [--db PATH]")
            return 0
        if arg == "--db":
            if not args:
                print("--db requires a path", file=sys.stderr)
                return 2
            db_path = args.pop(0)
        else:
            print(f"unknown argument: {arg}", file=sys.stderr)
            return 2

    client = RpcClient(db_path)
    try:
        client.start()
    except OSError as exc:
        print(f"could not start the OpenHail server: {exc}", file=sys.stderr)
        return 1

    try:
        app = App(client)
        app.mainloop()
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
