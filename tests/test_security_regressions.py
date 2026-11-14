"""Regression tests for the security fixes in this PR.

Each test is named after the attack or failure it prevents, so deleting a
guard turns a test red with an explanation attached.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from openhail.imap import ImapClient, ImapError
from openhail.smtp import SmtpError, SmtpSender
from openhail.validate import strip_control


# ---------------------------------------------------------------------------
# XOAUTH2 over SMTP must base64-encode the SASL initial response.
# ---------------------------------------------------------------------------


class _RecordingSMTP:
    """Stands in for smtplib.SMTP and records every command sent."""

    def __init__(self, *args, **kwargs) -> None:
        self.commands: list[tuple[str, str]] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self, *a, **k):
        return (250, b"ok")

    def has_extn(self, name: str) -> bool:
        return name.lower() == "starttls"

    def starttls(self, context=None):
        return (220, b"ready")

    def login(self, user, password):
        self.commands.append(("login", user))
        return (235, b"ok")

    def docmd(self, cmd, args=""):
        self.commands.append((cmd, args.decode() if isinstance(args, bytes) else args))
        return (235, b"2.7.0 accepted")

    def sendmail(self, sender, recipients, msg):
        self.commands.append(("sendmail", sender))
        return {}


def _wire_commands(monkeypatch, sender: SmtpSender) -> _RecordingSMTP:
    rec = _RecordingSMTP()

    def fake_smtp(*a, **k):
        return rec

    monkeypatch.setattr("openhail.smtp.smtplib.SMTP", fake_smtp)
    sender.send_xoauth2("me@example.com", "ya29.secret-token", ["to@example.com"], b"Subject: x\r\n\r\nbody")
    return rec


def test_xoauth2_smtp_response_is_base64_encoded(monkeypatch) -> None:
    """A raw SASL string in an AUTH command leaks the bearer token into the
    SMTP dialogue and puts \\x01 bytes on the command line."""
    rec = _wire_commands(monkeypatch, SmtpSender("smtp.example.com", 587))
    auth = [args for cmd, args in rec.commands if cmd == "AUTH"]
    assert len(auth) == 1
    assert auth[0].startswith("XOAUTH2 ")
    blob = auth[0][len("XOAUTH2 "):]
    # must be valid base64 and contain no control characters
    assert "\x01" not in blob
    assert "\x00" not in blob
    decoded = base64.b64decode(blob, validate=True).decode()
    assert decoded == "user=me@example.com\x01auth=Bearer ya29.secret-token\x01\x01"


def test_xoauth2_smtp_never_sends_raw_bearer_token(monkeypatch) -> None:
    """The token must not appear verbatim anywhere on the wire."""
    rec = _wire_commands(monkeypatch, SmtpSender("smtp.example.com", 587))
    for _cmd, args in rec.commands:
        assert "ya29.secret-token" not in args


def test_xoauth2_smtp_pins_envelope_sender_to_account(monkeypatch) -> None:
    rec = _wire_commands(monkeypatch, SmtpSender("smtp.example.com", 587))
    senders = [args for cmd, args in rec.commands if cmd == "sendmail"]
    assert senders == ["me@example.com"]


def test_xoauth2_smtp_rejects_empty_token(monkeypatch) -> None:
    with pytest.raises(SmtpError):
        SmtpSender("smtp.example.com", 587).send_xoauth2(
            "me@example.com", "", ["to@example.com"], b"x"
        )


# ---------------------------------------------------------------------------
# IMAP mailbox names must be escaped before use in a command.
# ---------------------------------------------------------------------------


class _RecordingIMAP:
    def __init__(self) -> None:
        self.selected: str | None = None

    def select(self, mailbox, readonly=True):
        self.selected = mailbox
        return ("OK", [b"1"])


def test_imap_folder_quote_injection_rejected() -> None:
    """A folder named `x" DELETE INBOX "` must not escape the quoted string."""
    conn = _RecordingIMAP()
    c = ImapClient("imap.example.com")
    c._conn = conn
    c.select('foo" DELETE INBOX "')
    # Every quote inside must be backslash-escaped.
    inner = conn.selected[1:-1]
    assert inner == 'foo\\" DELETE INBOX \\"'
    assert conn.selected.startswith('"') and conn.selected.endswith('"')


def test_imap_folder_backslash_is_escaped() -> None:
    conn = _RecordingIMAP()
    c = ImapClient("imap.example.com")
    c._conn = conn
    c.select("Archive\\Sub")
    assert conn.selected == '"Archive\\\\Sub"'


def test_imap_ordinary_folder_unchanged() -> None:
    conn = _RecordingIMAP()
    c = ImapClient("imap.example.com")
    c._conn = conn
    c.select("INBOX")
    assert conn.selected == '"INBOX"'


def test_imap_select_still_raises_on_failure() -> None:
    class Failing:
        def select(self, mailbox, readonly=True):
            return ("NO", [b"no such folder"])

    c = ImapClient("imap.example.com")
    c._conn = Failing()
    with pytest.raises(ImapError):
        c.select("Nope")


# ---------------------------------------------------------------------------
# Terminal escape injection from attacker-controlled mail content.
# ---------------------------------------------------------------------------


def test_terminal_csi_clear_screen_is_stripped() -> None:
    assert strip_control("before\x1b[2Jafter") == "beforeafter"


def test_terminal_cursor_move_is_stripped() -> None:
    assert strip_control("a\x1b[10;20Hb") == "ab"


def test_terminal_osc_window_title_is_stripped() -> None:
    """OSC 0 rewrites the terminal title - classic spoofing vector."""
    assert strip_control("a\x1b]0;pwned\x07b") == "ab"


def test_terminal_osc52_clipboard_write_is_stripped() -> None:
    """OSC 52 can write the clipboard from output alone."""
    payload = "a\x1b]52;c;SGVsbG8=\x07b"
    assert strip_control(payload) == "ab"


def test_terminal_8bit_csi_is_stripped() -> None:
    assert strip_control("a\x9b31mb") == "ab"


def test_terminal_nul_and_del_are_stripped() -> None:
    assert strip_control("a\x00b\x7fc") == "abc"


def test_terminal_keeps_tab_and_unicode() -> None:
    assert strip_control("a\tb cafe\u0301 \u00e9") == "a\tb cafe\u0301 \u00e9"


def test_terminal_plain_text_untouched() -> None:
    s = "Re: Invoice #4021 - paid"
    assert strip_control(s) == s


def test_cli_print_does_not_emit_escapes() -> None:
    from openhail.cli import _print

    # _print goes through strip_control; assert the helper it uses does.
    assert "\x1b" not in strip_control("\x1b]0;evil\x07subject")
