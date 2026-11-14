"""Input validation and hardening limits for OpenHail.

Every limit here exists because a red-teamer would otherwise use it. Each one is
named after the attack it stops, so a future maintainer can tell whether removing
it re-opens a hole.
"""

from __future__ import annotations

import re

# ---- size limits -------------------------------------------------------

# DoS: one giant stdin line OOMs the process. 1 MiB is far more than any
# legitimate JSON-RPC request needs (largest is a mail.send body).
MAX_REQUEST_BYTES = 1 * 1024 * 1024

# DoS: FTS5 MATCH with a pathological query spins SQLite. Cap length and
# forbid the operators that cause runaway work.
MAX_SEARCH_QUERY = 512

# A single sync call should never be asked to pull an unbounded number of
# messages into memory.
MAX_SYNC_LIMIT = 5000
MAX_LIST_LIMIT = 1000

# Sanity cap on outbound message size.
MAX_SEND_BYTES = 25 * 1024 * 1024

# ---- name / address validation -----------------------------------------

ACCOUNT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$")
EMAIL_RE = re.compile(r"^[^@\s,<>]{1,64}@[^@\s,<>]{1,255}$")
FOLDER_RE = re.compile(r"^[\w\-\. /&]{1,128}$")

# FTS5 operators that let a caller request unbounded work.
FORBIDDEN_FTS_TOKENS = ("NEAR", "*", "^", ":")


class ValidationError(ValueError):
    """Raised when caller-supplied input breaks a documented constraint."""


def account_name(value: object) -> str:
    if not isinstance(value, str) or not ACCOUNT_NAME_RE.match(value):
        raise ValidationError(
            "account name must be 1-64 chars of lowercase a-z, 0-9, '_' or '-', "
            "starting with a letter or digit"
        )
    return value


def hostname(value: object) -> str:
    if not isinstance(value, str) or not HOSTNAME_RE.match(value):
        raise ValidationError("host must be a plain DNS name or IPv4 address")
    return value


def port(value: object) -> int:
    try:
        p = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValidationError("port must be an integer")
    if not (1 <= p <= 65535):
        raise ValidationError("port must be 1-65535")
    return p


def email_addr(value: object, field: str = "address") -> str:
    if not isinstance(value, str) or not EMAIL_RE.match(value):
        raise ValidationError(f"{field} must be a single bare email address")
    if "\n" in value or "\r" in value:
        raise ValidationError(f"{field} must not contain newlines")
    return value


def email_list(value: object, field: str = "recipients") -> list[str]:
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, list):
        items = value
    else:
        raise ValidationError(f"{field} must be a string or list of strings")
    if not items:
        raise ValidationError(f"{field} must not be empty")
    if len(items) > 100:
        raise ValidationError(f"{field} exceeds 100 entries")
    return [email_addr(i, field) for i in items]


def folder_name(value: object) -> str:
    if not isinstance(value, str) or not FOLDER_RE.match(value):
        raise ValidationError("folder name contains disallowed characters")
    if ".." in value:
        raise ValidationError("folder name must not contain '..'")
    return value


def bounded_int(value: object, default: int, maximum: int, field: str = "limit") -> int:
    if value is None:
        return default
    try:
        n = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValidationError(f"{field} must be an integer")
    if n < 1:
        raise ValidationError(f"{field} must be >= 1")
    if n > maximum:
        raise ValidationError(f"{field} must be <= {maximum}")
    return n


def search_query(value: object) -> str:
    """Sanitize a search string before it reaches FTS5 MATCH."""
    if not isinstance(value, str):
        raise ValidationError("query must be a string")
    q = value.strip()
    if not q:
        raise ValidationError("query must not be empty")
    if len(q) > MAX_SEARCH_QUERY:
        raise ValidationError(f"query must be <= {MAX_SEARCH_QUERY} characters")
    upper = q.upper()
    for token in FORBIDDEN_FTS_TOKENS:
        if token in upper:
            raise ValidationError(
                f"query must not contain the FTS operator {token!r}; "
                "plain words and quoted phrases only"
            )
    return q


def header_safe(value: object, field: str = "value") -> str:
    """Reject CRLF injection into mail headers."""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    if "\r" in value or "\n" in value:
        raise ValidationError(
            f"{field} must not contain CR/LF (header injection)"
        )
    return value


_ESCAPE_RE = re.compile(
    r"""
    \x1b  \[ [0-9;?]* [A-Za-z]          # CSI  - colours, cursor moves, clears
  | \x1b  \]  [^\x07\x1b]* (\x07|\x1b\\)  # OSC  - window title, clipboard (OSC 52)
  | \x1b  [PX^_] [^\x1b]* \x1b\\        # DCS/SOS/PM/APC string sequences
  | \x1b  [@-Z\\-_]                     # Fe   - single-char escapes
  | \x9b  [0-9;?]* [A-Za-z]             # 8-bit CSI (C1)
    """,
    re.VERBOSE,
)


def strip_control(text: object) -> str:
    """Remove terminal escape sequences from untrusted text before printing.

    Mail subjects and bodies are attacker-controlled. Printed raw to a
    terminal they can rewrite the window title, clear the screen, move the
    cursor to spoof a prompt, or - via OSC 52 - write to the clipboard.
    This is the terminal equivalent of XSS.

    Only affects display. Stored and transmitted bytes are untouched.
    """
    if not isinstance(text, str):
        text = str(text)
    text = _ESCAPE_RE.sub("", text)
    # Remaining C0 controls (except tab) and DEL have no business in output.
    return "".join(
        ch for ch in text
        if ch == "\t" or (ch >= " " and ch != "\x7f")
    )
