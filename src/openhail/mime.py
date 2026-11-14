"""RFC 5322 / MIME parsing for OpenHail.

Wraps stdlib `email` with a deterministic, JSON-friendly output shape.
No network access. No third-party dependencies.

Hardening notes:
- Body parts are capped in size so a malicious multipart bomb cannot exhaust
  memory during sync.
- Address headers are normalized to bare addresses, which also strips any
  attempt to smuggle a second header via a comma.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
from datetime import datetime, timezone
from email.message import EmailMessage, Message
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any

from .validate import header_safe

# A single message body part larger than this is truncated rather than
# decoded whole. 10 MiB is well above any legitimate text part.
MAX_PART_BYTES = 10 * 1024 * 1024
MAX_ADDR_PER_HEADER = 100


def _addr_list(value: str | None) -> str:
    """Normalize an address header to 'a@b, c@d' form."""
    if not value:
        return ""
    out: list[str] = []
    for chunk in value.split(",")[:MAX_ADDR_PER_HEADER]:
        _, addr = parseaddr(chunk.strip())
        if addr:
            out.append(addr)
    return ", ".join(out)


def _parse_date(value: str | None) -> str:
    """Parse a Date header to ISO-8601 UTC. Returns '' when unparseable."""
    if not value:
        return ""
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return ""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _decode_part(part: Message) -> str:
    """Decode one MIME part to text, refusing to blow up on hostile input."""
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""
    if payload is None:
        return ""
    if isinstance(payload, bytes) and len(payload) > MAX_PART_BYTES:
        payload = payload[:MAX_PART_BYTES]
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def _body_parts(msg: Message) -> tuple[str, str]:
    """Return (text, html). Never raises on malformed parts."""
    text_chunks: list[str] = []
    html_chunks: list[str] = []

    if msg.is_multipart():
        # walk() on a deeply nested multipart bomb can recurse far; cap the
        # number of parts inspected rather than trusting the tree.
        for index, part in enumerate(msg.walk()):
            if index > 1000:
                break
            if part.get_content_maintype() == "multipart":
                continue
            disposition = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disposition:
                continue
            ctype = part.get_content_type()
            decoded = _decode_part(part)
            if ctype == "text/plain":
                text_chunks.append(decoded)
            elif ctype == "text/html":
                html_chunks.append(decoded)
    else:
        decoded = _decode_part(msg)
        if msg.get_content_type() == "text/html":
            html_chunks.append(decoded)
        else:
            text_chunks.append(decoded)

    return ("\n".join(text_chunks).strip(), "\n".join(html_chunks).strip())


def parse_message(raw: bytes, account_id: int, folder_id: int, uid: int | None) -> dict[str, Any]:
    """Parse raw RFC 5322 bytes into a store-ready dict."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    body_text, body_html = _body_parts(msg)

    # With policy.default the Subject header is a header object, not a str.
    # str() yields the decoded (RFC 2047) value without touching private classes.
    subject = str(msg.get("Subject") or "")

    return {
        "account_id": account_id,
        "folder_id": folder_id,
        "uid": uid,
        "message_id": (str(msg.get("Message-ID") or "")).strip() or None,
        "in_reply_to": (str(msg.get("In-Reply-To") or "")).strip() or None,
        "references_": (str(msg.get("References") or "")).strip() or None,
        "subject": subject.strip(),
        "from_addr": _addr_list(msg.get("From")),
        "to_addr": _addr_list(msg.get("To")),
        "cc_addr": _addr_list(msg.get("Cc")),
        "date_utc": _parse_date(msg.get("Date")),
        "body_text": body_text,
        "body_html": body_html,
        "flags": "",
        "size": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }


def parse_message_full(raw: bytes) -> Message:
    """Parse to a full email.message.Message (used for header inspection)."""
    return email.message_from_bytes(raw, policy=email.policy.default)


def build_message(
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    body: str,
    cc: list[str] | None = None,
    in_reply_to: str | None = None,
    references: list[str] | None = None,
) -> bytes:
    """Build an outbound RFC 5322 message as bytes.

    Every interpolated value is checked for CR/LF so a caller cannot inject
    additional headers (e.g. Bcc) through a subject or address.
    """
    header_safe(from_addr, "from address")
    header_safe(subject, "subject")
    for addr in to_addrs:
        header_safe(addr, "to address")
    for addr in cc or []:
        header_safe(addr, "cc address")

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    if in_reply_to:
        header_safe(in_reply_to, "in_reply_to")
        msg["In-Reply-To"] = in_reply_to
    if references:
        for ref in references:
            header_safe(ref, "references")
        msg["References"] = " ".join(references)
    msg.set_content(body)
    return msg.as_bytes(policy=email.policy.SMTP)
