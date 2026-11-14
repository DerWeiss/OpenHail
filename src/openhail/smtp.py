"""SMTP submission for OpenHail.

STARTTLS-only. Refuses plaintext auth. Wraps stdlib `smtplib`.

Hardening notes:
- The envelope sender is forced to the authenticated account. A caller cannot
  send mail as an arbitrary From address through someone else's account.
- Message size and recipient count are capped before the socket is opened.
"""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass

from .validate import MAX_SEND_BYTES, ValidationError


class SmtpError(RuntimeError):
    """SMTP-level failure the caller should handle explicitly."""


@dataclass
class SendResult:
    accepted: list[str]
    refused: dict[str, tuple[int, bytes]]
    response: str

    def to_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "refused": {k: {"code": v[0], "message": v[1].decode(errors="replace")}
                        for k, v in self.refused.items()},
            "response": self.response,
        }


class SmtpSender:
    """Minimal STARTTLS SMTP submit client."""

    def __init__(self, host: str, port: int = 587, timeout: float = 30.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def send(
        self,
        username: str,
        password: str,
        from_addr: str,
        to_addrs: list[str],
        raw_message: bytes,
        cc: list[str] | None = None,
    ) -> SendResult:
        if len(raw_message) > MAX_SEND_BYTES:
            raise SmtpError(
                f"message is {len(raw_message)} bytes, exceeds the "
                f"{MAX_SEND_BYTES} byte limit"
            )
        ctx = ssl.create_default_context()
        recipients = list(to_addrs) + list(cc or [])
        if not recipients:
            raise SmtpError("No recipients.")
        if len(recipients) > 100:
            raise SmtpError("Too many recipients (max 100).")

        # Refuse to relay under an identity the caller does not own.
        sender = (from_addr or username).strip()
        if sender.lower() != username.strip().lower():
            raise ValidationError(
                f"envelope sender must be the authenticated account "
                f"({username}), not {sender!r}"
            )

        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
                smtp.ehlo()
                if not smtp.has_extn("starttls"):
                    raise SmtpError(
                        f"{self.host}:{self.port} does not advertise STARTTLS; "
                        "refusing to send credentials over plaintext."
                    )
                smtp.starttls(context=ctx)
                smtp.ehlo()
                smtp.login(username, password)
                refused: dict[str, tuple[int, bytes]] = {}
                result = smtp.sendmail(sender, recipients, raw_message)
                if result:
                    refused = dict(result)
                return SendResult(
                    accepted=[r for r in recipients if r not in refused],
                    refused=refused,
                    response="sent",
                )
        except SmtpError:
            raise
        except ValidationError:
            raise
        except smtplib.SMTPAuthenticationError as exc:
            raise SmtpError(f"SMTP AUTH rejected for {username}: {exc}") from exc
        except smtplib.SMTPException as exc:
            raise SmtpError(f"SMTP failure: {exc}") from exc
        except OSError as exc:
            raise SmtpError(f"Connection to {self.host}:{self.port} failed: {exc}") from exc

    def send_xoauth2(
        self,
        username: str,
        access_token: str,
        to_addrs: list[str],
        raw_message: bytes,
        cc: list[str] | None = None,
    ) -> SendResult:
        """Send via SASL XOAUTH2 — the only path Gmail and Microsoft 365 allow."""
        if len(raw_message) > MAX_SEND_BYTES:
            raise SmtpError(
                f"message is {len(raw_message)} bytes, exceeds the "
                f"{MAX_SEND_BYTES} byte limit"
            )
        if not access_token:
            raise SmtpError("empty access token")
        ctx = ssl.create_default_context()
        recipients = list(to_addrs) + list(cc or [])
        if not recipients:
            raise SmtpError("No recipients.")
        if len(recipients) > 100:
            raise SmtpError("Too many recipients (max 100).")
        auth_string = f"user={username}\x01auth=Bearer {access_token}\x01\x01"
        sender = username
        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
                smtp.ehlo()
                if not smtp.has_extn("starttls"):
                    raise SmtpError(
                        f"{self.host}:{self.port} does not advertise STARTTLS; "
                        "refusing to send a bearer token over plaintext."
                    )
                smtp.starttls(context=ctx)
                smtp.ehlo()
                code, resp = smtp.docmd("AUTH", "XOAUTH2 " + auth_string)
                if code != 235:
                    raise SmtpError(
                        f"XOAUTH2 rejected for {username}: {code} "
                        f"{resp.decode(errors='replace') if isinstance(resp, bytes) else resp}"
                    )
                refused: dict[str, tuple[int, bytes]] = {}
                result = smtp.sendmail(sender, recipients, raw_message)
                if result:
                    refused = dict(result)
                return SendResult(
                    accepted=[r for r in recipients if r not in refused],
                    refused=refused,
                    response="sent",
                )
        except SmtpError:
            raise
        except ValidationError:
            raise
        except smtplib.SMTPAuthenticationError as exc:
            raise SmtpError(f"SMTP AUTH rejected for {username}: {exc}") from exc
        except smtplib.SMTPException as exc:
            raise SmtpError(f"SMTP failure: {exc}") from exc
        except OSError as exc:
            raise SmtpError(f"Connection to {self.host}:{self.port} failed: {exc}") from exc
