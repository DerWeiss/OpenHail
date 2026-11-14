"""SMTP submission for OpenHail.

STARTTLS-only. Refuses plaintext auth. Wraps stdlib `smtplib`.
"""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass


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
        ctx = ssl.create_default_context()
        recipients = list(to_addrs) + list(cc or [])
        if not recipients:
            raise SmtpError("No recipients.")

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
                result = smtp.sendmail(from_addr, recipients, raw_message)
                if result:
                    refused = dict(result)
                return SendResult(
                    accepted=[r for r in recipients if r not in refused],
                    refused=refused,
                    response="sent",
                )
        except smtplib.SMTPAuthenticationError as exc:
            raise SmtpError(f"SMTP AUTH rejected for {username}: {exc}") from exc
        except smtplib.SMTPException as exc:
            raise SmtpError(f"SMTP failure: {exc}") from exc
        except OSError as exc:
            raise SmtpError(f"Connection to {self.host}:{self.port} failed: {exc}") from exc
