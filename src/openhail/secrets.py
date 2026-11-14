"""Secret storage for OpenHail.

Passwords are held in the OS keyring when available, and never written to
mail.db or any config file. If the `keyring` package is absent we refuse to
persist secrets at all rather than fall back to plaintext.
"""

from __future__ import annotations

import os

SERVICE = "openhail"


class SecretError(RuntimeError):
    pass


def _backend():
    try:
        import keyring  # type: ignore
    except ImportError:
        return None
    return keyring


def set_password(account_name: str, username: str, password: str) -> None:
    kr = _backend()
    if kr is None:
        raise SecretError(
            "No keyring backend installed. Install `keyring` or supply the password "
            "via the OPENHAIL_PASSWORD environment variable for this session. "
            "OpenHail will not write plaintext credentials to disk."
        )
    kr.set_password(f"{SERVICE}:{account_name}", username, password)


def get_password(account_name: str, username: str) -> str | None:
    env = os.environ.get("OPENHAIL_PASSWORD")
    if env:
        return env
    kr = _backend()
    if kr is None:
        return None
    try:
        return kr.get_password(f"{SERVICE}:{account_name}", username)
    except Exception:
        return None


def delete_password(account_name: str, username: str) -> None:
    kr = _backend()
    if kr is None:
        return
    try:
        kr.delete_password(f"{SERVICE}:{account_name}", username)
    except Exception:
        pass
