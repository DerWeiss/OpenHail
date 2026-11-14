"""Secret storage for OpenHail.

Passwords are held in the OS keyring when available, and never written to
mail.db or any config file. If the `keyring` package is absent we refuse to
persist secrets at all rather than fall back to plaintext.

Hardening notes:
- The account name is validated before it becomes part of a keyring key, so
  a caller cannot forge a namespace by smuggling ':' into the name.
- Passwords are never accepted from argv (visible in `ps` and shell history).
"""

from __future__ import annotations

import os

from .validate import ValidationError, account_name as validate_account_name

SERVICE = "openhail"


class SecretError(RuntimeError):
    pass


def _backend():
    try:
        import keyring  # type: ignore
    except ImportError:
        return None
    return keyring


def _key(account_name: str) -> str:
    """Build a namespaced keyring entry name.

    The account name is validated to exclude ':' so it cannot collide with or
    escape the 'openhail:' namespace.
    """
    try:
        safe = validate_account_name(account_name)
    except ValidationError as exc:
        raise SecretError(f"invalid account name: {exc}") from exc
    return f"{SERVICE}:{safe}"


def set_password(account_name: str, username: str, password: str) -> None:
    if not password:
        raise SecretError("refusing to store an empty password")
    kr = _backend()
    if kr is None:
        raise SecretError(
            "No keyring backend installed. Install `keyring` or supply the password "
            "via the OPENHAIL_PASSWORD environment variable for this session. "
            "OpenHail will not write plaintext credentials to disk."
        )
    kr.set_password(_key(account_name), username, password)


def get_password(account_name: str, username: str) -> str | None:
    env = os.environ.get("OPENHAIL_PASSWORD")
    if env:
        return env
    kr = _backend()
    if kr is None:
        return None
    try:
        return kr.get_password(_key(account_name), username)
    except Exception:
        return None


def delete_password(account_name: str, username: str) -> None:
    kr = _backend()
    if kr is None:
        return
    try:
        kr.delete_password(_key(account_name), username)
    except Exception:
        pass
