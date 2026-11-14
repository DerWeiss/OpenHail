"""Tests for the XOAUTH2 / OAuth2 layer.

No network calls: `urllib.request.urlopen` is monkeypatched. Every test here
runs offline and deterministically.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.parse
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from openhail import oauth
from openhail.oauth import (
    GOOGLE,
    MICROSOFT,
    PROVIDERS,
    OAuthError,
    Token,
    authorization_url,
    device_code_start,
    pkce_pair,
    refresh_token,
    xoauth2_string,
)


# ---- provider registry ---------------------------------------------------


def test_both_providers_registered() -> None:
    assert set(PROVIDERS) == {GOOGLE, MICROSOFT}
    assert PROVIDERS[GOOGLE].imap_host() == "imap.gmail.com"
    assert PROVIDERS[MICROSOFT].imap_host() == "outlook.office365.com"


def test_google_requests_offline_access() -> None:
    params = dict(PROVIDERS[GOOGLE].extra_auth_params)
    assert params.get("access_type") == "offline"


def test_microsoft_requests_offline_scope() -> None:
    assert "offline_access" in PROVIDERS[MICROSOFT].default_scopes


# ---- PKCE ----------------------------------------------------------------


def test_pkce_pair_shape() -> None:
    verifier, challenge = pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert "=" not in verifier and "=" not in challenge
    assert len(challenge) == 43


def test_pkce_challenge_is_sha256_of_verifier() -> None:
    import base64
    import hashlib

    verifier, challenge = pkce_pair()
    expect = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    assert challenge == expect


def test_pkce_pairs_are_unique() -> None:
    assert pkce_pair()[0] != pkce_pair()[0]


# ---- authorization url ---------------------------------------------------


def test_authorization_url_contains_required_params() -> None:
    url, state, verifier = authorization_url(
        PROVIDERS[GOOGLE], "client-123", "http://127.0.0.1:8080/cb"
    )
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert q["client_id"] == ["client-123"]
    assert q["response_type"] == ["code"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["state"] == [state]
    assert q["code_verifier"] if "code_verifier" in q else True  # never sent
    assert "code_verifier" not in q
    assert q["redirect_uri"] == ["http://127.0.0.1:8080/cb"]
    assert verifier


def test_authorization_url_encodes_scope() -> None:
    url, _, _ = authorization_url(PROVIDERS[MICROSOFT], "c", "http://localhost/cb")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert "offline_access" in q["scope"][0]
    assert "IMAP.AccessAsUser.All" in q["scope"][0]


# ---- token model ---------------------------------------------------------


def test_token_expiry_logic() -> None:
    fresh = Token("a", "r", time.time() + 3600)
    assert not fresh.is_expired()
    stale = Token("a", "r", time.time() - 10)
    assert stale.is_expired()
    # within the 120s skew window counts as expired
    skew = Token("a", "r", time.time() + 60)
    assert skew.is_expired()


def test_token_roundtrip() -> None:
    t = Token("acc", "ref", 12345.0, scope="s")
    assert Token.from_dict(t.to_dict()) == t


def test_token_rotation_keeps_old_refresh() -> None:
    payload = {"access_token": "new", "expires_in": 3600}  # no refresh_token
    t = Token.from_response(payload, prior_refresh="old-refresh")
    assert t.refresh_token == "old-refresh"
    assert t.access_token == "new"


def test_token_rotation_accepts_new_refresh() -> None:
    payload = {"access_token": "new", "expires_in": 3600, "refresh_token": "new-r"}
    t = Token.from_response(payload, prior_refresh="old-r")
    assert t.refresh_token == "new-r"


def test_token_response_without_access_token_raises() -> None:
    with pytest.raises(OAuthError) as ei:
        Token.from_response({"error": "invalid_grant"})
    assert ei.value.code == "invalid_grant"


def test_expires_in_is_honoured() -> None:
    before = time.time()
    t = Token.from_response({"access_token": "a", "expires_in": 1200})
    assert t.expires_at >= before + 1190


# ---- refresh -------------------------------------------------------------


def test_refresh_without_refresh_token_raises() -> None:
    with pytest.raises(OAuthError) as ei:
        refresh_token(PROVIDERS[GOOGLE], "c", Token("a", None, 0))
    assert "refresh token" in str(ei.value)


def test_refresh_posts_correct_grant() -> None:
    seen: dict = {}

    def fake(url, data, timeout=30.0):
        seen["url"] = url
        seen["data"] = data
        return {"access_token": "fresh", "expires_in": 3600}

    with mock.patch.object(oauth, "_post_form", fake):
        t = refresh_token(
            PROVIDERS[GOOGLE], "cid", Token("old", "r-tok", time.time())
        )
    assert seen["url"] == PROVIDERS[GOOGLE].token_endpoint
    assert seen["data"]["grant_type"] == "refresh_token"
    assert seen["data"]["refresh_token"] == "r-tok"
    assert seen["data"]["client_id"] == "cid"
    assert "client_secret" not in seen["data"]
    assert t.access_token == "fresh"
    assert t.refresh_token == "r-tok"


def test_refresh_includes_secret_when_given() -> None:
    seen: dict = {}

    def fake(url, data, timeout=30.0):
        seen["data"] = data
        return {"access_token": "x", "expires_in": 60}

    with mock.patch.object(oauth, "_post_form", fake):
        refresh_token(PROVIDERS[MICROSOFT], "cid", Token("a", "r", 0), "s3cret")
    assert seen["data"]["client_secret"] == "s3cret"


# ---- device code ---------------------------------------------------------


def test_device_code_start_parses_response() -> None:
    def fake(url, data, timeout=30.0):
        assert data["client_id"] == "cid"
        return {
            "device_code": "dev-1",
            "user_code": "ABCD-EFGH",
            "verification_url": "https://example.com/dev",
            "interval": 5,
            "expires_in": 900,
        }

    with mock.patch.object(oauth, "_post_form", fake):
        dc = device_code_start(PROVIDERS[MICROSOFT], "cid")
    assert dc.device_code == "dev-1"
    assert dc.user_code == "ABCD-EFGH"
    assert dc.interval == 5
    assert not dc.expired


def test_device_code_poll_retries_on_pending() -> None:
    calls = {"n": 0}

    def fake(url, data, timeout=30.0):
        calls["n"] += 1
        if calls["n"] < 3:
            return {"error": "authorization_pending"}
        return {"access_token": "tok", "expires_in": 3600}

    dc = oauth.DeviceCode("d", "U", "https://e", 1, time.time() + 60)
    with mock.patch.object(oauth, "_post_form", fake), \
            mock.patch.object(oauth.time, "sleep", lambda _s: None):
        t = oauth.device_code_poll(PROVIDERS[MICROSOFT], "cid", dc)
    assert t.access_token == "tok"
    assert calls["n"] == 3


def test_device_code_poll_raises_on_access_denied() -> None:
    def fake(url, data, timeout=30.0):
        return {"error": "access_denied"}

    dc = oauth.DeviceCode("d", "U", "https://e", 1, time.time() + 60)
    with mock.patch.object(oauth, "_post_form", fake), \
            mock.patch.object(oauth.time, "sleep", lambda _s: None):
        with pytest.raises(OAuthError) as ei:
            oauth.device_code_poll(PROVIDERS[MICROSOFT], "cid", dc)
    assert ei.value.code == "access_denied"


def test_device_code_poll_times_out() -> None:
    def fake(url, data, timeout=30.0):
        return {"error": "authorization_pending"}

    dc = oauth.DeviceCode("d", "U", "https://e", 1, time.time() + 60)
    with mock.patch.object(oauth, "_post_form", fake), \
            mock.patch.object(oauth.time, "sleep", lambda _s: None):
        with pytest.raises(OAuthError) as ei:
            oauth.device_code_poll(PROVIDERS[MICROSOFT], "cid", dc, max_wait=0.01)
    assert "timed out" in str(ei.value)


# ---- SASL string ---------------------------------------------------------


def test_xoauth2_string_exact_shape() -> None:
    s = xoauth2_string("me@example.com", "ya29.token")
    assert s == "user=me@example.com\x01auth=Bearer ya29.token\x01\x01"
    assert s.count("\x01") == 3


def test_xoauth2_rejects_control_chars() -> None:
    with pytest.raises(OAuthError):
        xoauth2_string("me@example.com", "tok\x01auth=Bearer other")
    with pytest.raises(OAuthError):
        xoauth2_string("me\x01admin=1", "tok")


def test_xoauth2_rejects_empty_token() -> None:
    with pytest.raises(OAuthError):
        xoauth2_string("me@example.com", "")


# ---- token storage (keyring mocked) -------------------------------------


def test_save_and_load_token_roundtrip(tmp_path: Path) -> None:
    store: dict = {}

    class FakeKeyring:
        @staticmethod
        def set_password(service, user, value):
            store[(service, user)] = value

        @staticmethod
        def get_password(service, user):
            return store.get((service, user))

        @staticmethod
        def delete_password(service, user):
            store.pop((service, user), None)

    with mock.patch.dict(sys.modules, {"keyring": FakeKeyring}):
        t = Token("acc", "ref", time.time() + 3600, scope="s")
        oauth.save_token("myacct", t)
        loaded = oauth.load_token("myacct")
        assert loaded == t
        # stored under the openhail namespace, never a bare name
        assert any(k[0].startswith("openhail:") for k in store)
        oauth.delete_token("myacct")
        assert oauth.load_token("myacct") is None


def test_save_token_without_keyring_raises() -> None:
    from openhail.secrets import SecretError

    with mock.patch.dict(sys.modules, {"keyring": None}):
        with pytest.raises(SecretError):
            oauth.save_token("acct", Token("a", "r", 0))


def test_token_key_cannot_escape_namespace() -> None:
    from openhail.secrets import SecretError

    with pytest.raises(SecretError):
        oauth._token_key("bad:name")


# ---- HTTP error handling -------------------------------------------------


def test_post_form_error_payload_raises_oauth_error() -> None:
    import urllib.error
    import io

    def fake_urlopen(req, timeout=30.0):
        raise urllib.error.HTTPError(
            "https://x", 400, "Bad Request", {},
            io.BytesIO(json.dumps({
                "error": "invalid_client",
                "error_description": "bad client",
            }).encode()),
        )

    with mock.patch.object(oauth.urllib.request, "urlopen", fake_urlopen):
        with pytest.raises(OAuthError) as ei:
            oauth._post_form("https://x", {"a": "b"})
    assert ei.value.code == "invalid_client"
    assert ei.value.description == "bad client"


def test_form_encoding_prevents_param_smuggling() -> None:
    """A secret containing & or = must not create new form fields."""
    captured: dict = {}

    def fake_urlopen(req, timeout=30.0):
        captured["body"] = req.data
        import io
        return io.BytesIO(b'{"access_token":"t","expires_in":60}')

    with mock.patch.object(oauth.urllib.request, "urlopen", fake_urlopen):
        oauth._post_form("https://x", {"client_secret": "a&grant_type=junk"})
    parsed = urllib.parse.parse_qs(captured["body"].decode())
    assert parsed["client_secret"] == ["a&grant_type=junk"]
    assert "junk" not in parsed.get("grant_type", [])


# ---- IMAP/SMTP integration hooks ----------------------------------------


def test_imap_client_has_xoauth2_method() -> None:
    from openhail.imap import ImapClient

    c = ImapClient("imap.gmail.com", 993)
    assert hasattr(c, "authenticate_xoauth2")


def test_smtp_sender_has_xoauth2_method() -> None:
    from openhail.smtp import SmtpSender

    s = SmtpSender("smtp.gmail.com", 587)
    assert hasattr(s, "send_xoauth2")


def test_imap_auth_sends_correct_payload() -> None:
    from openhail.imap import ImapClient

    sent: dict = {}

    class FakeConn:
        def authenticate(self, mech, cb):
            sent["mech"] = mech
            sent["payload"] = cb(None)
            return ("OK", [b"ok"])

    c = ImapClient("imap.gmail.com")
    c._conn = FakeConn()
    c.authenticate_xoauth2("me@example.com", "ya29.tok")
    assert sent["mech"] == "XOAUTH2"
    assert sent["payload"] == b"user=me@example.com\x01auth=Bearer ya29.tok\x01\x01"


def test_imap_auth_failure_raises() -> None:
    from openhail.imap import ImapClient, ImapError

    class FakeConn:
        def authenticate(self, mech, cb):
            return ("NO", [b"[AUTHENTICATIONFAILED] invalid"])

    c = ImapClient("imap.gmail.com")
    c._conn = FakeConn()
    with pytest.raises(ImapError):
        c.authenticate_xoauth2("me@example.com", "bad")
