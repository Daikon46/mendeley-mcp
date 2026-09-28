"""Tests for credential loading."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

import mendeley_mcp.auth as auth


@pytest.fixture
def keyring_credentials_file(tmp_path, monkeypatch):
    """Point the auth module at a temp credentials file using keyring storage."""
    credentials_file = tmp_path / "credentials.json"
    credentials_file.write_text(json.dumps({"client_id": "id-123", "use_keyring": True}))
    monkeypatch.setattr(auth, "CREDENTIALS_FILE", credentials_file)
    monkeypatch.setattr(auth, "KEYRING_AVAILABLE", True)
    return credentials_file


def _fake_keyring(entries: dict[str, str | None]):
    class FakeKeyring:
        @staticmethod
        def get_password(service: str, key: str) -> str | None:
            assert service == "mendeley-mcp"
            return entries.get(key)

    return FakeKeyring


def test_load_credentials_returns_none_without_tokens(
    keyring_credentials_file, monkeypatch
):
    """Missing tokens mean there is nothing usable to load."""
    monkeypatch.setattr(
        auth, "keyring", _fake_keyring({"client_secret": "sec"})
    )

    assert auth.load_credentials() is None


def test_load_credentials_tolerates_missing_client_secret(
    keyring_credentials_file, monkeypatch
):
    """Logins made before v0.2.0 stored no client secret; tokens still load."""
    monkeypatch.setattr(
        auth,
        "keyring",
        _fake_keyring({"access_token": "at", "refresh_token": "rt"}),
    )

    config = auth.load_credentials()

    assert config is not None
    assert config["access_token"] == "at"
    assert config["refresh_token"] == "rt"
    assert "client_secret" not in config


def test_load_credentials_includes_client_secret_when_present(
    keyring_credentials_file, monkeypatch
):
    """A complete keyring entry loads all three secrets."""
    monkeypatch.setattr(
        auth,
        "keyring",
        _fake_keyring(
            {"client_secret": "sec", "access_token": "at", "refresh_token": "rt"}
        ),
    )

    config = auth.load_credentials()

    assert config is not None
    assert config["client_secret"] == "sec"
    assert config["access_token"] == "at"
    assert config["refresh_token"] == "rt"


def test_login_rejects_callback_with_wrong_state(monkeypatch):
    class CallbackServer:
        def __init__(self, address, handler):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def handle_request(self):
            auth._oauth_response = {"success": True, "code": "code", "state": "wrong"}

    monkeypatch.setattr(auth.socketserver, "TCPServer", CallbackServer)
    monkeypatch.setattr(auth.webbrowser, "open", lambda url: None)
    monkeypatch.setattr(auth.secrets, "token_urlsafe", lambda size: "expected")

    def exchange(*args, **kwargs):
        raise AssertionError("A callback with the wrong state must not exchange its code")

    monkeypatch.setattr(auth, "exchange_code_for_tokens", exchange)
    result = CliRunner().invoke(
        auth.cli,
        ["login", "--client-id", "id", "--client-secret", "secret", "--port", "8001"],
    )
    assert result.exit_code == 1
    assert "OAuth state mismatch" in result.output
