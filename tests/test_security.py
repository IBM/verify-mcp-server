"""Security regression tests for Verify MCP Server (PSIRT classes)."""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest
from starlette.requests import Request

from src.server import APIKeyMiddleware, _admin_authorized
from src.tools import _resolve_path


def test_resolve_path_happy_path():
    path, rem = _resolve_path("/v2.0/Users/{id}", {"id": "abc-123", "limit": "10"})
    assert path == "/v2.0/Users/abc-123"
    assert rem == {"limit": "10"}


def test_resolve_path_rejects_dotdot():
    with pytest.raises(ValueError, match="single path segment"):
        _resolve_path("/v2.0/Users/{id}", {"id": "../../../v1.0/Applications"})


def test_resolve_path_rejects_slash():
    with pytest.raises(ValueError, match="single path segment"):
        _resolve_path("/v2.0/Users/{id}", {"id": "foo/bar"})


def test_resolve_path_encodes_special_chars():
    path, _ = _resolve_path("/v2.0/Users/{id}", {"id": "a b"})
    assert path == "/v2.0/Users/a%20b"


def test_admin_authorized_requires_token(monkeypatch):
    monkeypatch.delenv("MCP_ADMIN_TOKEN", raising=False)
    req = MagicMock(spec=Request)
    req.headers = {"Authorization": "Bearer anything"}
    assert _admin_authorized(req) is False


def test_admin_authorized_accepts_bearer(monkeypatch):
    monkeypatch.setenv("MCP_ADMIN_TOKEN", "secret-admin")
    req = MagicMock(spec=Request)
    req.headers = {"Authorization": "Bearer secret-admin"}
    assert _admin_authorized(req) is True


def test_admin_authorized_accepts_x_admin_header(monkeypatch):
    monkeypatch.setenv("MCP_ADMIN_TOKEN", "secret-admin")
    req = MagicMock(spec=Request)
    req.headers = {"X-Admin-Token": "secret-admin"}
    assert _admin_authorized(req) is True


def test_admin_authorized_rejects_wrong_token(monkeypatch):
    monkeypatch.setenv("MCP_ADMIN_TOKEN", "secret-admin")
    req = MagicMock(spec=Request)
    req.headers = {"Authorization": "Bearer wrong"}
    assert _admin_authorized(req) is False


def test_middleware_open_prefixes_health_only():
    assert APIKeyMiddleware.OPEN_PREFIXES == ("/health",)
    assert "/admin/keys" not in APIKeyMiddleware.OPEN_PREFIXES
