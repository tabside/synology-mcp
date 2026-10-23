"""HTTP-Schutz: Bearer-Token auf allen Pfaden ausser GET /healthz."""

import os
import sys

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import synology_mcp as sm  # noqa: E402

TOKEN = "test-mcp-auth-token"
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
def http_client():
    with TestClient(sm.build_http_app(TOKEN), base_url="https://mcp.example.com") as client:
        yield client


def init_request():
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}},
    }


def test_healthz_without_token_is_200(http_client):
    resp = http_client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_mcp_without_token_is_401(http_client):
    resp = http_client.post("/mcp", json=init_request(), headers=HEADERS)
    assert resp.status_code == 401
    assert resp.json() == {"error": "unauthorized"}


@pytest.mark.parametrize("auth", ["Bearer wrong", f"bearer {TOKEN}", TOKEN, "Basic abc"])
def test_mcp_wrong_token_is_401(http_client, auth):
    assert http_client.post("/mcp", json=init_request(), headers={**HEADERS, "Authorization": auth}).status_code == 401


def test_mcp_valid_token_passes(http_client):
    resp = http_client.post("/mcp", json=init_request(), headers={**HEADERS, "Authorization": f"Bearer {TOKEN}"})
    assert resp.status_code == 200


@pytest.mark.parametrize("path", ["/healthz/", "/healthzx", "/mcp/healthz", "/"])
def test_other_paths_still_need_token(http_client, path):
    assert http_client.get(path).status_code == 401


def test_healthz_only_get(http_client):
    assert http_client.post("/healthz").status_code == 401


@pytest.mark.parametrize("token", ["", "kurz", "a" * 31])
def test_main_refuses_short_token(monkeypatch, token):
    monkeypatch.setattr(sm, "MCP_AUTH_TOKEN", token)
    with pytest.raises(RuntimeError, match="mind. 32 Zeichen"):
        sm.main()


def test_main_accepts_32_char_token(monkeypatch):
    monkeypatch.setattr(sm, "MCP_AUTH_TOKEN", "a" * 32)
    started = []
    monkeypatch.setattr(sm.asyncio, "run", lambda coro: (started.append(coro), coro.close()))
    sm.main()
    assert started

