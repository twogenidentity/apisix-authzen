from __future__ import annotations

"""
MCP security tests for the authzen APISIX plugin.

Route created here:
  POST/GET/DELETE /mcp  — MCP endpoint, enforce only on tools/call
  POST/GET/DELETE /mcp-strict — MCP endpoint, no enforce_on (all methods enforced)

Key security properties verified:
  - Bearer token always required, even for non-enforced MCP methods
  - tools/call is fully enforced (401 no token / 403 denied / 200 allowed)
  - initialize / tools/list skip PDP (pass through when allowed)
  - GET (SSE) and DELETE (session termination) skip PDP
  - PDP unavailability yields 503 for enforced methods
"""

import time

import pytest
import requests

from helpers import (
    APISIX_PROXY,
    MOCK_PDP,
    admin_delete,
    admin_put,
    bearer,
    configure_pdp,
    make_jwt,
    pdp_state,
)

_UPSTREAM_MCP = {
    "nodes": {"mock-mcp-upstream:8001": 1},
    "type": "roundrobin",
}

_UPSTREAM_NGINX = {
    "nodes": {"upstream:80": 1},
    "type": "roundrobin",
}

_AUTHZEN_MCP = {
    "pdp": {"host": "http://mock-pdp:8080"},
    "subject": {"type": "user", "id": "claim::sub"},
    "resource": {"type": "tool", "id": "mcp::tool::name"},
    "action": {"name": "execute"},
    "mcp": {
        "enforce_on": {"methods": ["tools/call"]},
    },
}

_AUTHZEN_MCP_STRICT = {
    "pdp": {"host": "http://mock-pdp:8080"},
    "subject": {"type": "user", "id": "claim::sub"},
    "resource": {"type": "route", "id": "uri"},
    "action": {"name": "method"},
    # No mcp.enforce_on → all requests are enforced (backward-compatible default)
}


def mcp_body(method: str, params: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}


@pytest.fixture(scope="module", autouse=True)
def mcp_routes():
    admin_put("/apisix/admin/routes/mcp-selective", {
        "uri": "/mcp",
        "methods": ["GET", "POST", "DELETE"],
        "upstream": _UPSTREAM_MCP,
        "plugins": {"authzen": _AUTHZEN_MCP},
    })
    admin_put("/apisix/admin/routes/mcp-strict", {
        "uri": "/mcp-strict",
        "methods": ["GET", "POST", "DELETE"],
        "upstream": _UPSTREAM_NGINX,
        "plugins": {"authzen": _AUTHZEN_MCP_STRICT},
    })
    time.sleep(1)
    yield
    admin_delete("/apisix/admin/routes/mcp-selective")
    admin_delete("/apisix/admin/routes/mcp-strict")


# ---------------------------------------------------------------------------
# Bearer token always required
# ---------------------------------------------------------------------------

class TestGivenNoBearerToken:
    def test_when_tools_call_sent_without_token_then_returns_401(self):
        r = requests.post(f"{APISIX_PROXY}/mcp",
                          json=mcp_body("tools/call", {
                              "name": "fintech_list_expenses",
                              "arguments": {"tenant": "tenant1"},
                          }))
        assert r.status_code == 401

    def test_when_initialize_sent_without_token_then_returns_401(self):
        """Even non-enforced MCP methods require a bearer token."""
        r = requests.post(f"{APISIX_PROXY}/mcp",
                          json=mcp_body("initialize", {
                              "protocolVersion": "2024-11-05",
                              "capabilities": {},
                          }))
        assert r.status_code == 401

    def test_when_sse_get_sent_without_token_then_returns_401(self):
        r = requests.get(f"{APISIX_PROXY}/mcp")
        assert r.status_code == 401

    def test_when_delete_sent_without_token_then_returns_401(self):
        r = requests.delete(f"{APISIX_PROXY}/mcp")
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# tools/call enforcement (the critical MCP method)
# ---------------------------------------------------------------------------

class TestGivenToolsCallEnforced:
    def test_when_pdp_allows_then_returns_200(self):
        configure_pdp(decision=True)
        r = requests.post(f"{APISIX_PROXY}/mcp",
                          json=mcp_body("tools/call", {
                              "name": "fintech_list_expenses",
                              "arguments": {"tenant": "tenant1"},
                          }),
                          headers=bearer(make_jwt(sub="user1")))
        assert r.status_code == 200

    def test_when_pdp_denies_then_returns_403(self):
        configure_pdp(decision=False)
        r = requests.post(f"{APISIX_PROXY}/mcp",
                          json=mcp_body("tools/call", {
                              "name": "fintech_list_expenses",
                              "arguments": {"tenant": "tenant1"},
                          }),
                          headers=bearer(make_jwt(sub="user1")))
        assert r.status_code == 403

    def test_when_tools_call_sent_then_pdp_receives_tool_name_as_resource_id(self):
        """Verifies the AuthZEN resource.id is the MCP tool name, not the URI."""
        configure_pdp(decision=True)
        requests.post(f"{APISIX_PROXY}/mcp",
                      json=mcp_body("tools/call", {
                          "name": "fintech_get_balance",
                          "arguments": {"tenant": "tenant1"},
                      }),
                      headers=bearer(make_jwt(sub="user1")))
        state = pdp_state()
        assert state["last_request"]["resource"]["id"] == "fintech_get_balance"
        assert state["last_request"]["resource"]["type"] == "tool"
        assert state["last_request"]["action"]["name"] == "execute"

    def test_when_tools_call_sent_then_pdp_receives_jwt_sub_as_subject_id(self):
        configure_pdp(decision=True)
        requests.post(f"{APISIX_PROXY}/mcp",
                      json=mcp_body("tools/call", {
                          "name": "fintech_list_expenses",
                          "arguments": {"tenant": "tenant1"},
                      }),
                      headers=bearer(make_jwt(sub="alice@example.com")))
        state = pdp_state()
        assert state["last_request"]["subject"]["id"] == "alice@example.com"

    def test_when_pdp_unavailable_then_returns_503(self):
        configure_pdp(simulate="error")
        r = requests.post(f"{APISIX_PROXY}/mcp",
                          json=mcp_body("tools/call", {
                              "name": "fintech_list_expenses",
                              "arguments": {"tenant": "tenant1"},
                          }),
                          headers=bearer(make_jwt()))
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# Selective enforcement — non-enforced methods skip PDP
# ---------------------------------------------------------------------------

class TestGivenSelectiveEnforcementOnToolsCall:
    def test_when_initialize_sent_with_pdp_denying_then_passes_through(self):
        """PDP configured to deny. initialize must still pass (PDP not called)."""
        configure_pdp(decision=False)
        r = requests.post(f"{APISIX_PROXY}/mcp",
                          json=mcp_body("initialize", {
                              "protocolVersion": "2024-11-05",
                              "capabilities": {},
                          }),
                          headers=bearer(make_jwt()))
        assert r.status_code == 200
        assert pdp_state()["call_count"] == 0

    def test_when_tools_list_sent_with_pdp_denying_then_passes_through(self):
        configure_pdp(decision=False)
        r = requests.post(f"{APISIX_PROXY}/mcp",
                          json=mcp_body("tools/list"),
                          headers=bearer(make_jwt()))
        assert r.status_code == 200
        assert pdp_state()["call_count"] == 0

    def test_when_resources_list_sent_with_pdp_denying_then_passes_through(self):
        configure_pdp(decision=False)
        r = requests.post(f"{APISIX_PROXY}/mcp",
                          json=mcp_body("resources/list"),
                          headers=bearer(make_jwt()))
        assert r.status_code == 200
        assert pdp_state()["call_count"] == 0

    def test_when_sse_get_sent_with_pdp_denying_then_passes_through(self):
        """GET (SSE connection) must bypass PDP regardless of enforce_on."""
        configure_pdp(decision=False)
        r = requests.get(f"{APISIX_PROXY}/mcp", headers=bearer(make_jwt()))
        assert r.status_code == 200
        assert pdp_state()["call_count"] == 0

    def test_when_delete_sent_with_pdp_denying_then_passes_through(self):
        """DELETE (session termination) must bypass PDP."""
        configure_pdp(decision=False)
        r = requests.delete(f"{APISIX_PROXY}/mcp", headers=bearer(make_jwt()))
        assert r.status_code == 200
        assert pdp_state()["call_count"] == 0


# ---------------------------------------------------------------------------
# AuthZEN spec compliance — structure of requests sent to the PDP
# ---------------------------------------------------------------------------

class TestGivenAuthZENSpecCompliance:
    """Verifies spec-compliant AuthZEN requests across both MCP route configurations.
    The mock PDP enforces the schema with Pydantic; a 400 response surfaces as 503."""

    def test_when_tools_call_sent_on_mcp_route_then_pdp_receives_spec_compliant_request(self):
        """MCP-aware config: resource is the tool, action is 'execute'."""
        configure_pdp(decision=True)
        requests.post(f"{APISIX_PROXY}/mcp",
                      json=mcp_body("tools/call", {
                          "name": "fintech_list_expenses",
                          "arguments": {"tenant": "tenant1"},
                      }),
                      headers=bearer(make_jwt(sub="alice@example.com")))
        req = pdp_state()["last_request"]
        assert isinstance(req.get("subject"), dict)
        assert req["subject"]["id"] == "alice@example.com"
        assert isinstance(req.get("resource"), dict)
        assert req["resource"]["id"] == "fintech_list_expenses"
        assert req["resource"]["type"] == "tool"
        assert isinstance(req.get("action"), dict)
        assert req["action"]["name"] == "execute"

    def test_when_tools_call_sent_on_strict_route_then_pdp_receives_spec_compliant_request(self):
        """Gateway config on MCP endpoint: resource is the URI, action is the HTTP method."""
        configure_pdp(decision=True)
        requests.post(f"{APISIX_PROXY}/mcp-strict",
                      json=mcp_body("tools/call", {
                          "name": "fintech_list_expenses",
                          "arguments": {"tenant": "tenant1"},
                      }),
                      headers=bearer(make_jwt(sub="alice@example.com")))
        req = pdp_state()["last_request"]
        assert isinstance(req.get("subject"), dict)
        assert req["subject"]["id"] == "alice@example.com"
        assert isinstance(req.get("resource"), dict)
        assert req["resource"]["id"] == "/mcp-strict"
        assert req["resource"]["type"] == "route"
        assert isinstance(req.get("action"), dict)
        assert req["action"]["name"] == "POST"


# ---------------------------------------------------------------------------
# Strict mode (no enforce_on) — all methods enforced
# ---------------------------------------------------------------------------

class TestGivenNoEnforceOnConfigured:
    def test_when_tools_call_sent_pdp_denies_then_returns_403(self):
        configure_pdp(decision=False)
        r = requests.post(f"{APISIX_PROXY}/mcp-strict",
                          json=mcp_body("tools/call", {
                              "name": "fintech_list_expenses",
                              "arguments": {"tenant": "tenant1"},
                          }),
                          headers=bearer(make_jwt()))
        assert r.status_code == 403

    def test_when_initialize_sent_pdp_denies_then_returns_403(self):
        """Without enforce_on, even initialize is enforced."""
        configure_pdp(decision=False)
        r = requests.post(f"{APISIX_PROXY}/mcp-strict",
                          json=mcp_body("initialize", {
                              "protocolVersion": "2024-11-05",
                              "capabilities": {},
                          }),
                          headers=bearer(make_jwt()))
        assert r.status_code == 403

    def test_when_tools_list_sent_pdp_denies_then_returns_403(self):
        configure_pdp(decision=False)
        r = requests.post(f"{APISIX_PROXY}/mcp-strict",
                          json=mcp_body("tools/list"),
                          headers=bearer(make_jwt()))
        assert r.status_code == 403

    def test_when_pdp_allows_all_methods_then_returns_200(self):
        configure_pdp(decision=True)
        for method, params in [
            ("tools/call", {"name": "fintech_list_expenses", "arguments": {"tenant": "t1"}}),
            ("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}}),
            ("tools/list", {}),
        ]:
            r = requests.post(f"{APISIX_PROXY}/mcp-strict",
                              json=mcp_body(method, params),
                              headers=bearer(make_jwt()))
            assert r.status_code == 200, f"Expected 200 for {method}, got {r.status_code}"
