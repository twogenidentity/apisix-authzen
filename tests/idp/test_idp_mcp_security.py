from __future__ import annotations

"""
IDP integration tests — Keycloak + openid-connect + authzen.

Full security chain under test:
  Keycloak issues JWT → APISIX openid-connect validates signature → authzen enforces PDP decision

Routes created once per module:
  /mcp-idp      — openid-connect + authzen with MCP selective enforcement (tools/call only)
  /api-idp/test — openid-connect + authzen for plain REST
"""

import time

import pytest
import requests

from helpers import (
    APISIX_PROXY,
    KEYCLOAK,
    MOCK_PDP,
    admin_delete,
    admin_put,
    bearer,
    configure_pdp,
    get_token,
    pdp_state,
)

_OIDC_PLUGIN = {
    "discovery": "http://keycloak:8080/realms/test/.well-known/openid-configuration",
    "client_id": "test-client",
    "client_secret": "test-secret",
    "bearer_only": True,
    "realm": "test",
}

_AUTHZEN_MCP = {
    "pdp": {"host": "http://mock-pdp:8080"},
    "mcp": {"enforce_on": {"methods": ["tools/call"]}},
    "subject": {
        "type": "user",
        "id": "claim::sub",
        "properties": [
            {"key": "roles", "claim": "realm_access.roles"},
        ],
    },
    "resource": {"type": "tool", "id": "mcp::tool::name"},
    "action": {"name": "execute"},
}

_AUTHZEN_API = {
    "pdp": {"host": "http://mock-pdp:8080"},
}

_UPSTREAM_MCP  = {"nodes": {"mock-mcp-upstream:8001": 1}, "type": "roundrobin"}
_UPSTREAM_NGINX = {"nodes": {"upstream:80": 1}, "type": "roundrobin"}


def mcp_body(method: str, params: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}


@pytest.fixture(scope="module", autouse=True)
def idp_routes():
    admin_put("/apisix/admin/routes/idp-mcp", {
        "uri": "/mcp-idp",
        "methods": ["GET", "POST", "DELETE"],
        "upstream": _UPSTREAM_MCP,
        "plugins": {
            "proxy-rewrite": {"uri": "/mcp"},
            "openid-connect": _OIDC_PLUGIN,
            "authzen": _AUTHZEN_MCP,
        },
    })
    admin_put("/apisix/admin/routes/idp-api", {
        "uri": "/api-idp/test",
        "methods": ["GET", "POST"],
        "upstream": _UPSTREAM_NGINX,
        "plugins": {
            "openid-connect": _OIDC_PLUGIN,
            "authzen": _AUTHZEN_API,
        },
    })
    time.sleep(1)
    yield
    admin_delete("/apisix/admin/routes/idp-mcp")
    admin_delete("/apisix/admin/routes/idp-api")


# ---------------------------------------------------------------------------
# Stack configuration checks — run first, fail fast with clear messages
# ---------------------------------------------------------------------------

class TestGivenKeycloakIsBootstrapped:
    """Verify that the IDP stack is correctly configured before any auth tests run.

    These tests catch bootstrap failures early and produce clear error messages
    instead of cascading 400/401 failures from the actual test classes.
    """

    def test_when_realm_endpoint_called_then_returns_200(self):
        """Realm 'test' must be present and accessible."""
        r = requests.get(f"{KEYCLOAK}/realms/test", timeout=10)
        assert r.status_code == 200, (
            f"Keycloak realm 'test' not found ({r.status_code}). "
            "Bootstrap container may have failed — check: docker logs idp-keycloak-bootstrap-1"
        )

    def test_when_discovery_endpoint_called_then_returns_oidc_metadata(self):
        """OIDC discovery endpoint must be reachable for openid-connect plugin."""
        r = requests.get(
            f"{KEYCLOAK}/realms/test/.well-known/openid-configuration", timeout=10
        )
        assert r.status_code == 200
        data = r.json()
        assert "token_endpoint" in data
        assert "jwks_uri" in data

    def test_when_alice_authenticates_then_receives_token(self):
        """alice/alice123 must authenticate successfully via ROPC flow."""
        try:
            token = get_token("alice", "alice123")
            assert token, "Empty token returned"
        except Exception as exc:
            pytest.fail(
                f"alice cannot get a token: {exc}. "
                "Possible cause: user missing firstName/lastName/email in bootstrap.sh "
                "or directAccessGrantsEnabled not set on client."
            )

    def test_when_bob_authenticates_then_receives_token(self):
        """bob/bob123 must authenticate successfully via ROPC flow."""
        try:
            token = get_token("bob", "bob123")
            assert token, "Empty token returned"
        except Exception as exc:
            pytest.fail(f"bob cannot get a token: {exc}.")

    def test_when_alice_token_decoded_then_contains_mcp_user_role(self):
        """alice's token must carry mcp-user role in realm_access.roles."""
        import base64, json as _json
        token = get_token("alice", "alice123")
        payload_b64 = token.split(".")[1]
        # pad to multiple of 4
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = _json.loads(base64.urlsafe_b64decode(payload_b64))
        roles = payload.get("realm_access", {}).get("roles", [])
        assert "mcp-user" in roles, f"mcp-user role missing from token. roles={roles}"

    def test_when_pdp_health_endpoint_called_then_returns_200(self):
        """mock-pdp must respond to health check."""
        r = requests.get(f"{MOCK_PDP}/health", timeout=5)
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Token validation (openid-connect layer)
# ---------------------------------------------------------------------------

class TestGivenOpenIDConnectValidation:
    def test_when_no_token_sent_then_returns_401(self):
        r = requests.get(f"{APISIX_PROXY}/api-idp/test")
        assert r.status_code == 401

    def test_when_forged_jwt_sent_then_returns_401(self):
        """A JWT with a valid structure but wrong signature must be rejected."""
        forged = (
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiJoYWNrZXIiLCJpYXQiOjE3MDAwMDAwMDB9"
            ".invalidsignatureXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        )
        r = requests.get(f"{APISIX_PROXY}/api-idp/test",
                         headers=bearer(forged))
        assert r.status_code == 401

    def test_when_valid_keycloak_token_and_pdp_allows_then_returns_200(self):
        """Real Keycloak token + PDP allows → request forwarded (200)."""
        configure_pdp(decision=True)
        token = get_token("alice", "alice123")
        r = requests.get(f"{APISIX_PROXY}/api-idp/test", headers=bearer(token))
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# MCP enforcement with real Keycloak tokens
# ---------------------------------------------------------------------------

class TestGivenToolsCallEnforcedWithKeycloakToken:
    def test_when_pdp_allows_then_returns_200(self):
        configure_pdp(decision=True)
        token = get_token("alice", "alice123")
        r = requests.post(
            f"{APISIX_PROXY}/mcp-idp",
            json=mcp_body("tools/call", {
                "name": "fintech_list_expenses",
                "arguments": {"tenant": "tenant1"},
            }),
            headers=bearer(token),
        )
        assert r.status_code == 200

    def test_when_pdp_denies_then_returns_403(self):
        configure_pdp(decision=False)
        token = get_token("alice", "alice123")
        r = requests.post(
            f"{APISIX_PROXY}/mcp-idp",
            json=mcp_body("tools/call", {
                "name": "fintech_list_expenses",
                "arguments": {"tenant": "tenant1"},
            }),
            headers=bearer(token),
        )
        assert r.status_code == 403

    def test_when_tools_call_sent_then_pdp_receives_keycloak_sub_as_subject_id(self):
        """AuthZEN subject.id must be the Keycloak user's sub claim."""
        configure_pdp(decision=True)
        token = get_token("alice", "alice123")
        requests.post(
            f"{APISIX_PROXY}/mcp-idp",
            json=mcp_body("tools/call", {
                "name": "fintech_list_expenses",
                "arguments": {"tenant": "tenant1"},
            }),
            headers=bearer(token),
        )
        state = pdp_state()
        # sub is a UUID assigned by Keycloak — just verify it's a non-empty string
        assert state["last_request"]["subject"]["id"]
        assert state["last_request"]["subject"]["type"] == "user"

    def test_when_tools_call_sent_then_pdp_receives_realm_roles_as_subject_properties(self):
        """realm_access.roles from Keycloak JWT must appear in AuthZEN subject.properties."""
        configure_pdp(decision=True)
        token = get_token("alice", "alice123")
        requests.post(
            f"{APISIX_PROXY}/mcp-idp",
            json=mcp_body("tools/call", {
                "name": "fintech_list_expenses",
                "arguments": {"tenant": "tenant1"},
            }),
            headers=bearer(token),
        )
        state = pdp_state()
        roles = state["last_request"]["subject"].get("properties", {}).get("roles", [])
        assert "mcp-user" in roles

    def test_when_pdp_returns_error_then_returns_503(self):
        configure_pdp(simulate="error")
        token = get_token("alice", "alice123")
        r = requests.post(
            f"{APISIX_PROXY}/mcp-idp",
            json=mcp_body("tools/call", {
                "name": "fintech_list_expenses",
                "arguments": {"tenant": "tenant1"},
            }),
            headers=bearer(token),
        )
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# Selective enforcement — non-enforced MCP methods bypass PDP
# ---------------------------------------------------------------------------

class TestGivenSelectiveEnforcementWithKeycloakToken:
    def test_when_initialize_sent_with_pdp_denying_then_passes_through(self):
        """PDP configured to deny; initialize must still pass (PDP not called)."""
        configure_pdp(decision=False)
        token = get_token("alice", "alice123")
        r = requests.post(
            f"{APISIX_PROXY}/mcp-idp",
            json=mcp_body("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
            }),
            headers=bearer(token),
        )
        assert r.status_code == 200
        assert pdp_state()["call_count"] == 0

    def test_when_tools_list_sent_with_pdp_denying_then_passes_through(self):
        configure_pdp(decision=False)
        token = get_token("alice", "alice123")
        r = requests.post(
            f"{APISIX_PROXY}/mcp-idp",
            json=mcp_body("tools/list"),
            headers=bearer(token),
        )
        assert r.status_code == 200
        assert pdp_state()["call_count"] == 0

    def test_when_sse_get_sent_with_pdp_denying_then_passes_through(self):
        """GET (SSE connection) must bypass PDP even with a valid token."""
        configure_pdp(decision=False)
        token = get_token("alice", "alice123")
        r = requests.get(f"{APISIX_PROXY}/mcp-idp", headers=bearer(token))
        assert r.status_code == 200
        assert pdp_state()["call_count"] == 0

    def test_when_no_token_on_initialize_then_returns_401(self):
        """Token is always required — even for non-enforced MCP methods."""
        r = requests.post(
            f"{APISIX_PROXY}/mcp-idp",
            json=mcp_body("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
            }),
        )
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# Plain REST API with real tokens
# ---------------------------------------------------------------------------

class TestGivenPlainAPIRouteWithKeycloakToken:
    def test_when_alice_token_and_pdp_allows_then_returns_200(self):
        configure_pdp(decision=True)
        token = get_token("alice", "alice123")
        r = requests.get(f"{APISIX_PROXY}/api-idp/test", headers=bearer(token))
        assert r.status_code == 200

    def test_when_bob_token_and_pdp_denies_then_returns_403(self):
        configure_pdp(decision=False)
        token = get_token("bob", "bob123")
        r = requests.get(f"{APISIX_PROXY}/api-idp/test", headers=bearer(token))
        assert r.status_code == 403

    def test_when_no_token_sent_then_returns_401(self):
        r = requests.get(f"{APISIX_PROXY}/api-idp/test")
        assert r.status_code == 401
