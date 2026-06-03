from __future__ import annotations

import os

"""
IDP integration tests — Keycloak AuthZEN as real PDP.

Full security chain under test:
  Keycloak (demo realm) issues JWT → APISIX openid-connect validates signature
  → authzen plugin calls Keycloak AuthZEN endpoint as the real PDP
  → Keycloak evaluates Authorization Services policies and returns decision

No mock-pdp is involved; all authorization decisions come from Keycloak.

Routes created once per module:
  /authzen-todos/read   — todos resource, can_read_todos scope  (admin + viewer)
  /authzen-todos/create — todos resource, can_create_todo scope (admin only)

Playground setup (bootstrap-authzen.sh):
  rick  → admin role  → can_read_todos + can_create_todo
  jerry → viewer role → can_read_todos only
"""

import time

import pytest
import requests

from helpers import (
    APISIX_PROXY,
    KEYCLOAK_AUTHZEN,
    admin_delete,
    admin_put,
    bearer,
    get_service_account_token_authzen,
    get_token_authzen,
    set_client_enabled,
)

_OIDC_AUTHZEN_PLUGIN = {
    "discovery": "http://keycloak-authzen:8080/realms/demo/.well-known/openid-configuration",
    "client_id": "demo-client",
    "client_secret": "demo-secret",
    "bearer_only": True,
    "realm": "demo",
}

_UPSTREAM_NGINX = {"nodes": {"upstream:80": 1}, "type": "roundrobin"}


@pytest.fixture(scope="module", autouse=True)
def authzen_routes():
    """Create APISIX routes pointing at Keycloak AuthZEN as the real PDP.

    A service account token is fetched once per module — valid for 3600 s (configured
    in bootstrap-authzen.sh) and refreshed automatically on the next test run.
    """
    sa_token = get_service_account_token_authzen()
    pdp_host = "http://keycloak-authzen:8080/realms/demo/authzen"

    admin_put("/apisix/admin/routes/authzen-read", {
        "uri": "/authzen-todos/read",
        "methods": ["GET"],
        "upstream": _UPSTREAM_NGINX,
        "plugins": {
            "openid-connect": _OIDC_AUTHZEN_PLUGIN,
            "authzen": {
                "pdp": {
                    "host": pdp_host,
                    "auth": {
                        "api_key": f"Bearer {sa_token}",
                    },
                },
#                "subject" : { "type": "user", "id": "email:jerry@demo.local" },
                "subject" : { "type": "user", "id": "claim::preferred_username" },
                "resource": {"id": "todo-1", "type": "todo"},
                "action": {"name": "can_read_todos"},
            },
        },
    })

    admin_put("/apisix/admin/routes/authzen-create", {
        "uri": "/authzen-todos/create",
        "methods": ["POST"],
        "upstream": _UPSTREAM_NGINX,
        "plugins": {
            "openid-connect": _OIDC_AUTHZEN_PLUGIN,
            "authzen": {
                "pdp": {
                    "host": pdp_host,
                    "auth": {
                        "api_key": f"Bearer {sa_token}",
                    },
                },
#                 "subject" : { "type": "user", "id": "email:jerry@demo.local" },
                 "subject" : { "type": "user", "id": "claim::preferred_username" },
                "resource": {"id": "todo-1", "type": "todo"},
                "action": {"name": "can_create_todo"},
            },
        },
    })
    

    time.sleep(1)
    yield
    admin_delete("/apisix/admin/routes/authzen-read")
    admin_delete("/apisix/admin/routes/authzen-create")


# ---------------------------------------------------------------------------
# Stack configuration checks — fail fast with clear messages
# ---------------------------------------------------------------------------

class TestGivenKeycloakAuthZENIsBootstrapped:
    """Verify keycloak-authzen + bootstrap-authzen.sh ran correctly."""

    def test_when_demo_realm_endpoint_called_then_returns_200(self):
        """Realm 'demo' must be present and accessible."""
        r = requests.get(f"{KEYCLOAK_AUTHZEN}/realms/demo", timeout=10)
        assert r.status_code == 200, (
            f"Keycloak AuthZEN realm 'demo' not found ({r.status_code}). "
            "Bootstrap may have failed — check: docker logs idp-keycloak-authzen-bootstrap-1"
        )

    def test_when_discovery_endpoint_called_then_returns_oidc_metadata(self):
        r = requests.get(
            f"{KEYCLOAK_AUTHZEN}/realms/demo/.well-known/openid-configuration", timeout=10
        )
        assert r.status_code == 200
        data = r.json()
        assert "token_endpoint" in data
        assert "jwks_uri" in data

    def test_when_rick_authenticates_then_receives_token(self):
        try:
            token = get_token_authzen("rick", "rick123")
            assert token, "Empty token returned"
        except Exception as exc:
            pytest.fail(
                f"rick cannot get a token: {exc}. "
                "Check directAccessGrantsEnabled on demo-client and user in bootstrap-authzen.sh."
            )

    def test_when_jerry_authenticates_then_receives_token(self):
        try:
            token = get_token_authzen("jerry", "jerry123")
            assert token, "Empty token returned"
        except Exception as exc:
            pytest.fail(f"jerry cannot get a token: {exc}.")

    def test_when_rick_token_decoded_then_contains_admin_role(self):
        import base64, json as _json
        token = get_token_authzen("rick", "rick123")
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = _json.loads(base64.urlsafe_b64decode(payload_b64))
        roles = payload.get("realm_access", {}).get("roles", [])
        assert "admin" in roles, f"admin role missing from rick's token. roles={roles}"

    def test_when_jerry_token_decoded_then_contains_viewer_role(self):
        import base64, json as _json
        token = get_token_authzen("jerry", "jerry123")
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = _json.loads(base64.urlsafe_b64decode(payload_b64))
        roles = payload.get("realm_access", {}).get("roles", [])
        assert "viewer" in roles, f"viewer role missing from jerry's token. roles={roles}"

    def test_when_authzen_endpoint_called_with_service_account_then_responds(self):
        """Keycloak AuthZEN evaluation endpoint must be reachable with a valid token."""
        sa_token = get_service_account_token_authzen()
        r = requests.post(
            f"{KEYCLOAK_AUTHZEN}/realms/demo/authzen/access/v1/evaluation",
            headers={
                "Authorization": f"Bearer {sa_token}",
                "Content-Type": "application/json",
            },
            json={
                "subject": {"id": "probe"},
                "resource": {"id": "todos"},
                "action": {"name": "can_read_todos"},
            },
            timeout=10,
        )
        # 200 (allow/deny) or 4xx (auth error) both confirm the endpoint exists
        assert r.status_code != 404, (
            "Keycloak AuthZEN endpoint not found. "
            "Ensure KC_FEATURES=authzen is set on keycloak-authzen service."
        )


# ---------------------------------------------------------------------------
# Rick (admin role) — can read AND create
# ---------------------------------------------------------------------------

class TestGivenRickHasAdminRole:
    def test_when_no_token_sent_then_returns_401(self):
        r = requests.get(f"{APISIX_PROXY}/authzen-todos/read")
        assert r.status_code == 401

    def test_when_reads_todos_then_keycloak_authzen_allows_and_returns_200(self):
        """rick has admin role → can_read_todos permission → Keycloak grants."""
        token = get_token_authzen("rick", "rick123")
        r = requests.get(f"{APISIX_PROXY}/authzen-todos/read", headers=bearer(token))
        assert r.status_code == 200, (
            f"Expected 200 (rick has admin role, admin can read todos). Got {r.status_code}. "
            f"Response: {r.text[:300]}"
        )

    def test_when_creates_todo_then_keycloak_authzen_allows_and_returns_200(self):
        """rick has admin role → can_create_todo permission → Keycloak grants."""
        token = get_token_authzen("rick", "rick123")
        r = requests.post(
            f"{APISIX_PROXY}/authzen-todos/create",
            headers=bearer(token),
            json={"title": "Buy milk"},
        )
        assert r.status_code == 200, (
            f"Expected 200 (rick has admin role, admin can create todos). Got {r.status_code}. "
            f"Response: {r.text[:300]}"
        )


# ---------------------------------------------------------------------------
# Jerry (viewer role) — can read, cannot create
# ---------------------------------------------------------------------------

class TestGivenJerryHasViewerRole:
    def test_when_no_token_sent_then_returns_401(self):
        r = requests.get(f"{APISIX_PROXY}/authzen-todos/read")
        assert r.status_code == 401

    def test_when_reads_todos_then_keycloak_authzen_allows_and_returns_200(self):
        """jerry has viewer role → can_read_todos permission → Keycloak grants."""
        token = get_token_authzen("jerry", "jerry123")
        r = requests.get(f"{APISIX_PROXY}/authzen-todos/read", headers=bearer(token))
        assert r.status_code == 200, (
            f"Expected 200 (jerry has viewer role, viewer can read todos). Got {r.status_code}. "
            f"Response: {r.text[:300]}"
        )

    def test_when_creates_todo_then_keycloak_authzen_denies_and_returns_403(self):
        """jerry has viewer role → no can_create_todo permission → Keycloak denies."""
        token = get_token_authzen("jerry", "jerry123")
        r = requests.post(
            f"{APISIX_PROXY}/authzen-todos/create",
            headers=bearer(token),
            json={"title": "Buy milk"},
        )
        assert r.status_code == 403, (
            f"Expected 403 (jerry has viewer role, viewer cannot create todos). Got {r.status_code}. "
            f"Response: {r.text[:300]}"
        )


# ---------------------------------------------------------------------------
# OAuth2 client_credentials PDP auth — gateway-client (20 s token lifetime)
# ---------------------------------------------------------------------------

_GATEWAY_TOKEN_URL = "http://keycloak-authzen:8080/realms/demo/protocol/openid-connect/token"
_GATEWAY_PDP_HOST  = "http://keycloak-authzen:8080/realms/demo/authzen"


@pytest.fixture(scope="module")
def oauth2_routes():
    """Route that uses pdp.auth.oauth2 (gateway-client) instead of a static api_key."""
    admin_put("/apisix/admin/routes/authzen-oauth2-read", {
        "uri": "/authzen-todos/oauth2-read",
        "methods": ["GET"],
        "upstream": _UPSTREAM_NGINX,
        "plugins": {
            "openid-connect": _OIDC_AUTHZEN_PLUGIN,
            "authzen": {
                "pdp": {
                    "host": _GATEWAY_PDP_HOST,
                    "auth": {
                        "oauth2": {
                            "token_url":     _GATEWAY_TOKEN_URL,
                            "client_id":     "gateway-client",
                            "client_secret": "gateway-secret",
                        },
                    },
                },
                "subject":  {"type": "user", "id": "claim::preferred_username"},
                "resource": {"id": "todo-1", "type": "todo"},
                "action":   {"name": "can_read_todos"},
            },
        },
    })
    time.sleep(1)
    yield
    admin_delete("/apisix/admin/routes/authzen-oauth2-read")


class TestGivenOAuth2PdpAuth:
    """Verify pdp.auth.oauth2 fetches, caches, and renews tokens automatically.

    gateway-client is configured with access.token.lifespan=20 s.
    Plugin cache TTL = 20 - 10 = 10 s.
    """

    def test_when_oauth2_configured_then_rick_can_read_todos(self, oauth2_routes):
        """APISIX fetches a gateway-client token and calls AuthZEN — rick is allowed."""
        token = get_token_authzen("rick", "rick123")
        r = requests.get(
            f"{APISIX_PROXY}/authzen-todos/oauth2-read",
            headers=bearer(token),
        )
        assert r.status_code == 200, (
            f"Expected 200 (OAuth2 PDP auth, rick has admin role). Got {r.status_code}. "
            f"Response: {r.text[:300]}"
        )

    @pytest.mark.skipif(
        os.getenv("SKIP_SLOW") == "1",
        reason="token renewal test (~12 s), set SKIP_SLOW=1 to skip",
    )
    def test_when_oauth2_token_expires_then_renews_automatically(self, oauth2_routes):
        """Cache TTL is 10 s. After sleeping 12 s the plugin must re-fetch a fresh token."""
        token = get_token_authzen("rick", "rick123")

        r1 = requests.get(
            f"{APISIX_PROXY}/authzen-todos/oauth2-read",
            headers=bearer(token),
        )
        assert r1.status_code == 200, f"First request failed: {r1.status_code} {r1.text[:300]}"

        time.sleep(12)  # outlast the 10 s cache TTL

        r2 = requests.get(
            f"{APISIX_PROXY}/authzen-todos/oauth2-read",
            headers=bearer(token),
        )
        assert r2.status_code == 200, (
            f"Expected 200 after automatic token renewal (cache expired). "
            f"Got {r2.status_code}. Response: {r2.text[:300]}"
        )

    @pytest.mark.skipif(
        os.getenv("SKIP_SLOW") == "1",
        reason="token renewal failure test (~12 s), set SKIP_SLOW=1 to skip",
    )
    def test_when_oauth2_renewal_fails_then_returns_503(self, oauth2_routes):
        """
        First request succeeds (token fetched and cached for 10 s).
        While the token is still cached, gateway-client is disabled in Keycloak.
        After the cache expires APISIX tries to renew — the token endpoint rejects
        the disabled client → plugin returns 503.
        """
        token = get_token_authzen("rick", "rick123")

        r1 = requests.get(
            f"{APISIX_PROXY}/authzen-todos/oauth2-read",
            headers=bearer(token),
        )
        assert r1.status_code == 200, f"First request failed: {r1.status_code} {r1.text[:300]}"

        set_client_enabled("gateway-client", False)
        try:
            time.sleep(12)  # outlast the 10 s cache TTL

            r2 = requests.get(
                f"{APISIX_PROXY}/authzen-todos/oauth2-read",
                headers=bearer(token),
            )
            assert r2.status_code == 503, (
                f"Expected 503 when OAuth2 token renewal fails (gateway-client disabled). "
                f"Got {r2.status_code}. Response: {r2.text[:300]}"
            )
        finally:
            set_client_enabled("gateway-client", True)
