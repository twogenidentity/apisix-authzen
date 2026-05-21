"""
API security tests for the authzen APISIX plugin.

Routes created here:
  /api/test            — standard route, PDP = mock-pdp
  /api/test-timeout    — same plugin, 500 ms timeout (for slow-PDP test)
  /api/test-unreachable — PDP host does not exist (connection failure)
"""

import time

import pytest
import requests

from helpers import (
    APISIX_PROXY,
    admin_delete,
    admin_put,
    bearer,
    configure_pdp,
    make_jwt,
    pdp_state,
)

_AUTHZEN_PLUGIN = {
    "pdp": {"host": "http://mock-pdp:8080"},
}

_UPSTREAM = {
    "nodes": {"upstream:80": 1},
    "type": "roundrobin",
}


@pytest.fixture(scope="module", autouse=True)
def api_routes():
    admin_put("/apisix/admin/routes/api-test", {
        "uri": "/api/test",
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "upstream": _UPSTREAM,
        "plugins": {"authzen": _AUTHZEN_PLUGIN},
    })
    admin_put("/apisix/admin/routes/api-test-timeout", {
        "uri": "/api/test-timeout",
        "methods": ["GET"],
        "upstream": _UPSTREAM,
        "plugins": {"authzen": {
            "pdp": {"host": "http://mock-pdp:8080"},
            "http": {"timeout": 500},
        }},
    })
    admin_put("/apisix/admin/routes/api-test-unreachable", {
        "uri": "/api/test-unreachable",
        "methods": ["GET"],
        "upstream": _UPSTREAM,
        "plugins": {"authzen": {
            "pdp": {"host": "http://no-such-pdp-host:9999"},
        }},
    })
    time.sleep(1)  # let APISIX propagate routes from etcd
    yield
    for route_id in ("api-test", "api-test-timeout", "api-test-unreachable"):
        admin_delete(f"/apisix/admin/routes/{route_id}")


# ---------------------------------------------------------------------------
# Missing / malformed bearer token → 401
# ---------------------------------------------------------------------------

class TestGivenNoBearerToken:
    def test_when_no_auth_header_then_returns_401(self):
        r = requests.get(f"{APISIX_PROXY}/api/test")
        assert r.status_code == 401

    def test_when_non_bearer_scheme_used_then_returns_401(self):
        r = requests.get(f"{APISIX_PROXY}/api/test",
                         headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert r.status_code == 401

    def test_when_bearer_value_is_empty_then_returns_401(self):
        r = requests.get(f"{APISIX_PROXY}/api/test",
                         headers={"Authorization": "Bearer "})
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# PDP decision enforcement
# ---------------------------------------------------------------------------

class TestGivenPDPEnforcement:
    def test_when_pdp_allows_get_then_returns_200(self):
        configure_pdp(decision=True)
        r = requests.get(f"{APISIX_PROXY}/api/test", headers=bearer(make_jwt()))
        assert r.status_code == 200

    def test_when_pdp_denies_get_then_returns_403(self):
        configure_pdp(decision=False)
        r = requests.get(f"{APISIX_PROXY}/api/test", headers=bearer(make_jwt()))
        assert r.status_code == 403

    def test_when_pdp_allows_post_then_returns_200(self):
        configure_pdp(decision=True)
        r = requests.post(f"{APISIX_PROXY}/api/test",
                          json={"data": "test"},
                          headers=bearer(make_jwt()))
        assert r.status_code == 200

    def test_when_pdp_denies_post_then_returns_403(self):
        configure_pdp(decision=False)
        r = requests.post(f"{APISIX_PROXY}/api/test",
                          json={"data": "test"},
                          headers=bearer(make_jwt()))
        assert r.status_code == 403

    def test_when_pdp_denies_put_then_returns_403(self):
        configure_pdp(decision=False)
        r = requests.put(f"{APISIX_PROXY}/api/test",
                         json={"data": "test"},
                         headers=bearer(make_jwt()))
        assert r.status_code == 403

    def test_when_pdp_denies_delete_then_returns_403(self):
        configure_pdp(decision=False)
        r = requests.delete(f"{APISIX_PROXY}/api/test",
                            headers=bearer(make_jwt()))
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# AuthZEN request shape sent to PDP
# ---------------------------------------------------------------------------

class TestGivenAuthZENRequestBuilding:
    def test_when_jwt_has_sub_claim_then_pdp_receives_it_as_subject_id(self):
        configure_pdp(decision=True)
        token = make_jwt(sub="alice@example.com")
        requests.get(f"{APISIX_PROXY}/api/test", headers=bearer(token))
        state = pdp_state()
        assert state["last_request"]["subject"]["id"] == "alice@example.com"

    def test_when_get_sent_then_pdp_receives_uri_as_resource_id(self):
        configure_pdp(decision=True)
        requests.get(f"{APISIX_PROXY}/api/test", headers=bearer(make_jwt()))
        state = pdp_state()
        assert state["last_request"]["resource"]["id"] == "/api/test"

    def test_when_get_sent_then_pdp_receives_get_as_action_name(self):
        configure_pdp(decision=True)
        requests.get(f"{APISIX_PROXY}/api/test", headers=bearer(make_jwt()))
        state = pdp_state()
        assert state["last_request"]["action"]["name"] == "GET"

    def test_when_post_sent_then_pdp_receives_post_as_action_name(self):
        configure_pdp(decision=True)
        requests.post(f"{APISIX_PROXY}/api/test",
                      json={},
                      headers=bearer(make_jwt()))
        state = pdp_state()
        assert state["last_request"]["action"]["name"] == "POST"


# ---------------------------------------------------------------------------
# AuthZEN spec compliance — structure of requests sent to the PDP
# ---------------------------------------------------------------------------

class TestGivenAuthZENSpecCompliance:
    """Verifies that every request the plugin sends to the PDP is structurally
    valid per the AuthZEN evaluation request spec (subject.id, action.name required;
    resource object required). The mock PDP enforces this with Pydantic — a 400
    from the PDP would surface as 503 here, failing the test immediately."""

    def test_when_get_sent_then_pdp_receives_spec_compliant_request(self):
        configure_pdp(decision=True)
        requests.get(f"{APISIX_PROXY}/api/test",
                     headers=bearer(make_jwt(sub="alice@example.com")))
        req = pdp_state()["last_request"]
        assert isinstance(req.get("subject"), dict)
        assert req["subject"]["id"] == "alice@example.com"
        assert isinstance(req.get("resource"), dict)
        assert req["resource"]["id"] == "/api/test"
        assert isinstance(req.get("action"), dict)
        assert req["action"]["name"] == "GET"

    def test_when_post_sent_then_pdp_receives_spec_compliant_request(self):
        configure_pdp(decision=True)
        requests.post(f"{APISIX_PROXY}/api/test",
                      json={"data": "test"},
                      headers=bearer(make_jwt(sub="bob@example.com")))
        req = pdp_state()["last_request"]
        assert isinstance(req.get("subject"), dict)
        assert req["subject"]["id"] == "bob@example.com"
        assert isinstance(req.get("resource"), dict)
        assert req["resource"]["id"] == "/api/test"
        assert isinstance(req.get("action"), dict)
        assert req["action"]["name"] == "POST"


# ---------------------------------------------------------------------------
# PDP failure modes → 503
# ---------------------------------------------------------------------------

class TestGivenPDPUnavailable:
    def test_when_pdp_returns_500_then_returns_503(self):
        configure_pdp(simulate="error")
        r = requests.get(f"{APISIX_PROXY}/api/test", headers=bearer(make_jwt()))
        assert r.status_code == 503

    def test_when_pdp_host_unreachable_then_returns_503(self):
        r = requests.get(f"{APISIX_PROXY}/api/test-unreachable",
                         headers=bearer(make_jwt()))
        assert r.status_code == 503

    def test_when_pdp_response_times_out_then_returns_503(self):
        configure_pdp(simulate="slow")
        r = requests.get(f"{APISIX_PROXY}/api/test-timeout",
                         headers=bearer(make_jwt()),
                         timeout=10)
        assert r.status_code == 503
