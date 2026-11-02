from __future__ import annotations

"""
cel mapping_format tests for the authzen APISIX plugin.

Routes created here:
  POST /cel-mcp      — MCP tools/call mapped with $token / $params expressions
  GET  /cel-api/...  — plain API route, cel mode with all defaults

Key properties verified:
  - $token.<path>, $params.<path>, $request.uri|method resolve into the AuthZEN request
  - '.?' optional paths are omitted when missing; empty maps are omitted
  - '$$' escapes a literal '$'
  - missing required paths and non-string ids fail closed (401, PDP not called)
  - invalid expressions and cel-only fields in legacy mode are rejected by the Admin API
"""

import time

import pytest
import requests

from helpers import (
    ADMIN_KEY,
    APISIX_ADMIN,
    APISIX_PROXY,
    admin_delete,
    admin_put,
    bearer,
    configure_pdp,
    make_jwt,
    pdp_state,
)

_UPSTREAM = {
    "nodes": {"upstream:80": 1},
    "type": "roundrobin",
}

_AUTHZEN_CEL_MCP = {
    "pdp": {"host": "http://mock-pdp:8080"},
    "mapping_format": "cel",
    "subject": {
        "type": "user",
        "id": "$token.sub",
        "properties": {"roles": "$token.?realm_access.roles"},
    },
    "resource": {
        "type": "customer",
        "id": "$params.arguments.id",
        "properties": {"case": "$params.arguments.?case"},
    },
    "action": {"name": "$params.name"},
    "context": {
        "agent": "$token.?azp",
        "channel": "mcp",
        "price": "$$5",
    },
    "mcp": {"enforce_on": {"methods": ["tools/call"]}},
}

_AUTHZEN_CEL_API = {
    "pdp": {"host": "http://mock-pdp:8080"},
    "mapping_format": "cel",
}


def tools_call(name: str, arguments: dict) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}


def put_route_raw(route_id: str, authzen: dict) -> requests.Response:
    return requests.put(
        f"{APISIX_ADMIN}/apisix/admin/routes/{route_id}",
        json={"uri": f"/{route_id}", "upstream": _UPSTREAM, "plugins": {"authzen": authzen}},
        headers={"X-API-KEY": ADMIN_KEY},
    )


@pytest.fixture(scope="module", autouse=True)
def cel_routes():
    admin_put("/apisix/admin/routes/cel-mcp", {
        "uri": "/cel-mcp",
        "methods": ["POST"],
        "upstream": _UPSTREAM,
        "plugins": {"authzen": _AUTHZEN_CEL_MCP},
    })
    admin_put("/apisix/admin/routes/cel-api", {
        "uri": "/cel-api/*",
        "methods": ["GET", "POST"],
        "upstream": _UPSTREAM,
        "plugins": {"authzen": _AUTHZEN_CEL_API},
    })
    time.sleep(1)
    yield
    admin_delete("/apisix/admin/routes/cel-mcp")
    admin_delete("/apisix/admin/routes/cel-api")


# ---------------------------------------------------------------------------
# MCP mapping
# ---------------------------------------------------------------------------

class TestGivenCelMcpMapping:
    def test_when_all_values_present_then_pdp_receives_full_request(self):
        configure_pdp(decision=True)
        token = make_jwt(sub="alice@example.com", extra={
            "azp": "mcp-client",
            "realm_access": {"roles": ["support"]},
        })
        r = requests.post(f"{APISIX_PROXY}/cel-mcp",
                          json=tools_call("get_customer", {"id": "cust-12345", "case": "c-9"}),
                          headers=bearer(token))
        assert r.status_code == 200
        assert pdp_state()["last_request"] == {
            "subject": {"type": "user", "id": "alice@example.com",
                        "properties": {"roles": ["support"]}},
            "resource": {"type": "customer", "id": "cust-12345",
                         "properties": {"case": "c-9"}},
            "action": {"name": "get_customer"},
            "context": {"agent": "mcp-client", "channel": "mcp", "price": "$5"},
        }

    def test_when_optional_values_missing_then_they_are_omitted(self):
        configure_pdp(decision=True)
        r = requests.post(f"{APISIX_PROXY}/cel-mcp",
                          json=tools_call("get_customer", {"id": "cust-1"}),
                          headers=bearer(make_jwt(sub="bob")))
        assert r.status_code == 200
        req = pdp_state()["last_request"]
        assert "properties" not in req["subject"]
        assert "properties" not in req["resource"]
        assert req["context"] == {"channel": "mcp", "price": "$5"}

    def test_when_numeric_id_then_sent_as_string(self):
        configure_pdp(decision=True)
        requests.post(f"{APISIX_PROXY}/cel-mcp",
                      json=tools_call("get_customer", {"id": 12345}),
                      headers=bearer(make_jwt()))
        assert pdp_state()["last_request"]["resource"]["id"] == "12345"

    def test_when_pdp_denies_then_returns_403(self):
        configure_pdp(decision=False)
        r = requests.post(f"{APISIX_PROXY}/cel-mcp",
                          json=tools_call("get_customer", {"id": "cust-1"}),
                          headers=bearer(make_jwt()))
        assert r.status_code == 403

    def test_when_required_argument_missing_then_returns_401_without_calling_pdp(self):
        configure_pdp(decision=True)
        r = requests.post(f"{APISIX_PROXY}/cel-mcp",
                          json=tools_call("get_customer", {}),
                          headers=bearer(make_jwt()))
        assert r.status_code == 401
        assert "mapping error" in r.json()["message"]
        assert pdp_state()["call_count"] == 0

    def test_when_id_is_an_object_then_returns_401_without_calling_pdp(self):
        configure_pdp(decision=True)
        r = requests.post(f"{APISIX_PROXY}/cel-mcp",
                          json=tools_call("get_customer", {"id": {"nested": "x"}}),
                          headers=bearer(make_jwt()))
        assert r.status_code == 401
        assert pdp_state()["call_count"] == 0


# ---------------------------------------------------------------------------
# API route with cel defaults
# ---------------------------------------------------------------------------

class TestGivenCelApiDefaults:
    def test_when_get_then_pdp_receives_request_uri_and_method(self):
        configure_pdp(decision=True)
        r = requests.get(f"{APISIX_PROXY}/cel-api/orders",
                         headers=bearer(make_jwt(sub="carol")))
        assert r.status_code == 200
        assert pdp_state()["last_request"] == {
            "subject": {"type": "identity", "id": "carol"},
            "resource": {"type": "route", "id": "/cel-api/orders"},
            "action": {"name": "GET"},
        }


# ---------------------------------------------------------------------------
# Admin API schema validation
# ---------------------------------------------------------------------------

_PDP = {"host": "http://mock-pdp:8080"}


class TestGivenInvalidMappingConfig:
    @pytest.mark.parametrize("authzen", [
        pytest.param({"pdp": _PDP, "context": {"agent": "x"}}, id="context-in-legacy"),
        pytest.param({"pdp": _PDP, "resource": {"properties": {"a": "x"}}}, id="resource-properties-in-legacy"),
        pytest.param({"pdp": _PDP, "subject": {"properties": {"roles": "realm_access.roles"}}},
                     id="subject-properties-map-in-legacy"),
        pytest.param({"pdp": _PDP, "mapping_format": "cel",
                      "subject": {"properties": [{"key": "roles", "claim": "realm_access.roles"}]}},
                     id="subject-properties-array-in-cel"),
        pytest.param({"pdp": _PDP, "mapping_format": "cel", "subject": {"id": "$token.?sub"}},
                     id="optional-on-required-field"),
        pytest.param({"pdp": _PDP, "mapping_format": "cel", "action": {"name": "$params.name == 'x'"}},
                     id="operator"),
        pytest.param({"pdp": _PDP, "mapping_format": "cel", "resource": {"id": "$jwt.sub"}},
                     id="unknown-root"),
        pytest.param({"pdp": _PDP, "mapping_format": "cel", "context": {"h": "$request.headers"}},
                     id="unsupported-request-field"),
    ])
    def test_when_route_created_then_admin_api_rejects_it(self, authzen):
        r = put_route_raw("cel-invalid", authzen)
        try:
            assert r.status_code == 400, r.text
        finally:
            admin_delete("/apisix/admin/routes/cel-invalid")
