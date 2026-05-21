from __future__ import annotations

import json as _json
import logging
import time

import pytest
import requests

from helpers import APISIX_ADMIN, APISIX_PROXY, ADMIN_KEY, KEYCLOAK, MOCK_PDP, wait_for

_http_log = logging.getLogger("apisix")
_route_log = logging.getLogger("route")
_orig_request = requests.Session.request


def _logged_request(self, method, url, **kwargs):
    resp = _orig_request(self, method, url, **kwargs)
    if url.startswith(APISIX_PROXY):
        body = kwargs.get("json")
        mcp_method = body.get("method", "") if isinstance(body, dict) else ""
        label = f" ({mcp_method})" if mcp_method else ""
        path = url[len(APISIX_PROXY):]
        _http_log.info("[apisix] %s %s%s → %d", method.upper(), path, label, resp.status_code)
        _http_log.info("[apisix] request body: %s", _json.dumps(body, default=str) if body else "-")
        _http_log.info("[apisix] response: %s", resp.text[:600])
        try:
            state = _orig_request(self, "GET", f"{MOCK_PDP}/mock/state", timeout=2).json()
            if state.get("last_request"):
                _http_log.info("[pdp]    authzen request → %s", _json.dumps(state["last_request"], default=str))
        except Exception:
            pass
    return resp


requests.Session.request = _logged_request


@pytest.fixture(scope="session", autouse=True)
def services_ready():
    """Block until APISIX admin API, Keycloak realm, and mock PDP are ready."""
    wait_for(f"{APISIX_ADMIN}/apisix/admin/routes", headers={"X-API-KEY": ADMIN_KEY})
    # Keycloak + bootstrap complete when the test realm is reachable
    wait_for(f"{KEYCLOAK}/realms/test")
    wait_for(f"{MOCK_PDP}/health")
    time.sleep(2)


def _pdp_reset():
    """Silent PDP reset — fixture bookkeeping, not test intent, so no INFO log."""
    requests.put(f"{MOCK_PDP}/mock/configure", json={"decision": True, "simulate": None})


@pytest.fixture(autouse=True)
def log_route_config():
    """Log the authzen plugin config for every active route before each test."""
    try:
        resp = requests.get(
            f"{APISIX_ADMIN}/apisix/admin/routes",
            headers={"X-API-KEY": ADMIN_KEY},
            timeout=3,
        )
        for item in resp.json().get("list", []):
            route = item.get("value", {})
            authzen = route.get("plugins", {}).get("authzen")
            if authzen:
                _route_log.info("[route] %s → %s", route.get("uri"), _json.dumps(authzen, default=str))
    except Exception:
        pass


@pytest.fixture(autouse=True)
def reset_pdp():
    """Reset mock PDP to a clean allow state before every test."""
    _pdp_reset()
    yield
    _pdp_reset()
