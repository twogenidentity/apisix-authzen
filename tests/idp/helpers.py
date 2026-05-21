from __future__ import annotations

import logging
import time

import requests

log = logging.getLogger("pdp")

APISIX_ADMIN  = "http://localhost:9182"
APISIX_PROXY  = "http://localhost:9082"
MOCK_PDP      = "http://localhost:8083"
KEYCLOAK      = "http://localhost:8090"
ADMIN_KEY     = "edd1c9f034335f136f87ad84b625c8f1"

_REALM        = "test"
_CLIENT_ID    = "test-client"
_CLIENT_SECRET = "test-secret"


# ---------------------------------------------------------------------------
# Service readiness
# ---------------------------------------------------------------------------

def wait_for(url: str, headers: dict | None = None, timeout: int = 180) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, headers=headers, timeout=3)
            if r.status_code < 500:
                return
        except Exception:
            pass
        time.sleep(3)
    raise RuntimeError(f"Service at {url} did not become ready within {timeout}s")


# ---------------------------------------------------------------------------
# Keycloak token (Resource Owner Password Credentials)
# ---------------------------------------------------------------------------

def get_token(username: str, password: str) -> str:
    r = requests.post(
        f"{KEYCLOAK}/realms/{_REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
            "username": username,
            "password": password,
        },
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# APISIX Admin API
# ---------------------------------------------------------------------------

def admin_put(path: str, body: dict) -> requests.Response:
    r = requests.put(
        f"{APISIX_ADMIN}{path}",
        json=body,
        headers={"X-API-KEY": ADMIN_KEY},
    )
    r.raise_for_status()
    return r


def admin_delete(path: str) -> None:
    requests.delete(
        f"{APISIX_ADMIN}{path}",
        headers={"X-API-KEY": ADMIN_KEY},
    )


# ---------------------------------------------------------------------------
# Mock PDP control
# ---------------------------------------------------------------------------

def configure_pdp(decision: bool = True, simulate: str | None = None) -> None:
    log.info("[pdp] configure → decision=%s simulate=%s", decision, simulate)
    requests.put(
        f"{MOCK_PDP}/mock/configure",
        json={"decision": decision, "simulate": simulate},
    )


def pdp_state() -> dict:
    state = requests.get(f"{MOCK_PDP}/mock/state").json()
    log.info("[pdp] state → call_count=%d decision=%s", state["call_count"], state["decision"])
    log.debug("[pdp] last_request: %s", state.get("last_request"))
    return state
