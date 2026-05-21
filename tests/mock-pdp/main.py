"""
Mock AuthZEN PDP for integration tests.

Exposes:
  POST /access/v1/evaluation  — the AuthZEN endpoint APISIX calls
  PUT  /mock/configure        — test control: set decision / simulate failure
  GET  /mock/state            — inspect call count and last request body
  GET  /health                — liveness probe
"""

import asyncio
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, ValidationError

app = FastAPI()


# ---------------------------------------------------------------------------
# AuthZEN evaluation request schema — https://openid.github.io/authzen/
# ---------------------------------------------------------------------------

class _Subject(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str

class _Resource(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: Optional[str] = None     # optional per spec; resource may be typed without an id

class _Action(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str

class AuthZENEvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    subject: _Subject
    resource: _Resource
    action: _Action
    context: Optional[dict[str, Any]] = None


_state: dict = {
    "decision": True,
    "simulate": None,   # None | "error" | "slow"
    "call_count": 0,
    "last_request": None,
    "generation": 0,    # incremented on configure; guards against stale slow-request side-effects
}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.put("/mock/configure")
async def configure(request: Request):
    body = await request.json()
    _state["decision"] = body.get("decision", True)
    _state["simulate"] = body.get("simulate", None)
    _state["call_count"] = 0
    _state["last_request"] = None
    _state["generation"] += 1
    return {"ok": True}


@app.get("/mock/state")
async def get_state():
    return _state


@app.post("/access/v1/evaluation")
async def evaluate(request: Request):
    body = await request.json()

    try:
        AuthZENEvaluationRequest.model_validate(body)
    except ValidationError as e:
        return JSONResponse(
            {"error": "AuthZEN request does not conform to spec", "details": e.errors()},
            status_code=400,
        )

    gen = _state["generation"]

    if _state["simulate"] == "slow":
        await asyncio.sleep(10)
        # Only record the call if the generation hasn't changed (no configure in between)
        if _state["generation"] == gen:
            _state["call_count"] += 1
        return JSONResponse({"decision": _state["decision"]})

    if _state["simulate"] == "error":
        return JSONResponse({"error": "internal server error"}, status_code=500)

    _state["call_count"] += 1
    _state["last_request"] = body
    return JSONResponse({"decision": _state["decision"]})
