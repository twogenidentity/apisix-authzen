"""
Mock MCP upstream server for integration tests.

Handles MCP JSON-RPC 2.0 requests forwarded by APISIX after authorization.
No auth here — APISIX (authzen plugin) enforces access before forwarding.

Supports:
  POST /mcp   — JSON-RPC dispatcher (tools/call, initialize, tools/list, etc.)
  GET  /mcp   — SSE endpoint placeholder (returns 200 immediately)
  DELETE /mcp — Session termination placeholder
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

app = FastAPI()

TOOLS = [
    {
        "name": "fintech_list_expenses",
        "description": "List expenses for a tenant",
        "inputSchema": {
            "type": "object",
            "properties": {"tenant": {"type": "string"}},
            "required": ["tenant"],
        },
    },
    {
        "name": "fintech_get_balance",
        "description": "Get account balance for a tenant",
        "inputSchema": {
            "type": "object",
            "properties": {"tenant": {"type": "string"}},
            "required": ["tenant"],
        },
    },
]


def _jsonrpc(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


@app.post("/mcp")
async def mcp_post(request: Request):
    body = await request.json()
    rpc_id = body.get("id", 1)
    method = body.get("method", "")
    params = body.get("params", {})

    if method == "initialize":
        return JSONResponse(_jsonrpc(rpc_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-mcp-upstream", "version": "1.0.0"},
        }))

    if method == "tools/list":
        return JSONResponse(_jsonrpc(rpc_id, {"tools": TOOLS}))

    if method == "tools/call":
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})
        return JSONResponse(_jsonrpc(rpc_id, {
            "content": [{"type": "text", "text": f"Tool '{tool_name}' executed with {arguments}"}],
        }))

    return JSONResponse(
        {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32601, "message": "Method not found"}},
        status_code=200,
    )


@app.get("/mcp")
async def mcp_sse(request: Request):
    # SSE connection placeholder — just acknowledge
    return Response(status_code=200, media_type="text/event-stream")


@app.delete("/mcp")
async def mcp_delete(request: Request):
    return Response(status_code=200)
