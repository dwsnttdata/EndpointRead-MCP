"""HTTP bridge exposing read-only queries; POST bodies are transport, not Graph writes."""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from intune_mcp_server.auth import EntraBearerAuthMiddleware
from intune_mcp_server.config import get_config
from intune_mcp_server.server import (
    get_intune_overview,
    manage_intune_devices,
    test_connection,
)


app = FastAPI(title="Intune MCP HTTP Bridge", version="1.0.0")


class ListDevicesRequest(BaseModel):
    filter_query: str = Field(default="")
    top: int = Field(default=50, ge=1, le=1000)


@app.get("/")
async def root() -> dict:
    return {
        "service": "intune-mcp-bridge",
        "status": "ok",
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/actions/test-connection")
async def action_test_connection() -> dict:
    try:
        return await test_connection()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/actions/get-intune-overview")
async def action_get_intune_overview() -> dict:
    try:
        return await get_intune_overview()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/actions/list-managed-devices")
async def action_list_managed_devices(payload: ListDevicesRequest) -> dict:
    try:
        return await manage_intune_devices(
            action="list",
            filter_query=payload.filter_query,
            top=payload.top,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


_config = get_config()
if _config.auth_mode != "obo":
    raise RuntimeError(
        "The HTTP bridge requires AUTH_MODE=obo; unauthenticated app-only "
        "and shared-cache delegated modes are not supported."
    )

app = EntraBearerAuthMiddleware(app, _config, protected_paths=None)
