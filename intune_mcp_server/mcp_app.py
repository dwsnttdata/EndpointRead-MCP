"""ASGI entrypoint for native MCP Streamable HTTP transport."""

from intune_mcp_server.auth import EntraBearerAuthMiddleware
from intune_mcp_server.config import get_config
from intune_mcp_server.server import mcp


# OBO mode requires Copilot Studio to send a delegated token on every MCP request.
_mcp_app = mcp.streamable_http_app()
_config = get_config()
if _config.auth_mode != "obo":
    raise RuntimeError(
        "The hosted MCP HTTP app requires AUTH_MODE=obo. "
        "App-only and cached delegated modes are not safe for this shared HTTP endpoint."
    )

app = EntraBearerAuthMiddleware(_mcp_app, _config)