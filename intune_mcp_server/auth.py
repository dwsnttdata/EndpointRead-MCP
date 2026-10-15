"""Request-scoped Microsoft Entra bearer-token validation for OBO."""

from __future__ import annotations

import asyncio
import json
import logging
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient, PyJWKClientError

from .config import GraphConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuthenticatedUser:
    """Validated caller identity and the assertion used for Graph OBO."""

    access_token: str
    claims: dict[str, Any]


current_user: ContextVar[AuthenticatedUser | None] = ContextVar(
    "endpointread_current_user",
    default=None,
)


class EntraTokenVerifier:
    """Validate access tokens issued for this MCP API by its Entra tenant."""

    def __init__(self, config: GraphConfig):
        self.config = config
        self._jwks_client = PyJWKClient(
            f"https://login.microsoftonline.com/{config.tenant_id}/discovery/v2.0/keys",
            cache_keys=True,
            timeout=10,
        )

    def verify(self, access_token: str) -> AuthenticatedUser:
        """Validate signature, issuer, audience, tenant, and delegated scope."""
        signing_key = self._jwks_client.get_signing_key_from_jwt(access_token)
        claims = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=[
                self.config.mcp_api_audience,
                self.config.client_id,
            ],
            issuer=[
                f"https://login.microsoftonline.com/{self.config.tenant_id}/v2.0",
                f"https://login.microsoftonline.com/{self.config.tenant_id}/",
                f"https://sts.windows.net/{self.config.tenant_id}/",
            ],
            leeway=60,
        )

        if claims.get("tid") != self.config.tenant_id:
            raise jwt.InvalidTokenError("Token tenant does not match this MCP tenant.")
        if not claims.get("oid"):
            raise jwt.InvalidTokenError("Token does not identify a user.")

        scopes = set(str(claims.get("scp", "")).split())
        if self.config.mcp_api_scope not in scopes:
            raise jwt.InvalidTokenError("Token does not grant the required MCP scope.")

        return AuthenticatedUser(access_token=access_token, claims=claims)


class EntraBearerAuthMiddleware:
    """Require a validated delegated token for MCP HTTP requests."""

    def __init__(
        self,
        app,
        config: GraphConfig,
        verifier: EntraTokenVerifier | None = None,
        protected_paths: set[str] | None = None,
    ):
        self.app = app
        self.verifier = verifier or EntraTokenVerifier(config)
        self.protected_paths = (
            frozenset(path.rstrip("/") or "/" for path in protected_paths)
            if protected_paths is not None
            else None
        )

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "").rstrip("/") or "/"
        if (
            scope["type"] != "http"
            or (self.protected_paths is not None and path not in self.protected_paths)
        ):
            await self.app(scope, receive, send)
            return

        authorization_headers = [
            value
            for name, value in scope.get("headers", [])
            if name.lower() == b"authorization"
        ]
        if len(authorization_headers) != 1:
            await self._unauthorized(send)
            return

        authorization = authorization_headers[0].decode("latin-1")
        scheme, separator, access_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not access_token.strip():
            await self._unauthorized(send)
            return

        try:
            user = await asyncio.to_thread(self.verifier.verify, access_token.strip())
        except jwt.InvalidTokenError:
            await self._unauthorized(send)
            return
        except PyJWKClientError:
            logger.exception("Unable to retrieve Microsoft Entra signing keys.")
            await self._service_unavailable(send)
            return

        user_token = current_user.set(user)
        try:
            await self.app(scope, receive, send)
        finally:
            current_user.reset(user_token)

    @staticmethod
    async def _unauthorized(send) -> None:
        await EntraBearerAuthMiddleware._respond(
            send,
            401,
            {
                "error": "unauthorized",
                "message": "A valid delegated MCP access token is required.",
            },
            [(b"www-authenticate", b'Bearer realm="EndpointRead-MCP"')],
        )

    @staticmethod
    async def _service_unavailable(send) -> None:
        await EntraBearerAuthMiddleware._respond(
            send,
            503,
            {
                "error": "authentication_unavailable",
                "message": "Unable to verify the token with Microsoft Entra ID.",
            },
        )

    @staticmethod
    async def _respond(send, status: int, payload: dict[str, str], extra_headers=()) -> None:
        body = json.dumps(payload).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    *extra_headers,
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
