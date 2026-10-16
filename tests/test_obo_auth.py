from __future__ import annotations

import ast
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt

from intune_mcp_server import server
from intune_mcp_server.auth import (
    AuthenticatedUser,
    EntraBearerAuthMiddleware,
    EntraTokenVerifier,
    current_user,
)
from intune_mcp_server.config import GraphConfig
from intune_mcp_server.graph_client import AuthRequiredError, GraphClient


def make_config(**overrides) -> GraphConfig:
    values = {
        "tenant_id": "tenant-id",
        "client_id": "client-id",
        "client_secret": "client-secret",
        "auth_mode": "obo",
        "mcp_api_audience": "api://client-id",
        "mcp_api_scope": "Mcp.Access",
    }
    values.update(overrides)
    return GraphConfig(**values)


class EntraTokenVerifierTests(unittest.TestCase):
    def setUp(self):
        self.verifier = EntraTokenVerifier(make_config())
        self.verifier._jwks_client = MagicMock()
        self.verifier._jwks_client.get_signing_key_from_jwt.return_value = MagicMock(
            key="verified-key"
        )

    @patch("intune_mcp_server.auth.jwt.decode")
    def test_accepts_token_with_expected_audience_tenant_user_and_scope(self, decode):
        claims = {
            "tid": "tenant-id",
            "oid": "user-id",
            "scp": "Mcp.Access User.Read",
        }
        decode.return_value = claims

        result = self.verifier.verify("signed-token")

        self.assertEqual(result.access_token, "signed-token")
        self.assertEqual(result.claims, claims)
        self.assertEqual(
            decode.call_args.kwargs["audience"],
            ["api://client-id", "client-id"],
        )

    @patch("intune_mcp_server.auth.jwt.decode")
    def test_rejects_token_without_mcp_scope(self, decode):
        decode.return_value = {
            "tid": "tenant-id",
            "oid": "user-id",
            "scp": "User.Read",
        }

        with self.assertRaises(jwt.InvalidTokenError):
            self.verifier.verify("signed-token")

    @patch("intune_mcp_server.auth.jwt.decode")
    def test_rejects_token_from_another_tenant(self, decode):
        decode.return_value = {
            "tid": "another-tenant",
            "oid": "user-id",
            "scp": "Mcp.Access",
        }

        with self.assertRaises(jwt.InvalidTokenError):
            self.verifier.verify("signed-token")


class EntraBearerAuthMiddlewareTests(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_missing_bearer_token(self):
        downstream = MagicMock()
        verifier = MagicMock()
        middleware = EntraBearerAuthMiddleware(
            downstream,
            make_config(),
            verifier=verifier,
        )
        messages = []

        async def send(message):
            messages.append(message)

        await middleware(
            {"type": "http", "path": "/mcp", "headers": []},
            MagicMock(),
            send,
        )

        self.assertEqual(messages[0]["status"], 401)
        downstream.assert_not_called()
        verifier.verify.assert_not_called()

    async def test_can_protect_every_bridge_route(self):
        middleware = EntraBearerAuthMiddleware(
            MagicMock(),
            make_config(),
            verifier=MagicMock(),
            protected_paths=None,
        )
        messages = []

        async def send(message):
            messages.append(message)

        await middleware(
            {"type": "http", "path": "/health", "headers": []},
            MagicMock(),
            send,
        )

        self.assertEqual(messages[0]["status"], 401)

    async def test_sets_validated_identity_only_for_request(self):
        user = AuthenticatedUser(
            access_token="user-assertion",
            claims={"oid": "user-id", "tid": "tenant-id"},
        )
        verifier = MagicMock()
        verifier.verify.return_value = user
        observed_users = []

        async def downstream(scope, receive, send):
            observed_users.append(current_user.get())

        middleware = EntraBearerAuthMiddleware(
            downstream,
            make_config(),
            verifier=verifier,
        )

        async def send(message):
            return None

        await middleware(
            {
                "type": "http",
                "path": "/mcp",
                "headers": [(b"authorization", b"Bearer incoming-token")],
            },
            MagicMock(),
            send,
        )

        self.assertEqual(observed_users, [user])
        self.assertIsNone(current_user.get())


class GraphClientOBOTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_current_assertion_without_caching_it_globally(self):
        graph_client = GraphClient(make_config())
        msal_app = MagicMock()
        msal_app.acquire_token_on_behalf_of.return_value = {
            "access_token": "graph-user-token"
        }
        graph_client._msal_app = msal_app
        user = AuthenticatedUser(
            access_token="incoming-user-token",
            claims={"oid": "user-id", "tid": "tenant-id"},
        )
        context_token = current_user.set(user)
        try:
            result = await graph_client.get_token()
        finally:
            current_user.reset(context_token)

        self.assertEqual(result, "graph-user-token")
        self.assertIsNone(graph_client._token)
        msal_app.acquire_token_on_behalf_of.assert_called_once_with(
            user_assertion="incoming-user-token",
            scopes=["https://graph.microsoft.com/.default"],
        )
        msal_app.acquire_token_for_client.assert_not_called()

    async def test_missing_request_identity_never_falls_back_to_app_token(self):
        graph_client = GraphClient(make_config())
        msal_app = MagicMock()
        graph_client._msal_app = msal_app

        with self.assertRaises(AuthRequiredError):
            await graph_client.get_token()

        msal_app.acquire_token_for_client.assert_not_called()


class GraphClientRequestTests(unittest.IsolatedAsyncioTestCase):
    async def test_sends_obo_graph_token_as_bearer_authorization(self):
        graph_client = GraphClient(make_config())
        graph_client.get_token = AsyncMock(return_value="graph-user-token")
        response = MagicMock()
        response.status_code = 200
        response.text = '{"id": "user-id"}'
        response.json.return_value = {"id": "user-id"}
        client = MagicMock()
        client.request = AsyncMock(return_value=response)
        graph_client.get_http_client = AsyncMock(return_value=client)

        await graph_client.get("me")

        authorization = client.request.await_args.kwargs["headers"]["Authorization"]
        self.assertEqual(authorization, "Bearer " + "graph-user-token")


class GraphClientAuthDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    async def test_graph_401_logs_only_selected_headers_and_token_claims(self):
        graph_client = GraphClient(make_config())
        graph_token = jwt.encode(
            {
                "aud": "https://graph.microsoft.com",
                "iss": "https://sts.windows.net/tenant-id/",
                "ver": "1.0",
                "scp": "User.Read",
                "exp": 2_000_000_000,
                "email": "private@example.com",
            },
            "test-signing-key-that-is-at-least-thirty-two-bytes",
            algorithm="HS256",
        )
        graph_client.get_token = AsyncMock(return_value=graph_token)
        response = MagicMock()
        response.status_code = 401
        response.headers = httpx.Headers(
            {
                "WWW-Authenticate": 'Bearer error="invalid_token"',
                "request-id": "graph-request-id",
                "client-request-id": "client-request-id",
                "Date": "Thu, 16 Oct 2025 00:00:00 GMT",
                "x-unrelated-header": "do-not-log",
            }
        )
        response.json.return_value = {
            "error": {"message": "Protocol 'Bearer' failed to validate."}
        }
        response.text = "response body"
        client = MagicMock()
        client.request = AsyncMock(return_value=response)
        graph_client.get_http_client = AsyncMock(return_value=client)

        with self.assertLogs("intune_mcp_server.graph_client", level="WARNING") as logs:
            with self.assertRaisesRegex(Exception, "Graph API error \\(401\\)"):
                await graph_client.get("users")

        diagnostic_log = "\n".join(logs.output)
        self.assertIn("graph-request-id", diagnostic_log)
        self.assertIn("client-request-id", diagnostic_log)
        self.assertIn("https://graph.microsoft.com", diagnostic_log)
        self.assertIn("User.Read", diagnostic_log)
        self.assertNotIn(graph_token, diagnostic_log)
        self.assertNotIn("private@example.com", diagnostic_log)
        self.assertNotIn("do-not-log", diagnostic_log)


class GraphClientReadOnlyTests(unittest.IsolatedAsyncioTestCase):
    def test_graph_client_exposes_no_generic_write_helpers(self):
        for method in ("post", "patch", "put", "delete"):
            with self.subTest(method=method):
                self.assertFalse(hasattr(GraphClient, method))

    async def test_rejects_graph_mutation_methods(self):
        graph_client = GraphClient(make_config())

        for method in ("PATCH", "PUT", "DELETE"):
            with self.subTest(method=method):
                with self.assertRaises(ValueError):
                    await graph_client._request(method, "/users/user-id")

    async def test_rejects_posts_to_anything_except_report_export(self):
        graph_client = GraphClient(make_config())

        with self.assertRaises(ValueError):
            await graph_client._request("POST", "/users", json={"displayName": "No"})

    async def test_report_export_uses_only_the_fixed_report_job_endpoint(self):
        graph_client = GraphClient(make_config())
        graph_client._request = AsyncMock(return_value={"id": "export-job-id"})

        result = await graph_client.create_report_export_job(
            json={"reportName": "Devices", "format": "csv"}
        )

        self.assertEqual(result, {"id": "export-job-id"})
        graph_client._request.assert_awaited_once_with(
            "POST",
            "/deviceManagement/reports/exportJobs",
            use_beta=True,
            json={"reportName": "Devices", "format": "csv"},
        )

    def test_mcp_tools_have_no_direct_graph_mutation_calls(self):
        source_path = Path(server.__file__)
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        mutation_calls = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr.lower() in {"post", "patch", "put", "delete"}
        ]

        self.assertEqual(mutation_calls, [])


if __name__ == "__main__":
    unittest.main()
