import unittest

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from ghostmcp.transport_security import (
    TransportAuthMiddleware,
    get_transport_principal,
)


async def principal_view(_request):
    principal = get_transport_principal()
    return JSONResponse(
        {
            "principal_id": principal.principal_id if principal else None,
            "auth_mode": principal.auth_mode if principal else None,
        }
    )


class TransportSecurityTests(unittest.TestCase):
    def test_token_mode_rejects_missing_and_invalid_bearer(self) -> None:
        app = TransportAuthMiddleware(
            Starlette(routes=[Route("/", principal_view)]),
            auth_mode="token",
            token="correct-token",
        )
        client = TestClient(app)
        self.assertEqual(client.get("/").status_code, 401)
        self.assertEqual(
            client.get(
                "/", headers={"Authorization": "Bearer wrong-token"}
            ).status_code,
            401,
        )

    def test_token_mode_sets_request_scoped_principal(self) -> None:
        app = TransportAuthMiddleware(
            Starlette(routes=[Route("/", principal_view)]),
            auth_mode="token",
            token="correct-token",
        )
        response = TestClient(app).get(
            "/", headers={"Authorization": "Bearer correct-token"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["auth_mode"], "token")
        self.assertTrue(response.json()["principal_id"].startswith("token:"))
        self.assertIsNone(get_transport_principal())

    def test_remote_none_mode_is_blocked_without_explicit_override(self) -> None:
        with self.assertRaises(RuntimeError):
            TransportAuthMiddleware(
                Starlette(routes=[Route("/", principal_view)]),
                auth_mode="none",
            )


if __name__ == "__main__":
    unittest.main()
