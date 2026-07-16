import os
import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from ghostmcp.dashboard_security import generate_safe_html_report, secure_dashboard_app


async def home(_request):
    return PlainTextResponse("ok")


async def mutate(_request):
    return PlainTextResponse("changed")


class DashboardSecurityTests(unittest.TestCase):
    def test_dashboard_requires_token_configuration(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                secure_dashboard_app(Starlette(routes=[Route("/", home)]))

    def test_bearer_token_allows_access(self) -> None:
        with patch.dict(
            os.environ, {"GHOSTMCP_DASHBOARD_TOKEN": "secret-token"}, clear=True
        ):
            app = secure_dashboard_app(Starlette(routes=[Route("/", home)]))
            client = TestClient(app)
            self.assertEqual(client.get("/").status_code, 401)
            response = client.get(
                "/", headers={"Authorization": "Bearer secret-token"}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["x-frame-options"], "DENY")

    def test_cookie_mutation_requires_same_origin(self) -> None:
        with patch.dict(
            os.environ, {"GHOSTMCP_DASHBOARD_TOKEN": "secret-token"}, clear=True
        ):
            app = secure_dashboard_app(
                Starlette(routes=[Route("/mutate", mutate, methods=["POST"])])
            )
            client = TestClient(app)
            client.cookies.set("ghostmcp_dashboard_token", "secret-token")
            self.assertEqual(client.post("/mutate").status_code, 403)
            self.assertEqual(
                client.post(
                    "/mutate", headers={"Origin": "http://testserver"}
                ).status_code,
                200,
            )

    def test_html_report_escapes_stored_values(self) -> None:
        rendered = generate_safe_html_report(
            {
                "engagement": {"name": "<script>alert(1)</script>", "id": "1"},
                "stats": {},
                "findings": [
                    {
                        "severity": "high",
                        "title": "<img src=x onerror=alert(1)>",
                        "description": "unsafe <b>description</b>",
                    }
                ],
            }
        )
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img", rendered)
        self.assertIn("&lt;script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
