"""Authentication and response hardening for the optional dashboard."""

from __future__ import annotations

import hmac
import html
import os
from urllib.parse import parse_qs, urlsplit

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

COOKIE_NAME = "ghostmcp_dashboard_token"
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"Invalid boolean environment value for {name}")


def _extract_token(request: Request) -> tuple[str | None, bool]:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip(), False
    header_token = request.headers.get("x-ghostmcp-token")
    if header_token:
        return header_token.strip(), False
    cookie_token = request.cookies.get(COOKIE_NAME)
    if cookie_token:
        return cookie_token, True
    return None, False


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    source = origin or referer
    if not source:
        return False
    parsed = urlsplit(source)
    expected_host = request.headers.get("host", "")
    return parsed.scheme in {"http", "https"} and parsed.netloc == expected_host


class DashboardSecurityMiddleware:
    def __init__(self, app: ASGIApp, token: str, allow_unauthenticated: bool = False):
        self.app = app
        self.token = token
        self.allow_unauthenticated = allow_unauthenticated

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        if not self.allow_unauthenticated:
            supplied, cookie_auth = _extract_token(request)
            if supplied is None or not hmac.compare_digest(supplied, self.token):
                response = Response("Unauthorized", status_code=401)
                await response(scope, receive, send)
                return
            if cookie_auth and request.method.upper() in _UNSAFE_METHODS:
                if not _same_origin(request):
                    response = Response("CSRF validation failed", status_code=403)
                    await response(scope, receive, send)
                    return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (
                            b"content-security-policy",
                            b"default-src 'self'; img-src 'self' data:; "
                            b"style-src 'self' 'unsafe-inline'; script-src 'self'",
                        ),
                        (b"cache-control", b"no-store"),
                    ]
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


async def login_form(_request: Request) -> HTMLResponse:
    return HTMLResponse(
        """<!doctype html>
<html><head><meta charset="utf-8"><title>GhostMCP login</title></head>
<body><main><h1>GhostMCP Dashboard</h1>
<form method="post" action="/login">
<label>Dashboard token <input type="password" name="token" required></label>
<button type="submit">Sign in</button>
</form></main></body></html>"""
    )


async def login_submit(request: Request) -> Response:
    body = (await request.body()).decode("utf-8", errors="strict")
    supplied = parse_qs(body).get("token", [""])[0]
    expected = request.app.state.dashboard_token
    if not supplied or not hmac.compare_digest(supplied, expected):
        return Response("Invalid token", status_code=401)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        COOKIE_NAME,
        expected,
        httponly=True,
        secure=_env_bool("GHOSTMCP_DASHBOARD_SECURE_COOKIE", False),
        samesite="strict",
        max_age=8 * 60 * 60,
    )
    return response


async def logout(_request: Request) -> Response:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME)
    return response


def secure_dashboard_app(app: ASGIApp) -> ASGIApp:
    token = os.getenv("GHOSTMCP_DASHBOARD_TOKEN", "").strip()
    allow_unauthenticated = _env_bool(
        "GHOSTMCP_DASHBOARD_ALLOW_UNAUTHENTICATED", False
    )
    if not token and not allow_unauthenticated:
        raise RuntimeError(
            "GHOSTMCP_DASHBOARD_TOKEN is required. "
            "Set GHOSTMCP_DASHBOARD_ALLOW_UNAUTHENTICATED=true only for isolated testing."
        )
    if allow_unauthenticated:
        token = os.urandom(32).hex()

    protected = DashboardSecurityMiddleware(
        app, token=token, allow_unauthenticated=allow_unauthenticated
    )
    wrapper = Starlette(
        routes=[
            Route("/login", login_form, methods=["GET"]),
            Route("/login", login_submit, methods=["POST"]),
            Route("/logout", logout, methods=["POST"]),
            Mount("/", app=protected),
        ]
    )
    wrapper.state.dashboard_token = token
    return wrapper


def generate_safe_html_report(data: dict) -> str:
    engagement = data.get("engagement", {})
    stats = data.get("stats", {})
    findings = data.get("findings", [])

    def esc(value: object) -> str:
        return html.escape(str(value), quote=True)

    finding_items = "".join(
        "<article>"
        f"<h3>{esc(item.get('severity', 'info')).upper()}: "
        f"{esc(item.get('title', 'Untitled'))}</h3>"
        f"<p><strong>Type:</strong> {esc(item.get('type', ''))}</p>"
        f"<p><strong>Target:</strong> {esc(item.get('target', ''))}</p>"
        f"<p>{esc(item.get('description', ''))}</p>"
        "</article>"
        for item in findings
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>{esc(engagement.get('name', 'GhostMCP'))} - Report</title>
<style>body{{font-family:sans-serif;max-width:900px;margin:2rem auto;padding:1rem}}
article{{border-top:1px solid #ddd;padding-top:1rem}}</style></head>
<body><h1>{esc(engagement.get('name', 'Security Assessment'))}</h1>
<p><strong>Engagement ID:</strong> {esc(engagement.get('id', ''))}</p>
<p><strong>Status:</strong> {esc(engagement.get('status', ''))}</p>
<p><strong>Total scans:</strong> {esc(stats.get('total_scans', 0))}</p>
<p><strong>Total findings:</strong> {esc(stats.get('total_findings', 0))}</p>
<h2>Findings</h2>{finding_items or '<p>No findings recorded.</p>'}</body></html>"""
