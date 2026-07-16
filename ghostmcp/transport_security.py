"""Transport-level authentication for remote MCP deployments."""

from __future__ import annotations

import hashlib
import hmac
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


@dataclass(frozen=True)
class TransportPrincipal:
    principal_id: str
    auth_mode: str
    client_host: str | None


_current_principal: ContextVar[TransportPrincipal | None] = ContextVar(
    "ghostmcp_transport_principal", default=None
)


def get_transport_principal() -> TransportPrincipal | None:
    return _current_principal.get()


def _client_host(scope: Scope) -> str | None:
    client = scope.get("client")
    if isinstance(client, tuple) and client:
        return str(client[0])
    return None


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _bearer_token(scope: Scope) -> str | None:
    for raw_name, raw_value in scope.get("headers", []):
        if raw_name.lower() != b"authorization":
            continue
        value = raw_value.decode("latin-1").strip()
        scheme, separator, token = value.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token.strip():
            return None
        return token.strip()
    return None


class TransportAuthMiddleware:
    """Authenticate every HTTP request before it reaches FastMCP."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        auth_mode: str,
        token: str = "",
        allow_insecure_none: bool = False,
    ) -> None:
        self.app = app
        self.auth_mode = auth_mode
        self.token = token
        self.allow_insecure_none = allow_insecure_none
        if auth_mode == "token" and not token:
            raise RuntimeError("Token authentication requires a configured token")
        if auth_mode == "none" and not allow_insecure_none:
            raise RuntimeError("Remote HTTP transport without authentication is blocked")
        if auth_mode not in {"none", "token", "mtls"}:
            raise RuntimeError(f"Unsupported transport authentication mode: {auth_mode}")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        principal = self._authenticate(scope)
        if principal is None:
            response = JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        context_token: Token[TransportPrincipal | None] = _current_principal.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            _current_principal.reset(context_token)

    def _authenticate(self, scope: Scope) -> TransportPrincipal | None:
        host = _client_host(scope)
        if self.auth_mode == "token":
            supplied = _bearer_token(scope)
            if supplied is None or not hmac.compare_digest(supplied, self.token):
                return None
            return TransportPrincipal(
                principal_id=f"token:{_token_fingerprint(self.token)}",
                auth_mode="token",
                client_host=host,
            )

        if self.auth_mode == "mtls":
            # Uvicorn performs certificate verification before ASGI dispatch when
            # ssl_cert_reqs=ssl.CERT_REQUIRED. The ASGI layer receives only verified
            # connections, so the client address is used as the audit principal.
            return TransportPrincipal(
                principal_id=f"mtls:{host or 'unknown'}",
                auth_mode="mtls",
                client_host=host,
            )

        if self.allow_insecure_none:
            return TransportPrincipal(
                principal_id=f"insecure:{host or 'unknown'}",
                auth_mode="none",
                client_host=host,
            )
        return None


def transport_auth_snapshot() -> dict[str, Any]:
    principal = get_transport_principal()
    if principal is None:
        return {"authenticated": False, "principal_id": None, "auth_mode": None}
    return {
        "authenticated": True,
        "principal_id": principal.principal_id,
        "auth_mode": principal.auth_mode,
        "client_host": principal.client_host,
    }
