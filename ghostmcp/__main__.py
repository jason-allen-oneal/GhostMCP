"""GhostMCP CLI entry points."""

from __future__ import annotations

import os
import sys

from .server import main as server_main


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "dashboard":
        run_dashboard()
    else:
        server_main()


def run_dashboard() -> None:
    import uvicorn

    from . import dashboard
    from .dashboard_security import generate_safe_html_report, secure_dashboard_app

    dashboard.generate_html_report = generate_safe_html_report
    app = secure_dashboard_app(dashboard.app)
    host = os.getenv("GHOSTMCP_DASHBOARD_HOST", "127.0.0.1").strip()
    port = int(os.getenv("GHOSTMCP_DASHBOARD_PORT", "8080"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
