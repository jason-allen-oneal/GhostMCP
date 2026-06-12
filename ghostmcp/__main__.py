"""GhostMCP CLI entry points."""

import sys

from .server import main as server_main


def main() -> None:
    """Main CLI entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "dashboard":
        run_dashboard()
    else:
        server_main()


def run_dashboard() -> None:
    """Run the GhostMCP web dashboard."""
    import uvicorn

    from .dashboard import app

    host = "127.0.0.1"
    port = 8080
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
