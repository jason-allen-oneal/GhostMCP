# Contributing

## Scope

GhostMCP is intended for authorized red-team and security operations.

## Development

### Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

### Pre-push checks

Before pushing, run:

```bash
pytest
```

If the repo adds linting later, ensure lint is clean before push.

## Reporting issues

- Include the exact command, expected vs actual behavior, and relevant logs.
- Do not include secrets or sensitive operational data.

## Security issues

See `SECURITY.md`.
