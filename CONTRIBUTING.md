# Contributing

## Scope and conduct

GhostMCP is intended only for authorized security assessment workflows. Contributions must not weaken scope enforcement, authentication, audit integrity, credential handling, or safe defaults for convenience.

Do not include real client targets, credentials, tokens, audit keys, private reports, or sensitive scanner output in issues, tests, commits, or pull requests.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,dashboard,credentials]"
```

## Required checks

Before opening a pull request, run:

```bash
ruff check .
mypy ghostmcp
bandit -q -r ghostmcp
pip-audit -r requirements-dev.lock.txt
python -m unittest discover -s tests -v
python -m build
```

CI repeats these checks on Python 3.11 and 3.12 and also validates generated locks, clean-wheel installation, container construction, Trivy policy, and CodeQL.

## Tests

Add focused tests for behavior changes. Security-sensitive changes should cover both allowed and denied paths.

Examples:

- Scope validation for literal IPs, DNS answers, CIDRs, ranges, redirects, and URLs
- Engagement and tool-level authorization
- Raw-wrapper and plugin allowlisting
- Credential redaction and backend failure behavior
- Audit-chain persistence and signature verification
- Dashboard authentication and same-origin checks
- Scheduler leases, duplicate claims, and worker failures
- Packaging imports and required static assets

Tests must not call real public targets or require destructive security tools by default. Opt-in end-to-end tests should be clearly isolated.

## Documentation

Update documentation in the same pull request when changing:

- Environment variables or defaults
- Authentication or transport behavior
- Tool registration or workflow names
- Raw-wrapper or plugin policy
- Credential backends
- Dashboard or scheduling behavior
- Database or audit formats
- Deployment paths, ports, commands, or service files

At minimum, review `README.md`, `.env.example`, and the relevant file under `docs/`.

## Dependency changes

- Update `pyproject.toml` constraints.
- Regenerate the appropriate hash-locked requirement files.
- Run `pip-audit` against the development lock.
- Confirm the final container passes Trivy.
- Explain new runtime dependencies in the pull request.

Do not add unpinned GitHub Actions. Repository workflows use commit-SHA pinning.

## Pull requests

A pull request should include:

- Problem statement
- Security and operational impact
- Implementation summary
- Tests performed
- Documentation updated
- Known limitations

Keep changes focused. Large security or architecture changes should be separated from unrelated formatting or refactoring.

## Reporting issues

Include:

- Commit or version
- Deployment mode
- Relevant configuration with secrets removed
- Expected and observed behavior
- Minimal reproduction steps
- Sanitized logs

For vulnerabilities, follow [SECURITY.md](SECURITY.md) and do not disclose exploit details publicly.
