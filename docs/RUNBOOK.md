# Runbook

## Local dev

- Create venv and install dev deps
- Run tests and lint before pushing

## Container

- Container definition lives in `deploy/container/`
- Build and run steps should be kept close to the deployment artifacts

## Troubleshooting

- If the server fails at startup, check environment and dependency locks first
- Prefer reproducing with the same lock file used by CI
