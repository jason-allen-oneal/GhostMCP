# Security policy

## Supported versions

GhostMCP is currently an alpha project. Security updates are provided for the latest `main` branch. Older commits, unmerged branches, locally modified copies, and prerelease artifacts may not receive fixes.

The package version is `0.2.0a1`. Review configuration and deployment changes before upgrading between alpha revisions.

## Reporting a vulnerability

Do not open a public issue containing vulnerability details, exploit code, credentials, target information, or sensitive logs.

Preferred reporting method:

- Use [GitHub Security Advisories](https://github.com/jason-allen-oneal/GhostMCP/security/advisories/new).

Include, when available:

- Affected commit or version
- Deployment mode and relevant configuration with secrets removed
- Reproduction steps
- Expected and observed behavior
- Security impact
- Suggested mitigation
- Whether the issue is already being exploited

If GitHub Security Advisories cannot be used, open a minimal public issue without technical exploit details and request a private communication channel.

## Operational security

Vulnerability reporting and secure operation are separate concerns. Operators should also review:

- [Security operations](docs/SECURITY-OPERATIONS.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Operations runbook](docs/RUNBOOK.md)

GhostMCP must only be used against systems the operator owns or is explicitly authorized to assess.

## Scope

The security policy covers GhostMCP source code and repository-maintained deployment artifacts. It does not automatically cover:

- Third-party security binaries invoked by GhostMCP
- External plugins
- MCP clients
- Reverse proxies and identity providers
- Vault, AWS, or GCP services
- Locally modified containers or systemd units

Reports involving third-party components are still useful when GhostMCP's integration makes an issue exploitable or leaks sensitive information.
