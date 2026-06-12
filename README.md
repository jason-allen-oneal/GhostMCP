<p align="center">
  <img src="docs/images/banner.png" alt="GhostMCP banner" />
</p>

# GhostMCP

[![CI](https://github.com/jason-allen-oneal/GhostMCP/actions/workflows/ci.yml/badge.svg)](https://github.com/jason-allen-oneal/GhostMCP/actions/workflows/ci.yml)
[![CodeQL](https://github.com/jason-allen-oneal/GhostMCP/actions/workflows/codeql.yml/badge.svg)](https://github.com/jason-allen-oneal/GhostMCP/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/jason-allen-oneal/GhostMCP/badge)](https://securityscorecards.dev/viewer/?uri=github.com/jason-allen-oneal/GhostMCP)
[![Dependabot Updates](https://github.com/jason-allen-oneal/GhostMCP/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/jason-allen-oneal/GhostMCP/actions/workflows/dependabot/dependabot-updates)
[![License](https://img.shields.io/github/license/jason-allen-oneal/GhostMCP)](https://github.com/jason-allen-oneal/GhostMCP/blob/main/LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/jason-allen-oneal/GhostMCP/blob/main/SECURITY.md)
[![Contributing](https://img.shields.io/badge/contributing-guidelines-blue)](https://github.com/jason-allen-oneal/GhostMCP/blob/main/CONTRIBUTING.md)

**40+ security tools** — production-oriented MCP server for authorized red-team and security operations.

GhostMCP provides a comprehensive toolkit for authorized security assessments:

- **16 core tools** — DNS, WHOIS, HTTP, TLS, port scanning, IOC extraction, risk scoring, recon generators
- **23 curated binary-backed tools** — nmap, whatweb, nikto, amass, gobuster, nuclei, ffuf, feroxbuster, wfuzz, subfinder, assetfinder, dnsx, gowitness, jaeles, cloudflair, s3scanner, trufflehog, gitleaks, sqlmap, sslscan, wafw00f, wpscan, hydra (auto-discovered at startup)
- **67+ raw binary tools** — any Kali tool on `PATH` exposed as `<binary>_raw_tool`
- **Engagement context** — `engagement_id`, `engagement_mode` (`default|passive|active|intrusive`)
- **Policy controls** — CIDR/domain allowlists, port blocking, rate limits, tool-level ceilings
- **Proxy/Tor** — `GHOSTMCP_PROXY_MODE=tor|proxychains|torsocks` for all outbound traffic
- **Encrypted credentials** — Fernet-encrypted store + Vault/AWS/GCP secret managers
- **Database-backed** — SQLite engagement/scan/finding tracking with web dashboard
- **Plugin system** — Entrypoint-based external tool extensions
- **Remote transport** — `streamable-http` with token/mTLS auth
- **Audit & metrics** — Hash-chained audit log, per-tool metrics, health probes

## Quick Links
- [Documentation](docs/README.md)
- [Runbook](docs/RUNBOOK.md)
- [Web Dashboard](docs/DASHBOARD.md) — `ghostmcp-dashboard` at http://localhost:8080
- [Plugin Development](docs/PLUGINS.md)

## Remote Transport Security
GhostMCP supports `streamable-http` transport via `GHOSTMCP_TRANSPORT_MODE=remote_gateway`. Run the server on a separate host from the LLM client.

### Threat Model & Auth Modes
1. **`AUTH_MODE=none`**: **Hard blocked** in remote mode unless `GHOSTMCP_ALLOW_INSECURE_REMOTE_NO_AUTH=true` is set. Local testing only.
2. **`AUTH_MODE=token`**: Requires `GHOSTMCP_AUTH_TOKEN`. Client provides token in `auth_token` field.
3. **`AUTH_MODE=mtls`**: Most secure. Requires CA, client cert, and private key. Enforces mutual TLS.

**Recommendations:**
- Always use `mtls` for production remote deployments.
- Bind to a specific internal interface (`GHOSTMCP_HTTP_HOST`) rather than `0.0.0.0`.
- Use a firewall to restrict access to `GHOSTMCP_HTTP_PORT`.

## Deployment Quickstart

### Systemd (Linux)
```bash
# Edit deploy/systemd/ghostmcp.service with your environment variables
sudo cp deploy/systemd/ghostmcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ghostmcp
```

### Docker
```bash
docker build -f deploy/container/Dockerfile -t ghostmcp .
docker run -d \
  --name ghostmcp \
  -e GHOSTMCP_AUTH_MODE=token \
  -e GHOSTMCP_AUTH_TOKEN=your-secret-token \
  ghostmcp
```

### Web Dashboard (NEW)
```bash
# Install dashboard dependencies
pip install -e .[dashboard]

# Run dashboard
ghostmcp-dashboard
# Opens at http://127.0.0.1:8080
```

## Tool Types

### 1) Core tools (always available, 16)
- `dns_lookup_tool` — A record resolution
- `reverse_dns_tool` — PTR lookup
- `whois_tool` — WHOIS query
- `http_probe_tool` — HTTP(S) probe with security headers
- `tls_certificate_tool` — TLS cert fetch/summary
- `tls_certificate_expiry_tool` — Cert expiration check
- `tcp_port_scan_tool` — Policy-guarded TCP port scan
- `security_txt_tool` — .well-known/security.txt fetch
- `ioc_extract_tool` — URLs, domains, IPs, hashes from text
- `url_risk_score_tool` — Heuristic URL risk scoring
- `subdomain_candidates_tool` — Subdomain generation for recon
- `common_web_paths_tool` — Common web endpoint generation
- `toolchain_status_tool` — Installed/missing binaries & enabled tools
- `metrics_tool` — Runtime call/failure/timeout/deny stats
- `runtime_probe_tool` — Readiness/liveness probe
- `server_health_tool` — Policy/config snapshot + toolchain summary

### 2) Curated binary-backed tools (23, enabled when installed)
**Recon & Discovery**
- `nmap_service_scan_tool` — Service version detection
- `whatweb_tool` — Web technology fingerprinting
- `nikto_tool` — Web vulnerability scanning
- `amass_passive_tool` — Passive subdomain enumeration
- `subfinder_tool` — Fast passive subdomain enum
- `assetfinder_tool` — Asset discovery
- `dnsx_tool` — Fast DNS probing
- `gowitness_tool` — Web screenshots & metadata

**Vulnerability Scanning**
- `nuclei_tool` — Template-based vuln scanning
- `jaeles_tool` — Vulnerability scanning engine
- `sqlmap_tool` — SQL injection testing
- `wpscan_tool` — WordPress vulnerability scanning
- `wafw00f_tool` — WAF detection

**Directory & Content Discovery**
- `gobuster_dir_tool` — Directory enumeration
- `ffuf_tool` — Fast web fuzzer
- `feroxbuster_tool` — Fast recursive content discovery
- `wfuzz_tool` — Web application fuzzer

**Cloud & Secret Scanning**
- `cloudflair_tool` — Cloudflare origin IP detection
- `s3scanner_tool` — S3 bucket misconfiguration scanning
- `trufflehog_tool` — Secret scanning (filesystem)
- `gitleaks_tool` — Secret scanning (git repos)

**Crypto & TLS**
- `sslscan_tool` — SSL/TLS configuration scanner

### 3) Generated raw binary tools (67+, pattern: `<binary>_raw_tool`)
Any Kali tool on `PATH` auto-registered. Example: `testssl.sh` → `testssl_sh_raw_tool`.
Full list includes: masscan, dnsrecon, dnsenum, fierce, theharvester, recon-ng, dirsearch, hydra, enum4linux-ng, crackmapexec, smbclient, smbmap, rpcclient, searchsploit, exiftool, binwalk, and 40+ more.

### 4) Proxy/Tor Mode (NEW)
```bash
export GHOSTMCP_PROXY_MODE=tor          # Tor SOCKS5 (default 127.0.0.1:9050)
export GHOSTMCP_PROXY_MODE=proxychains  # proxychains4 wrapper
export GHOSTMCP_PROXY_MODE=torsocks     # torsocks wrapper
```
Works for all external tools and internal HTTP/TLS probes.

### 5) Plugin System (NEW)
```bash
# Install plugin from PyPI
pip install ghostmcp-plugin-example

# Or set custom entrypoint group
export GHOSTMCP_PLUGIN_GROUP=myorg.ghostmcp.plugins
```
Develop plugins via `ghostmcp.plugins` entrypoint. See [Plugin Development](docs/PLUGINS.md).

## Requirements
- Python 3.11+
- `mcp` package (installed via this project)
- Optional: Kali tools on `PATH` for binary-backed tools
- Dashboard: `pip install -e .[dashboard]`

## Install
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
# For dashboard:
pip install -e .[dashboard]
# For secret managers:
pip install -e .[hvac,boto3]
```

## Configuration
Use `.env.example` as baseline.

### Core Settings
- `GHOSTMCP_LOG_LEVEL` (default: `INFO`)
- `GHOSTMCP_LOG_FORMAT` (default: `json`)
- `GHOSTMCP_RATE_LIMIT_CALLS` (default: `120`)
- `GHOSTMCP_RATE_LIMIT_WINDOW_SECONDS` (default: `60`)
- `GHOSTMCP_MAX_PORTS_PER_SCAN` (default: `256`)
- `GHOSTMCP_CONNECT_TIMEOUT_MS` (default: `1500`)
- `GHOSTMCP_MAX_CONCURRENT_CONNECTS` (default: `64`)
- `GHOSTMCP_ALLOW_PRIVATE_ONLY` (default: `true`)
- `GHOSTMCP_ALLOWED_CIDRS` (optional, comma-separated)
- `GHOSTMCP_ALLOWED_DOMAINS` (optional, comma-separated)
- `GHOSTMCP_BLOCKED_PORTS` (default: `22,2375,2376,3389`)
- `GHOSTMCP_USER_AGENT` (default: `GhostMCP/0.1`)
- `GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT` (default: `false`)
- `GHOSTMCP_MAX_TOOL_LEVEL` (`passive|active|intrusive`, default: `intrusive`)
- `GHOSTMCP_TRANSPORT_MODE` (`stdio|remote_gateway`, default: `stdio`)
- `GHOSTMCP_AUTH_MODE` (`none|token|mtls`, default: `none`)
- `GHOSTMCP_AUTH_TOKEN` (required for token mode)
- `GHOSTMCP_ALLOW_INSECURE_REMOTE_NO_AUTH` (default: `false`)
- `GHOSTMCP_MTLS_CA_CERT_PATH`, `GHOSTMCP_MTLS_CERT_PATH`, `GHOSTMCP_MTLS_KEY_PATH`
- `GHOSTMCP_HTTP_HOST`, `GHOSTMCP_HTTP_PORT` (remote gateway bind)
- `GHOSTMCP_UVICORN_LOG_LEVEL` (default: `info`)
- `GHOSTMCP_MAX_PASSIVE_PARALLEL`, `GHOSTMCP_MAX_ACTIVE_PARALLEL`, `GHOSTMCP_MAX_INTRUSIVE_PARALLEL`
- `GHOSTMCP_MAX_RAW_ARG_COUNT`, `GHOSTMCP_MAX_RAW_ARG_LENGTH`, `GHOSTMCP_MAX_RAW_RUNTIME_SECONDS`
- `GHOSTMCP_MAX_RAW_STDOUT_BYTES`, `GHOSTMCP_MAX_RAW_STDERR_BYTES`
- `GHOSTMCP_AUDIT_SINK_PATH` (JSONL sink for SIEM)
- `GHOSTMCP_ALLOW_RUN_AS_ROOT` (default: `false`)

### Proxy/Tor (NEW)
- `GHOSTMCP_PROXY_MODE` (`none|tor|proxychains|torsocks`, default: `none`)
- `GHOSTMCP_TOR_HOST` (default: `127.0.0.1`)
- `GHOSTMCP_TOR_PORT` (default: `9050`)

### Credential Store (NEW)
- `GHOSTMCP_CREDENTIAL_STORE` (default: `credentials.json`)
- `GHOSTMCP_CRED_ENCRYPTED` (default: `false`)
- `GHOSTMCP_CRED_PASSWORD` (for encrypted mode)
- `GHOSTMCP_CRED_SALT` (PBKDF2 salt, default: `ghostmcp-salt`)

### Secret Managers (NEW)
- `VAULT_ADDR`, `VAULT_TOKEN` (HashiCorp Vault)
- `AWS_REGION` (AWS Secrets Manager)
- `GCP_PROJECT_ID` (GCP Secret Manager)

### Database (NEW)
- `GHOSTMCP_DB_TYPE` (`sqlite|postgres`, default: `sqlite`)
- `GHOSTMCP_DB_PATH` (default: `ghostmcp.db`)
- `GHOSTMCP_DB_DSN` (PostgreSQL connection string)

## Run
```bash
# MCP server (stdio)
ghostmcp

# Web dashboard (NEW)
ghostmcp-dashboard
# http://127.0.0.1:8080
```

## MCP Client Example (Claude Desktop)
```json
{
  "mcpServers": {
    "ghostmcp": {
      "command": "ghostmcp",
      "env": {
        "GHOSTMCP_ALLOW_PRIVATE_ONLY": "true",
        "GHOSTMCP_ALLOWED_CIDRS": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
        "GHOSTMCP_ALLOWED_DOMAINS": "example.com",
        "GHOSTMCP_PROXY_MODE": "tor"
      }
    }
  }
}
```

## Engagement Model
Most tools accept:
- `engagement_id` (optional unless required by policy)
- `engagement_mode` (`default`, `passive`, `active`, `intrusive`); `default` = `passive`
- `auth_token` (required for `remote_gateway` + `token` auth)

Authorization enforces:
- Global max tool level (`GHOSTMCP_MAX_TOOL_LEVEL`)
- Per-call engagement mode ceiling
- Auth policy for remote mode
- Hard block on `remote_gateway + AUTH_MODE=none` (unless override)

## Audit & Safety
- Structured JSON logs
- Per-call audit entries with hash chaining (`prev_hash`, `event_hash`)
- Optional JSONL audit sink (`GHOSTMCP_AUDIT_SINK_PATH`)
- Per-tool runtime metrics (`metrics_tool`)
- Runtime orchestration probe (`runtime_probe_tool`)

Scope controls:
- Target/private network validation
- Optional domain/CIDR allowlists
- Port policy enforcement
- Raw-tool argument policy (allowlisted tokens/flags, length/count limits)
- Runtime/output caps + forced subprocess termination on timeout
- Per-tool-class concurrency controls (passive/active/intrusive semaphores)

## Inspect Runtime Availability
- `toolchain_status_tool` — installed/missing binaries + enabled tools
- `server_health_tool` — policy/config snapshot + toolchain summary
- `metrics_tool` — call/failure/timeout/deny statistics
- `runtime_probe_tool` — readiness/liveness state

## Development
```bash
# Run tests
python -m pytest tests/ -v

# Type check
mypy ghostmcp/ --ignore-missing-imports

# Lint
ruff check ghostmcp/

# E2E smoke test (opt-in)
GHOSTMCP_E2E=1 python -m pytest tests/test_e2e_mcp.py -v
```

## CI/CD
GitHub workflows:
- `.github/workflows/ci.yml`: lint, type-check, tests, bandit, pip-audit, build, trivy
- `.github/workflows/codeql.yml`: scheduled CodeQL analysis
- `.github/workflows/release.yml`: tag-triggered build, Twine verify, SBOM, provenance, release, optional PyPI publish

## Deployment
- `deploy/systemd/ghostmcp.service` — systemd service
- `deploy/container/Dockerfile` — non-root container
- `deploy/apparmor/ghostmcp.apparmor` — AppArmor confinement

## Runtime Security
- Non-root enforcement (`GHOSTMCP_ALLOW_RUN_AS_ROOT=false`)
- Minimal write footprint (logs/audit sink only)
- Optional AppArmor profile

## Legal
Use GhostMCP only on systems and networks you are explicitly authorized to assess.

## License
AGPL-3.0-or-later. See [LICENSE](LICENSE).