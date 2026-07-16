from __future__ import annotations

import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import ServerConfig
from .credentials import CredentialStore

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)


@dataclass(frozen=True)
class ValidationResult:
    host: str
    ips: list[str]


class SecurityPolicy:
    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        store_path = os.getenv("GHOSTMCP_CREDENTIAL_STORE", "credentials.json")
        self.credentials = CredentialStore(store_path)

    def inject_credentials(self, tool_id: str, target: str, args: list[str]) -> list[str]:
        """Inject stored credentials without mutating the caller's argument list."""
        creds = self.credentials.get_credentials(tool_id, target)
        if not creds:
            return list(args)

        new_args = list(args)
        if tool_id == "sqlmap" and "auth_type" in creds:
            user = str(creds.get("user", ""))
            password = str(creds.get("pass", ""))
            auth_type = str(creds["auth_type"])
            if not user or not password:
                raise ValueError("Stored sqlmap credentials require user and pass")
            new_args.extend(
                [f"--auth-type={auth_type}", f"--auth-cred={user}:{password}"]
            )
        return new_args

    def validate_domain(self, domain: str) -> str:
        candidate = domain.strip().lower().rstrip(".")
        if not candidate or len(candidate) > 253 or not DOMAIN_RE.fullmatch(candidate):
            raise ValueError("Invalid domain name")
        self.enforce_domain_scope(candidate)
        return candidate

    def enforce_domain_scope(self, domain: str) -> None:
        candidate = domain.strip().lower().rstrip(".")
        if not candidate or not DOMAIN_RE.fullmatch(candidate):
            raise ValueError("Invalid domain name")
        if self.config.allowed_domains and not any(
            candidate == allowed or candidate.endswith(f".{allowed}")
            for allowed in self.config.allowed_domains
        ):
            raise ValueError(
                f"Domain policy violation: {candidate} not in allowed domains"
            )

        ips = self._resolve_ips(candidate)
        if not ips:
            raise ValueError("Unable to resolve target host")
        self._validate_ip_set(ips)

    def validate_url(self, url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("URL scheme must be http or https")
        if not parsed.hostname:
            raise ValueError("URL host is required")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials in URLs are not allowed")
        self.validate_target(parsed.hostname)
        if parsed.port is not None:
            self.parse_ports([parsed.port])
        return url

    def parse_ports(self, ports: list[int]) -> list[int]:
        if not ports:
            raise ValueError("At least one port is required")
        deduped = sorted(set(ports))
        if len(deduped) > self.config.max_ports_per_scan:
            raise ValueError(
                f"Port list too large: {len(deduped)} > {self.config.max_ports_per_scan}"
            )
        for port in deduped:
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")
            if port in self.config.blocked_ports:
                raise ValueError(f"Port is blocked by policy: {port}")
        return deduped

    def validate_target(self, host: str) -> ValidationResult:
        candidate = host.strip().strip("[]")
        if not candidate:
            raise ValueError("Target host is required")

        try:
            literal = ipaddress.ip_address(candidate)
        except ValueError:
            ips = self._resolve_ips(candidate)
        else:
            ips = [str(literal)]

        if not ips:
            raise ValueError("Unable to resolve target host")
        self._validate_ip_set(ips)
        return ValidationResult(host=candidate, ips=ips)

    def validate_masscan_targets(self, targets: str) -> str:
        """Validate every masscan IP, CIDR, or explicit address range."""
        candidate = targets.strip()
        if not candidate:
            raise ValueError("Masscan targets are required")
        if any(ch in candidate for ch in ";|&`$(){}<>\\\n\r\t"):
            raise ValueError("Invalid characters in masscan targets")

        tokens = [token.strip() for token in candidate.split(",") if token.strip()]
        if not tokens:
            raise ValueError("Masscan targets are required")
        if len(tokens) > 256:
            raise ValueError("Too many masscan target expressions")

        for token in tokens:
            self._validate_network_expression(token)
        return ",".join(tokens)

    def _validate_network_expression(self, token: str) -> None:
        if "-" in token:
            start_raw, separator, end_raw = token.partition("-")
            if not separator or not start_raw or not end_raw or "-" in end_raw:
                raise ValueError(f"Invalid address range: {token}")
            start = ipaddress.ip_address(start_raw)
            end = ipaddress.ip_address(end_raw)
            if start.version != end.version or int(start) > int(end):
                raise ValueError(f"Invalid address range: {token}")
            self._validate_range(start, end)
            return

        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            address = ipaddress.ip_address(token)
            self._validate_ip_set([str(address)])
            return
        self._validate_network(network)

    def _validate_network(self, network: ipaddress._BaseNetwork) -> None:
        start = network.network_address
        end = network.broadcast_address
        self._validate_range(start, end)

    def _validate_range(
        self, start: ipaddress._BaseAddress, end: ipaddress._BaseAddress
    ) -> None:
        if self.config.allow_private_only and not any(
            start in network and end in network
            for network in _PRIVATE_NETWORKS
            if network.version == start.version
        ):
            raise ValueError(
                f"Target policy violation: range {start}-{end} is not fully private"
            )
        if self.config.allowed_cidrs and not any(
            start in cidr and end in cidr
            for cidr in self.config.allowed_cidrs
            if cidr.version == start.version
        ):
            raise ValueError(
                f"Target policy violation: range {start}-{end} is outside allowed CIDRs"
            )

    def _validate_ip_set(self, ips: list[str]) -> None:
        for ip in ips:
            address = ipaddress.ip_address(ip)
            if address.is_unspecified or address.is_multicast:
                raise ValueError(f"Target policy violation: disallowed address {ip}")
            if self.config.allow_private_only and not any(
                address in network
                for network in _PRIVATE_NETWORKS
                if network.version == address.version
            ):
                raise ValueError(
                    "Target policy violation: only private addresses are allowed"
                )
            if self.config.allowed_cidrs and not any(
                address in cidr
                for cidr in self.config.allowed_cidrs
                if cidr.version == address.version
            ):
                raise ValueError(
                    f"Target policy violation: {ip} not in allowed CIDRs"
                )

    @staticmethod
    def _resolve_ips(host: str) -> list[str]:
        try:
            addrinfo = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return []
        ips: list[str] = []
        for info in addrinfo:
            ip = str(info[4][0])
            if ip not in ips:
                ips.append(ip)
        return ips
