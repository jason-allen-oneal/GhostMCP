"""Credential storage with explicit, fail-closed backend selection."""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Protocol

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

_SAFE_SECRET_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


class SecretManager:
    def get_secret(self, name: str) -> str | None:
        raise NotImplementedError

    def set_secret(self, name: str, value: str) -> bool:
        raise NotImplementedError


class VaultSecretManager(SecretManager):
    def __init__(self, url: str | None = None, token: str | None = None):
        self.url = url or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.token = token or os.getenv("VAULT_TOKEN")

    def _client(self):
        if not self.token:
            raise RuntimeError("VAULT_TOKEN is required")
        import hvac

        client = hvac.Client(url=self.url, token=self.token)
        if not client.is_authenticated():
            raise RuntimeError("Vault authentication failed")
        return client

    def get_secret(self, name: str) -> str | None:
        try:
            response = self._client().secrets.kv.v2.read_secret_version(
                path=f"ghostmcp/{name}"
            )
        except Exception as exc:
            if exc.__class__.__name__ in {"InvalidPath", "Forbidden"}:
                return None
            raise
        return response.get("data", {}).get("data", {}).get("value")

    def set_secret(self, name: str, value: str) -> bool:
        self._client().secrets.kv.v2.create_or_update_secret(
            path=f"ghostmcp/{name}", secret={"value": value}
        )
        return True


class AWSSecretManager(SecretManager):
    def __init__(self, region: str | None = None):
        self.region = region or os.getenv("AWS_REGION", "us-east-1")

    def _client(self):
        import boto3

        return boto3.client("secretsmanager", region_name=self.region)

    def get_secret(self, name: str) -> str | None:
        try:
            response = self._client().get_secret_value(SecretId=f"ghostmcp/{name}")
        except Exception as exc:
            if exc.__class__.__name__ == "ResourceNotFoundException":
                return None
            raise
        return response.get("SecretString")

    def set_secret(self, name: str, value: str) -> bool:
        client = self._client()
        secret_id = f"ghostmcp/{name}"
        try:
            client.put_secret_value(SecretId=secret_id, SecretString=value)
        except Exception as exc:
            if exc.__class__.__name__ != "ResourceNotFoundException":
                raise
            client.create_secret(Name=secret_id, SecretString=value)
        return True


class GCPSecretManager(SecretManager):
    def __init__(self, project_id: str | None = None):
        self.project_id = project_id or os.getenv("GCP_PROJECT_ID")
        if not self.project_id:
            raise RuntimeError("GCP_PROJECT_ID is required")

    def _client(self):
        from google.cloud import secretmanager

        return secretmanager.SecretManagerServiceClient()

    def get_secret(self, name: str) -> str | None:
        secret_path = (
            f"projects/{self.project_id}/secrets/ghostmcp-{name}/versions/latest"
        )
        try:
            response = self._client().access_secret_version(
                request={"name": secret_path}
            )
        except Exception as exc:
            if exc.__class__.__name__ == "NotFound":
                return None
            raise
        return response.payload.data.decode("utf-8")

    def set_secret(self, name: str, value: str) -> bool:
        client = self._client()
        parent = f"projects/{self.project_id}"
        secret_id = f"ghostmcp-{name}"
        secret_path = f"{parent}/secrets/{secret_id}"
        try:
            client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {"replication": {"automatic": {}}},
                }
            )
        except Exception as exc:
            if exc.__class__.__name__ != "AlreadyExists":
                raise
        client.add_secret_version(
            request={
                "parent": secret_path,
                "payload": {"data": value.encode("utf-8")},
            }
        )
        return True


class _CredentialStoreBackend(Protocol):
    def get_credentials(
        self, tool_id: str, target: str | None = None
    ) -> dict[str, Any] | None: ...

    def set_credentials(
        self, tool_id: str, creds: dict[str, Any], scope: str = "default"
    ) -> None: ...


def _chmod_private(path: str | Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _chmod_private(temp_path)
        os.replace(temp_path, path)
        _chmod_private(path)
    finally:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


class EncryptedCredentialStore:
    def __init__(
        self,
        store_path: str,
        password: str | None = None,
        key_file: str | None = None,
    ):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError(
                "cryptography is required for the encrypted credential store"
            )
        if bool(password) == bool(key_file):
            raise RuntimeError(
                "Encrypted credentials require exactly one of "
                "GHOSTMCP_CRED_PASSWORD or GHOSTMCP_CRED_KEY_FILE"
            )

        self.store_path = Path(store_path).expanduser()
        self._cache: dict[str, Any] = {}
        self._fernet = Fernet(
            self._derive_key(password) if password else self._read_key_file(key_file)
        )
        self._load()

    def _derive_key(self, password: str | None) -> bytes:
        if password is None:
            raise RuntimeError("Credential password is missing")
        salt_path = self.store_path.with_suffix(self.store_path.suffix + ".salt")
        if salt_path.exists():
            salt = salt_path.read_bytes()
            if len(salt) != 16:
                raise RuntimeError("Credential salt file is invalid")
        else:
            salt = os.urandom(16)
            _atomic_write(salt_path, salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    @staticmethod
    def _read_key_file(key_file: str | None) -> bytes:
        if not key_file:
            raise RuntimeError("Credential key file is missing")
        path = Path(key_file).expanduser()
        key = path.read_bytes().strip()
        _chmod_private(path)
        try:
            Fernet(key)
        except ValueError as exc:
            raise RuntimeError("Credential key file does not contain a Fernet key") from exc
        return key

    def _load(self) -> None:
        if not self.store_path.exists():
            return
        encrypted = self.store_path.read_bytes()
        _chmod_private(self.store_path)
        if not encrypted:
            return
        try:
            decrypted = self._fernet.decrypt(encrypted)
        except InvalidToken as exc:
            raise RuntimeError(
                "Unable to decrypt credential store with the configured key"
            ) from exc
        payload = json.loads(decrypted.decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("Credential store payload must be an object")
        self._cache = payload

    def _save(self) -> None:
        plaintext = json.dumps(
            self._cache, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        _atomic_write(self.store_path, self._fernet.encrypt(plaintext))

    def get_credentials(
        self, tool_id: str, target: str | None = None
    ) -> dict[str, Any] | None:
        tool_creds = self._cache.get(tool_id, {})
        if not isinstance(tool_creds, dict):
            return None
        value = tool_creds.get(target) if target else None
        if value is None:
            value = tool_creds.get("default")
        return dict(value) if isinstance(value, dict) else None

    def set_credentials(
        self, tool_id: str, creds: dict[str, Any], scope: str = "default"
    ) -> None:
        self._cache.setdefault(tool_id, {})[scope] = dict(creds)
        self._save()


class _PlainCredentialStore:
    """Plaintext compatibility backend. Must be selected explicitly."""

    def __init__(self, store_path: str):
        self.store_path = Path(store_path).expanduser()
        self._cache: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not self.store_path.exists():
            return
        payload = json.loads(self.store_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("Credential store payload must be an object")
        self._cache = payload
        _chmod_private(self.store_path)

    def get_credentials(
        self, tool_id: str, target: str | None = None
    ) -> dict[str, Any] | None:
        tool_creds = self._cache.get(tool_id, {})
        if not isinstance(tool_creds, dict):
            return None
        value = tool_creds.get(target) if target else None
        if value is None:
            value = tool_creds.get("default")
        return dict(value) if isinstance(value, dict) else None

    def set_credentials(
        self, tool_id: str, creds: dict[str, Any], scope: str = "default"
    ) -> None:
        self._cache.setdefault(tool_id, {})[scope] = dict(creds)
        _atomic_write(
            self.store_path,
            (json.dumps(self._cache, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
        )


class _DisabledCredentialStore:
    def get_credentials(
        self, tool_id: str, target: str | None = None
    ) -> dict[str, Any] | None:
        return None

    def set_credentials(
        self, tool_id: str, creds: dict[str, Any], scope: str = "default"
    ) -> None:
        raise RuntimeError("Credential storage is disabled")


class SecretManagerCredentialStore:
    def __init__(self, manager: SecretManager):
        self.manager = manager

    @staticmethod
    def _name(tool_id: str, scope: str) -> str:
        return _SAFE_SECRET_NAME.sub("_", f"{tool_id}--{scope}")

    def get_credentials(
        self, tool_id: str, target: str | None = None
    ) -> dict[str, Any] | None:
        for scope in ([target, "default"] if target else ["default"]):
            raw = self.manager.get_secret(self._name(tool_id, scope))
            if raw is None:
                continue
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise RuntimeError("Secret manager credential payload must be an object")
            return payload
        return None

    def set_credentials(
        self, tool_id: str, creds: dict[str, Any], scope: str = "default"
    ) -> None:
        payload = json.dumps(creds, sort_keys=True, separators=(",", ":"))
        if not self.manager.set_secret(self._name(tool_id, scope), payload):
            raise RuntimeError("Secret manager rejected credential update")


def CredentialStore(
    store_path: str, password: str | None = None
) -> _CredentialStoreBackend:
    backend = os.getenv("GHOSTMCP_CREDENTIAL_BACKEND", "disabled").strip().lower()
    if os.getenv("GHOSTMCP_CRED_ENCRYPTED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        backend = "encrypted"

    if backend in {"disabled", "none", "off"}:
        return _DisabledCredentialStore()
    if backend in {"encrypted", "fernet"}:
        resolved_password = password or os.getenv("GHOSTMCP_CRED_PASSWORD")
        key_file = os.getenv("GHOSTMCP_CRED_KEY_FILE")
        return EncryptedCredentialStore(store_path, resolved_password, key_file)
    if backend in {"plain", "plaintext"}:
        if os.getenv("GHOSTMCP_ALLOW_PLAINTEXT_CREDENTIALS", "false").lower() not in {
            "1",
            "true",
            "yes",
            "on",
        }:
            raise RuntimeError(
                "Plaintext credential storage requires "
                "GHOSTMCP_ALLOW_PLAINTEXT_CREDENTIALS=true"
            )
        return _PlainCredentialStore(store_path)
    if backend == "vault":
        return SecretManagerCredentialStore(VaultSecretManager())
    if backend == "aws":
        return SecretManagerCredentialStore(AWSSecretManager())
    if backend == "gcp":
        return SecretManagerCredentialStore(GCPSecretManager())
    raise RuntimeError(f"Unsupported credential backend: {backend}")


__all__ = [
    "SecretManager",
    "VaultSecretManager",
    "AWSSecretManager",
    "GCPSecretManager",
    "EncryptedCredentialStore",
    "SecretManagerCredentialStore",
    "_DisabledCredentialStore",
    "_PlainCredentialStore",
    "CredentialStore",
]
