"""Credential Store v2 with encryption and secret manager support."""

import base64
import json
import os
from typing import Any, Protocol

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class SecretManager:
    """Base class for secret manager integrations."""

    def get_secret(self, name: str) -> str | None:
        raise NotImplementedError

    def set_secret(self, name: str, value: str) -> bool:
        raise NotImplementedError


class VaultSecretManager(SecretManager):
    """HashiCorp Vault secret manager."""

    def __init__(self, url: str | None = None, token: str | None = None):
        self.url = url or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.token = token or os.getenv("VAULT_TOKEN")

    def get_secret(self, name: str) -> str | None:
        if not self.token:
            return None
        try:
            import hvac
            client = hvac.Client(url=self.url, token=self.token)
            if not client.is_authenticated():
                return None
            response = client.secrets.kv.v2.read_secret_version(path=f"ghostmcp/{name}")
            return response.get("data", {}).get("data", {}).get("value")
        except Exception:  # nosec B110 - expected to fail silently for missing secrets
            return None

    def set_secret(self, name: str, value: str) -> bool:
        if not self.token:
            return False
        try:
            import hvac
            client = hvac.Client(url=self.url, token=self.token)
            if not client.is_authenticated():
                return False
            client.secrets.kv.v2.create_or_update_secret(
                path=f"ghostmcp/{name}",
                secret={"value": value}
            )
            return True
        except Exception:  # nosec B110 - expected to fail silently for network issues
            return False


class AWSSecretManager(SecretManager):
    """AWS Secrets Manager integration."""

    def __init__(self, region: str | None = None):
        self.region = region or os.getenv("AWS_REGION", "us-east-1")

    def get_secret(self, name: str) -> str | None:
        try:
            import boto3
            client = boto3.client("secretsmanager", region_name=self.region)
            response = client.get_secret_value(SecretId=f"ghostmcp/{name}")
            return response.get("SecretString")
        except Exception:  # nosec B110 - expected to fail silently for missing secrets
            return None

    def set_secret(self, name: str, value: str) -> bool:
        try:
            import boto3
            client = boto3.client("secretsmanager", region_name=self.region)
            client.put_secret_value(SecretId=f"ghostmcp/{name}", SecretString=value)
            return True
        except Exception:  # nosec B110 - expected to fail silently for network issues
            return False


class GCPSecretManager(SecretManager):
    """Google Cloud Secret Manager integration."""

    def __init__(self, project_id: str | None = None):
        self.project_id = project_id or os.getenv("GCP_PROJECT_ID")

    def get_secret(self, name: str) -> str | None:
        if not self.project_id:
            return None
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            secret_path = f"projects/{self.project_id}/secrets/ghostmcp-{name}/versions/latest"
            response = client.access_secret_version(request={"name": secret_path})
            return response.payload.data.decode("UTF-8")
        except Exception:  # nosec B110 - expected to fail silently for missing secrets
            return None

    def set_secret(self, name: str, value: str) -> bool:
        if not self.project_id:
            return False
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            parent = f"projects/{self.project_id}"
            secret_id = f"ghostmcp-{name}"
            try:
                client.create_secret(
                    request={
                        "parent": parent,
                        "secret_id": secret_id,
                        "secret": {"replication": {"automatic": {}}},
                    }
                )
            except Exception:  # nosec B110 - secret may already exist
                pass
            client.add_secret_version(
                request={"parent": f"{parent}/secrets/{secret_id}", "payload": {"data": value.encode("UTF-8")}}
            )
            return True
        except Exception:  # nosec B110 - expected to fail silently for network issues
            return False


class _CredentialStoreBackend(Protocol):
    def get_credentials(self, tool_id: str, target: str | None = None) -> dict[str, Any] | None: ...
    def set_credentials(self, tool_id: str, creds: dict[str, Any], scope: str = "default") -> None: ...


class EncryptedCredentialStore:
    """Encrypted credential store using Fernet symmetric encryption."""

    def __init__(self, store_path: str, password: str | None = None):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography package required for encrypted credential store")

        self.store_path = store_path
        self._cache: dict[str, Any] = {}
        self._fernet: Fernet | None = None

        if password:
            self._init_fernet(password)
        else:
            key_path = f"{store_path}.key"
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(key_path, "wb") as f:
                    f.write(key)
            self._fernet = Fernet(key)

        self._load()

    def _init_fernet(self, password: str):
        """Initialize Fernet from password using PBKDF2."""
        salt = os.getenv("GHOSTMCP_CRED_SALT", "ghostmcp-salt").encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self._fernet = Fernet(key)

    def _load(self):
        if os.path.exists(self.store_path):
            try:
                with open(self.store_path, "rb") as f:
                    encrypted = f.read()
                if self._fernet and encrypted:
                    decrypted = self._fernet.decrypt(encrypted)
                    self._cache = json.loads(decrypted.decode())
            except Exception:  # nosec B110 - corrupted or missing store
                self._cache = {}

    def _save(self):
        if not self._fernet:
            return
        try:
            encrypted = self._fernet.encrypt(json.dumps(self._cache).encode())
            with open(self.store_path, "wb") as f:
                f.write(encrypted)
        except Exception:  # nosec B110 - best effort save
            pass

    def get_credentials(self, tool_id: str, target: str | None = None) -> dict[str, Any] | None:
        tool_creds = self._cache.get(tool_id, {})
        if not tool_creds:
            return None

        if target and target in tool_creds:
            return tool_creds[target]

        return tool_creds.get("default")

    def set_credentials(self, tool_id: str, creds: dict[str, Any], scope: str = "default"):
        if tool_id not in self._cache:
            self._cache[tool_id] = {}
        self._cache[tool_id][scope] = creds
        self._save()


class _PlainCredentialStore:
    """Original plain-text credential store for backward compatibility."""

    def __init__(self, store_path: str):
        self.store_path = store_path
        self._cache: dict[str, Any] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.store_path):
            try:
                with open(self.store_path) as f:
                    self._cache = json.load(f)
            except Exception:  # nosec B110 - corrupted or missing store
                self._cache = {}

def CredentialStore(store_path: str, password: str | None = None) -> EncryptedCredentialStore | _PlainCredentialStore:
    """Factory function to create appropriate credential store."""
    if CRYPTO_AVAILABLE and password:
        return EncryptedCredentialStore(store_path, password)
    return _PlainCredentialStore(store_path)


__all__ = [
    "SecretManager",
    "VaultSecretManager",
    "AWSSecretManager",
    "GCPSecretManager",
    "EncryptedCredentialStore",
    "_PlainCredentialStore",
    "CredentialStore",
]
