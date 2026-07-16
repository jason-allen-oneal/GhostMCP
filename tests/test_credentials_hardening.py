import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ghostmcp.credentials import CredentialStore, EncryptedCredentialStore


class CredentialHardeningTests(unittest.TestCase):
    def test_default_backend_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            store = CredentialStore(str(Path(tmp) / "credentials.bin"))
            self.assertIsNone(store.get_credentials("sqlmap", "https://example.com"))

    def test_plaintext_requires_explicit_unsafe_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"GHOSTMCP_CREDENTIAL_BACKEND": "plaintext"},
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                CredentialStore(str(Path(tmp) / "credentials.json"))

    def test_encrypted_store_round_trip_and_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.bin"
            store = EncryptedCredentialStore(str(path), password="correct horse")
            store.set_credentials("sqlmap", {"user": "alice", "pass": "secret"})
            reopened = EncryptedCredentialStore(str(path), password="correct horse")
            credentials = reopened.get_credentials("sqlmap")
            self.assertIsNotNone(credentials)
            assert credentials is not None
            self.assertEqual(credentials["user"], "alice")
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)
            self.assertNotIn(b"secret", path.read_bytes())


if __name__ == "__main__":
    unittest.main()
