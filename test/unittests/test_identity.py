"""Tests for NodeIdentity and HiveMessageBusClient initialization."""
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch


class TestNodeIdentity(unittest.TestCase):

    def test_default_identity_name_fallback(self):
        """Fresh NodeIdentity with no stored name returns the default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from json_database import JsonConfigXDG
            from hivemind_bus_client.identity import NodeIdentity
            identity = NodeIdentity.__new__(NodeIdentity)
            identity.IDENTITY_FILE = JsonConfigXDG("_test_identity_blank", subfolder="hivemind_test_tmp")
            # Clear any persisted values
            identity.IDENTITY_FILE.clear()
            identity.IDENTITY_FILE.store()

            # Without a name set, should return the default fallback
            self.assertIsInstance(identity.name, str)
            self.assertTrue(len(identity.name) > 0)

    def test_access_key_initially_none_or_string(self):
        """access_key property should be None or str, never raise."""
        from hivemind_bus_client.identity import NodeIdentity
        identity = NodeIdentity.__new__(NodeIdentity)
        identity.IDENTITY_FILE = MagicMock()
        identity.IDENTITY_FILE.get.return_value = None
        result = identity.access_key
        self.assertIsNone(result)

    def test_password_initially_none_or_string(self):
        from hivemind_bus_client.identity import NodeIdentity
        identity = NodeIdentity.__new__(NodeIdentity)
        identity.IDENTITY_FILE = MagicMock()
        identity.IDENTITY_FILE.get.return_value = None
        result = identity.password
        self.assertIsNone(result)

    def test_site_id_returns_none_when_not_set(self):
        """site_id returns None when not stored in the identity file."""
        from hivemind_bus_client.identity import NodeIdentity
        identity = NodeIdentity.__new__(NodeIdentity)
        identity.IDENTITY_FILE = MagicMock()
        identity.IDENTITY_FILE.get.return_value = None
        result = identity.site_id
        self.assertIsNone(result)

    def test_site_id_returns_value_when_set(self):
        from hivemind_bus_client.identity import NodeIdentity
        identity = NodeIdentity.__new__(NodeIdentity)
        identity.IDENTITY_FILE = MagicMock()
        identity.IDENTITY_FILE.get.return_value = "my-site"
        result = identity.site_id
        self.assertEqual(result, "my-site")

    def test_name_setter_stores_value(self):
        from hivemind_bus_client.identity import NodeIdentity
        identity = NodeIdentity.__new__(NodeIdentity)
        identity.IDENTITY_FILE = MagicMock()
        identity.IDENTITY_FILE.get.return_value = None
        identity.name = "my-satellite"
        identity.IDENTITY_FILE.__setitem__.assert_called_with("name", "my-satellite")

    def test_access_key_setter(self):
        from hivemind_bus_client.identity import NodeIdentity
        identity = NodeIdentity.__new__(NodeIdentity)
        identity.IDENTITY_FILE = MagicMock()
        identity.access_key = "my-api-key"
        identity.IDENTITY_FILE.__setitem__.assert_called_with("access_key", "my-api-key")

    def test_password_setter(self):
        from hivemind_bus_client.identity import NodeIdentity
        identity = NodeIdentity.__new__(NodeIdentity)
        identity.IDENTITY_FILE = MagicMock()
        identity.password = "secret"
        identity.IDENTITY_FILE.__setitem__.assert_called_with("password", "secret")


class TestHiveMessageBusClientInit(unittest.TestCase):

    def _make_client(self, **kwargs):
        """Create HiveMessageBusClient without connecting."""
        from hivemind_bus_client.client import HiveMessageBusClient
        defaults = {
            "key": "test-api-key",
            "password": "test-password",
            "port": 5678,
            "host": "ws://localhost",
        }
        defaults.update(kwargs)
        # Bypass actual connection
        with patch.object(HiveMessageBusClient, "connect", return_value=None):
            client = HiveMessageBusClient(**defaults)
        return client

    def test_client_stores_key(self):
        client = self._make_client()
        self.assertEqual(client.key, "test-api-key")

    def test_client_stores_password(self):
        client = self._make_client()
        self.assertEqual(client.password, "test-password")

    def test_client_stores_key(self):
        client = self._make_client()
        self.assertEqual(client.key, "test-api-key")

    def test_client_session_id_is_string(self):
        """session_id should be a non-empty string (typically a UUID)."""
        client = self._make_client()
        self.assertIsInstance(client.session_id, str)
        self.assertTrue(len(client.session_id) > 0)

    def test_client_session_id_looks_like_uuid(self):
        """session_id should have the UUID-hex format (32 hex chars / UUID dashes)."""
        import re
        client = self._make_client()
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$",
            re.IGNORECASE
        )
        self.assertRegex(client.session_id, uuid_pattern)


if __name__ == "__main__":
    unittest.main()
