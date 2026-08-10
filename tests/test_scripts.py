"""Tests for the hivemind-client command line tools."""
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from hivemind_bus_client.scripts import forget_server


def _make_identity(tmpdir):
    from json_database import JsonStorage
    from hivemind_bus_client.identity import NodeIdentity
    store = JsonStorage(os.path.join(tmpdir, "identity.json"),
                        disable_lock=True)
    identity = NodeIdentity(identity_file=store)
    identity.default_master = "ws://hive.example"
    identity.default_port = 5678
    identity.pin_noise_key("hive.example:5678", "aa" * 32)
    identity.pin_noise_key("other.example:5678", "bb" * 32)
    identity.save()
    return identity


class TestForgetServer(unittest.TestCase):
    """Recovering from a reinstalled master must not need a text editor."""

    def test_forgets_only_the_named_server(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = _make_identity(tmpdir)
            with patch("hivemind_bus_client.scripts.NodeIdentity",
                       return_value=identity):
                result = CliRunner().invoke(
                    forget_server, ["--host", "hive.example", "--port", "5678"])

            self.assertEqual(result.exit_code, 0)
            self.assertIn("forgot pinned key for hive.example:5678",
                          result.output)
            self.assertEqual(identity.pinned_noise_keys,
                             {"other.example:5678": "bb" * 32})

    def test_defaults_to_the_master_in_the_identity_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = _make_identity(tmpdir)
            with patch("hivemind_bus_client.scripts.NodeIdentity",
                       return_value=identity):
                result = CliRunner().invoke(forget_server, [])

            self.assertEqual(result.exit_code, 0)
            self.assertNotIn("hive.example:5678", identity.pinned_noise_keys)

    def test_accepts_a_host_with_a_scheme(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = _make_identity(tmpdir)
            with patch("hivemind_bus_client.scripts.NodeIdentity",
                       return_value=identity):
                result = CliRunner().invoke(
                    forget_server,
                    ["--host", "ws://hive.example", "--port", "5678"])

            self.assertEqual(result.exit_code, 0)
            self.assertNotIn("hive.example:5678", identity.pinned_noise_keys)

    def test_unknown_server_lists_what_is_pinned(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = _make_identity(tmpdir)
            with patch("hivemind_bus_client.scripts.NodeIdentity",
                       return_value=identity):
                result = CliRunner().invoke(
                    forget_server, ["--host", "nowhere", "--port", "5678"])

            self.assertEqual(result.exit_code, 0)
            self.assertIn("no pinned key for nowhere:5678", result.output)
            self.assertIn("hive.example:5678", result.output)
            self.assertEqual(len(identity.pinned_noise_keys), 2)

    def test_removal_is_written_to_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            from json_database import JsonStorage
            from hivemind_bus_client.identity import NodeIdentity
            identity = _make_identity(tmpdir)
            path = identity.IDENTITY_FILE.path
            with patch("hivemind_bus_client.scripts.NodeIdentity",
                       return_value=identity):
                CliRunner().invoke(
                    forget_server, ["--host", "hive.example", "--port", "5678"])

            reloaded = NodeIdentity(
                identity_file=JsonStorage(path, disable_lock=True))
            self.assertEqual(reloaded.pinned_noise_keys,
                             {"other.example:5678": "bb" * 32})


if __name__ == "__main__":
    unittest.main()
