"""Tests for the hivemind-client command line tools."""
import os
import tempfile
import unittest
import unittest.mock
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


class TestARoutingCommandSendsAnEnvelope(unittest.TestCase):
    """HIVEMIND-MSG-1 §4: an ESCALATE or PROPAGATE payload IS a HiveMessage.

    Both commands passed the Layer-1 ``Message`` straight in. The constructor
    turns one into ``{"type", "data", "context"}``, which carries no
    ``msg_type`` and is therefore not the nested envelope §4 requires. The far
    end raises ``TypeError`` the moment it reads ``.payload``, so the frame is
    unusable and the sender is told nothing.
    """

    def _emitted(self, command):
        """Drive the real click command with the network stubbed out, and
        return the HiveMessage it emitted."""
        from hivemind_bus_client.message import HiveMessage

        sent = []

        class _Node:
            def __init__(self, *a, **kw):
                self.connected_event = unittest.mock.MagicMock()

            def connect(self, *a, **kw):
                pass

            def emit(self, message):
                sent.append(message)

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as tmpdir:
            identity = _make_identity(tmpdir)
            identity.password = "pw"
            identity.access_key = "key"
            identity.save()
            with patch("hivemind_bus_client.scripts._node_identity",
                       return_value=identity), \
                 patch("hivemind_bus_client.scripts.HiveMessageBusClient",
                       _Node):
                result = CliRunner().invoke(
                    command, ["--msg", "speak",
                              "--payload", '{"utterance": "hi"}',
                              # the flag under test in
                              # test_the_outer_envelope_carries_the_site_id
                              "--siteid", "test-site"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(len(sent), 1)
        self.assertIsInstance(sent[0], HiveMessage)
        return sent[0]

    def test_escalate_wraps_the_message_in_a_bus_envelope(self):
        from hivemind_bus_client.message import HiveMessageType
        from hivemind_bus_client.scripts import escalate

        outer = self._emitted(escalate)
        self.assertEqual(outer.msg_type, HiveMessageType.ESCALATE)
        inner = outer.as_dict["payload"]
        self.assertIn("msg_type", inner,
                      "a routing payload must itself be an envelope (§4)")
        self.assertEqual(inner["msg_type"], HiveMessageType.BUS)

    def test_propagate_wraps_the_message_in_a_bus_envelope(self):
        from hivemind_bus_client.message import HiveMessageType
        from hivemind_bus_client.scripts import propagate

        outer = self._emitted(propagate)
        self.assertEqual(outer.msg_type, HiveMessageType.PROPAGATE)
        inner = outer.as_dict["payload"]
        self.assertIn("msg_type", inner)
        self.assertEqual(inner["msg_type"], HiveMessageType.BUS)

    def test_the_layer_1_message_still_arrives_intact(self):
        """The control: wrapping must not lose what the operator typed."""
        from hivemind_bus_client.scripts import escalate

        outer = self._emitted(escalate)
        inner_bus = outer.payload          # the nested HiveMessage
        self.assertEqual(inner_bus.payload.msg_type, "speak")
        self.assertEqual(inner_bus.payload.data, {"utterance": "hi"})

    def test_the_far_end_can_read_the_payload(self):
        """What the defect actually broke: dereferencing .payload raised
        TypeError, which is what a receiving node does on arrival."""
        from hivemind_bus_client.message import HiveMessage, HiveMessageType
        from hivemind_bus_client.scripts import propagate

        outer = self._emitted(propagate)
        inner = outer.payload
        self.assertIsInstance(inner, HiveMessage)
        self.assertEqual(inner.msg_type, HiveMessageType.BUS)
        self.assertEqual(inner.payload.msg_type, "speak")

    def test_the_outer_envelope_carries_the_site_id(self):
        """HIVEMIND-MSG-1 §5: an unset target_site_id means NO node may
        deliver the inner BUS message. The frame travels and nothing acts on
        it, so a parseable envelope with the key unset is still undeliverable.
        The key is read from the OUTER envelope.

        --siteid was reaching node.connect, which declares this node's own
        site, and never the message.
        """
        from hivemind_bus_client.scripts import escalate, propagate

        for command in (escalate, propagate):
            with self.subTest(command=command.name):
                outer = self._emitted(command)
                self.assertEqual(outer.as_dict["target_site_id"],
                                 "test-site",
                                 "the site the operator named must be on the "
                                 "outer envelope, or no node may deliver it")

    def test_the_inner_envelope_does_not_carry_it(self):
        """The control. §5 says the key is read from the OUTER envelope, so
        setting it on the inner one would look right and deliver nothing."""
        from hivemind_bus_client.scripts import escalate

        outer = self._emitted(escalate)
        self.assertIsNone(outer.as_dict["payload"].get("target_site_id"))
