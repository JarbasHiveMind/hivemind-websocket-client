"""Regression tests for HELLO/HANDSHAKE payload handling."""
import unittest
from unittest.mock import MagicMock, patch

from ovos_bus_client.message import Message

from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol


def _make_protocol() -> HiveMindSlaveProtocol:
    hm = MagicMock()
    hm.session_id = "test-session"
    hm.handshake_event = MagicMock()
    identity = MagicMock(spec=NodeIdentity)
    identity.name = "test-node"
    identity.password = "test"
    proto = HiveMindSlaveProtocol(hm=hm, identity=identity, site_id="living-room")
    proto.internal_protocol = MagicMock()
    proto.internal_protocol.node_id = ""
    proto.internal_protocol.bus = MagicMock()
    return proto


class TestHelloAndHandshakePayloads(unittest.TestCase):
    def test_handle_hello_accepts_dict_payload(self):
        proto = _make_protocol()
        msg = HiveMessage(HiveMessageType.HELLO,
                          {"pubkey": "master-pubkey", "node_id": "master-1"})

        proto.handle_hello(msg)

        self.assertEqual(proto.mpubkey, "master-pubkey")
        self.assertEqual(proto.internal_protocol.node_id, "master-1")

    def test_handle_handshake_accepts_dict_payload(self):
        proto = _make_protocol()
        msg = HiveMessage(HiveMessageType.HANDSHAKE,
                          {"password": True, "binarize": True})

        with patch.object(proto, "start_handshake") as mock_start:
            proto.handle_handshake(msg)

        self.assertTrue(proto.binarize)
        mock_start.assert_called_once()

    def test_handle_handshake_allows_no_key_exchange_when_core_marks_it_optional(self):
        proto = _make_protocol()
        proto.hm.crypto_key = "existing-session-key"
        msg = HiveMessage(HiveMessageType.HANDSHAKE,
                          {"handshake": False, "preshared_key": True, "binarize": True})

        with patch.object(proto, "start_handshake") as mock_start:
            proto.handle_handshake(msg)

        self.assertTrue(proto.binarize)
        proto.hm.handshake_event.set.assert_called_once_with()
        mock_start.assert_not_called()

    def test_handle_bus_accepts_outer_bus_frame(self):
        proto = _make_protocol()
        inner = Message("speak", {"utterance": "hello"}, {"destination": "HiveMind"})
        msg = HiveMessage(HiveMessageType.BUS, inner)

        fake_session = MagicMock()
        fake_session.session_id = "remote-session"

        with patch("hivemind_bus_client.protocol.Session.from_message", return_value=fake_session) as mock_from_message:
            with patch("hivemind_bus_client.protocol.SessionManager.update") as mock_update:
                proto.handle_bus(msg)

        mock_from_message.assert_called_once()
        mock_update.assert_called_once_with(fake_session)
        proto.internal_protocol.bus.emit.assert_called_once()
