"""Regression tests for INTERCOM compatibility with HiveMind-core."""
import unittest
import pybase64
from unittest.mock import MagicMock, patch

from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol
from ovos_bus_client.message import Message


def _make_protocol() -> HiveMindSlaveProtocol:
    hm = MagicMock()
    hm.session_id = "test-session"
    hm.handshake_event = MagicMock()
    hm._handle_binary = MagicMock()
    identity = MagicMock(spec=NodeIdentity)
    identity.name = "test-node"
    identity.password = "test"
    proto = HiveMindSlaveProtocol(hm=hm, identity=identity, site_id="living-room")
    proto.internal_protocol = MagicMock()
    proto.internal_protocol.node_id = ""
    proto.internal_protocol.bus = MagicMock()
    return proto


class TestIntercomCompatibility(unittest.TestCase):
    def test_handle_intercom_accepts_core_rsa_envelope(self):
        proto = _make_protocol()
        proto.identity.public_key = "client-pubkey"
        inner = HiveMessage(HiveMessageType.BUS,
                            Message("speak", {"utterance": "hello"}, {}))
        msg = HiveMessage(HiveMessageType.INTERCOM,
                          {"ciphertext": pybase64.b64encode(b"ciphertext").decode("ascii"),
                           "signature": pybase64.b64encode(b"signature").decode("ascii")},
                          target_pubkey="client-pubkey")

        with patch("hivemind_bus_client.protocol.load_RSA_key", return_value=object()):
            with patch("hivemind_bus_client.protocol.decrypt_RSA", return_value=inner.serialize().encode("utf-8")):
                with patch.object(proto, "handle_bus") as mock_handle_bus:
                    self.assertTrue(proto.handle_intercom(msg))

        mock_handle_bus.assert_called_once()
        self.assertEqual(mock_handle_bus.call_args[0][0].msg_type, HiveMessageType.BUS)

    def test_handle_broadcast_passes_inner_intercom(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.INTERCOM,
                            {"ciphertext": pybase64.b64encode(b"x").decode("ascii"),
                             "signature": pybase64.b64encode(b"y").decode("ascii")})
        msg = HiveMessage(HiveMessageType.BROADCAST, inner)

        with patch.object(proto, "handle_intercom") as mock_handle_intercom:
            proto.handle_broadcast(msg)

        mock_handle_intercom.assert_called_once()
        dispatched = mock_handle_intercom.call_args[0][0]
        self.assertEqual(dispatched.msg_type, HiveMessageType.INTERCOM)
        self.assertEqual(dispatched.payload["ciphertext"], inner.payload["ciphertext"])

    def test_handle_propagate_passes_inner_intercom(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.INTERCOM,
                            {"ciphertext": pybase64.b64encode(b"x").decode("ascii"),
                             "signature": pybase64.b64encode(b"y").decode("ascii")})
        msg = HiveMessage(HiveMessageType.PROPAGATE, inner)

        with patch.object(proto, "handle_intercom") as mock_handle_intercom:
            proto.handle_propagate(msg)

        mock_handle_intercom.assert_called_once()
        dispatched = mock_handle_intercom.call_args[0][0]
        self.assertEqual(dispatched.msg_type, HiveMessageType.INTERCOM)
        self.assertEqual(dispatched.payload["ciphertext"], inner.payload["ciphertext"])

    def test_handle_query_passes_inner_intercom(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.INTERCOM,
                            {"ciphertext": pybase64.b64encode(b"x").decode("ascii"),
                             "signature": pybase64.b64encode(b"y").decode("ascii")})
        msg = HiveMessage(HiveMessageType.QUERY, inner)

        with patch.object(proto, "handle_intercom") as mock_handle_intercom:
            proto.handle_query(msg)

        mock_handle_intercom.assert_called_once()
        dispatched = mock_handle_intercom.call_args[0][0]
        self.assertEqual(dispatched.msg_type, HiveMessageType.INTERCOM)
        self.assertEqual(dispatched.payload["ciphertext"], inner.payload["ciphertext"])
