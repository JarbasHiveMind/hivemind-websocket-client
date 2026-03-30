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
        proto.internal_protocol.node_id = "master-1"
        proto.mpubkey = "master-pubkey"
        inner = HiveMessage(HiveMessageType.BUS,
                            Message("speak", {"utterance": "hello"}, {}))
        msg = HiveMessage(HiveMessageType.INTERCOM,
                          {"ciphertext": pybase64.b64encode(b"ciphertext").decode("ascii"),
                           "signature": pybase64.b64encode(b"signature").decode("ascii")},
                          target_pubkey="client-pubkey",
                          source_peer="master-1")

        with patch("hivemind_bus_client.protocol.load_RSA_key", return_value=object()):
            with patch("hivemind_bus_client.protocol.verify_RSA", return_value=True) as mock_verify:
                with patch("hivemind_bus_client.protocol.decrypt_RSA", return_value=inner.serialize().encode("utf-8")):
                    with patch.object(proto, "handle_bus") as mock_handle_bus:
                        self.assertTrue(proto.handle_intercom(msg))

        mock_verify.assert_called_once_with("master-pubkey", b"ciphertext", b"signature")
        mock_handle_bus.assert_called_once()
        self.assertEqual(mock_handle_bus.call_args[0][0].msg_type, HiveMessageType.BUS)

    def test_handle_intercom_accepts_legacy_hybrid_envelope(self):
        proto = _make_protocol()
        proto.identity.public_key = "client-pubkey"
        proto.internal_protocol.node_id = "master-1"
        proto.mpubkey = "master-pubkey"
        inner = HiveMessage(HiveMessageType.BUS,
                            Message("speak", {"utterance": "hello"}, {}))
        msg = HiveMessage(HiveMessageType.INTERCOM,
                          {"ciphertext": pybase64.b64encode(b"ciphertext").decode("ascii"),
                           "signature": pybase64.b64encode(b"signature").decode("ascii"),
                           "encrypted_key": pybase64.b64encode(b"encrypted-key").decode("ascii"),
                           "tag": pybase64.b64encode(b"tag").decode("ascii"),
                           "nonce": pybase64.b64encode(b"nonce").decode("ascii")},
                          target_pubkey="client-pubkey",
                          source_peer="master-1")

        with patch("hivemind_bus_client.protocol.load_RSA_key", return_value=object()):
            with patch("hivemind_bus_client.protocol.verify_RSA", return_value=True) as mock_verify:
                with patch("hivemind_bus_client.protocol.hybrid_decrypt",
                           return_value=inner.serialize().encode("utf-8")):
                    with patch.object(proto, "handle_bus") as mock_handle_bus:
                        self.assertTrue(proto.handle_intercom(msg))

        mock_verify.assert_called_once_with("master-pubkey", b"ciphertext", b"signature")
        mock_handle_bus.assert_called_once()

    def test_handle_intercom_rejects_invalid_signature(self):
        proto = _make_protocol()
        proto.identity.public_key = "client-pubkey"
        proto.internal_protocol.node_id = "master-1"
        proto.mpubkey = "master-pubkey"
        msg = HiveMessage(HiveMessageType.INTERCOM,
                          {"ciphertext": pybase64.b64encode(b"ciphertext").decode("ascii"),
                           "signature": pybase64.b64encode(b"signature").decode("ascii")},
                          target_pubkey="client-pubkey",
                          source_peer="master-1")

        with patch("hivemind_bus_client.protocol.load_RSA_key", return_value=object()):
            with patch("hivemind_bus_client.protocol.verify_RSA", return_value=False):
                with patch.object(proto, "handle_bus") as mock_handle_bus:
                    self.assertFalse(proto.handle_intercom(msg))

        mock_handle_bus.assert_not_called()

    def test_handle_intercom_rejects_decryption_failure(self):
        proto = _make_protocol()
        proto.identity.public_key = "client-pubkey"
        proto.internal_protocol.node_id = "master-1"
        proto.mpubkey = "master-pubkey"
        msg = HiveMessage(HiveMessageType.INTERCOM,
                          {"ciphertext": pybase64.b64encode(b"ciphertext").decode("ascii"),
                           "signature": pybase64.b64encode(b"signature").decode("ascii")},
                          target_pubkey="client-pubkey",
                          source_peer="master-1")

        with patch("hivemind_bus_client.protocol.load_RSA_key", return_value=object()):
            with patch("hivemind_bus_client.protocol.verify_RSA", return_value=True):
                with patch("hivemind_bus_client.protocol.decrypt_RSA", side_effect=ValueError("bad key")):
                    with patch.object(proto, "handle_bus") as mock_handle_bus:
                        self.assertFalse(proto.handle_intercom(msg))

        mock_handle_bus.assert_not_called()

    def test_handle_intercom_rejects_missing_ciphertext(self):
        proto = _make_protocol()
        proto.identity.public_key = "client-pubkey"
        proto.internal_protocol.node_id = "master-1"
        proto.mpubkey = "master-pubkey"
        msg = HiveMessage(HiveMessageType.INTERCOM,
                          {"signature": pybase64.b64encode(b"signature").decode("ascii")},
                          target_pubkey="client-pubkey",
                          source_peer="master-1")

        with patch.object(proto, "handle_bus") as mock_handle_bus:
            self.assertFalse(proto.handle_intercom(msg))

        mock_handle_bus.assert_not_called()

    def test_handle_intercom_rejects_malformed_base64(self):
        proto = _make_protocol()
        proto.identity.public_key = "client-pubkey"
        proto.internal_protocol.node_id = "master-1"
        proto.mpubkey = "master-pubkey"
        msg = HiveMessage(HiveMessageType.INTERCOM,
                          {"ciphertext": "!!!", "signature": "???"},
                          target_pubkey="client-pubkey",
                          source_peer="master-1")

        with patch("hivemind_bus_client.protocol.load_RSA_key", return_value=object()):
            with patch("hivemind_bus_client.protocol.pybase64.b64decode", side_effect=ValueError("bad b64")):
                with patch.object(proto, "handle_bus") as mock_handle_bus:
                    self.assertFalse(proto.handle_intercom(msg))

        mock_handle_bus.assert_not_called()

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

    def test_dispatch_intercom_handles_ping(self):
        proto = _make_protocol()
        ping = HiveMessage(HiveMessageType.PING, {"flood_id": "abc", "peer": "other"})

        with patch.object(proto, "_handle_ping") as mock_handle_ping:
            self.assertTrue(proto._dispatch_intercom_payload(ping))

        wrapper = mock_handle_ping.call_args[0][0]
        self.assertEqual(wrapper.msg_type, HiveMessageType.PROPAGATE)
        self.assertEqual(wrapper.payload.msg_type, HiveMessageType.PING)
