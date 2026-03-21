"""Tests for PING/PONG on the satellite (client) side."""
import time
import unittest
from unittest.mock import MagicMock, patch

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.serialization import _INT2TYPE, get_bitstring, decode_bitstring


# ---------------------------------------------------------------------------
# Enum / message type tests
# ---------------------------------------------------------------------------

class TestPongEnumExists(unittest.TestCase):
    def test_pong_in_enum(self):
        self.assertIn(HiveMessageType.PONG, list(HiveMessageType))

    def test_pong_value(self):
        self.assertEqual(HiveMessageType.PONG.value, "pong")

    def test_ping_value_unchanged(self):
        self.assertEqual(HiveMessageType.PING.value, "ping")

    def test_pong_in_serialization_map(self):
        self.assertIn(HiveMessageType.PONG, _INT2TYPE.values())

    def test_pong_bitstring_index_is_13(self):
        typemap = {v: k for k, v in _INT2TYPE.items()}
        self.assertEqual(typemap[HiveMessageType.PONG], 13)


class TestPongSerialization(unittest.TestCase):
    def _make_pong_msg(self, ping_id: str = "abc") -> HiveMessage:
        return HiveMessage(
            HiveMessageType.PONG,
            payload={
                "ping_id": ping_id,
                "timestamp": 1000.0,
                "pong_timestamp": 1001.0,
                "peer": "node-b::s1",
                "site_id": "bedroom",
            },
        )

    def test_pong_roundtrip_json(self):
        msg = self._make_pong_msg()
        serialized = msg.as_json
        restored = HiveMessage.deserialize(serialized)
        self.assertEqual(restored.msg_type, HiveMessageType.PONG)

    def test_pong_roundtrip_bitstring(self):
        msg = self._make_pong_msg()
        payload_dict = msg._payload
        bits = get_bitstring(HiveMessageType.PONG, payload_dict)
        decoded = decode_bitstring(bits.bytes)
        self.assertEqual(decoded.msg_type, HiveMessageType.PONG)

    def test_propagate_wrapping_pong(self):
        pong_inner = self._make_pong_msg("ping-1")
        outer = HiveMessage(HiveMessageType.PROPAGATE, payload=pong_inner)
        self.assertEqual(outer.msg_type, HiveMessageType.PROPAGATE)
        self.assertIsInstance(outer.payload, HiveMessage)
        self.assertEqual(outer.payload.msg_type, HiveMessageType.PONG)


class TestPingMessage(unittest.TestCase):
    def test_ping_roundtrip_json(self):
        msg = HiveMessage(HiveMessageType.PING, payload={
            "ping_id": "p1",
            "timestamp": 1000.0,
            "peer": "node-a::s0",
            "site_id": "kitchen",
        })
        serialized = msg.as_json
        restored = HiveMessage.deserialize(serialized)
        self.assertEqual(restored.msg_type, HiveMessageType.PING)

    def test_propagate_wrapping_ping(self):
        ping_inner = HiveMessage(HiveMessageType.PING, {"ping_id": "p1", "timestamp": 1000.0,
                                                        "peer": "a::1", "site_id": ""})
        outer = HiveMessage(HiveMessageType.PROPAGATE, payload=ping_inner)
        self.assertEqual(outer.payload.msg_type, HiveMessageType.PING)


# ---------------------------------------------------------------------------
# Satellite protocol PING/PONG handler tests
# ---------------------------------------------------------------------------

class TestSlaveProtocolPingHandling(unittest.TestCase):
    """Test HiveMindSlaveProtocol._handle_ping and _handle_pong."""

    def _make_slave_proto(self):
        from hivemind_bus_client.protocol import HiveMindSlaveProtocol, HiveMindSlaveInternalProtocol

        hm = MagicMock()
        hm.session_id = "test-session"
        hm.emit = MagicMock()

        internal = MagicMock()
        internal.bus = MagicMock()

        identity = MagicMock()
        identity.name = "test-satellite"
        identity.site_id = "test-room"
        identity.private_key = ""

        proto = HiveMindSlaveProtocol.__new__(HiveMindSlaveProtocol)
        proto.hm = hm
        proto.identity = identity
        proto.internal_protocol = internal
        proto.site_id = "test-room"
        proto.shared_bus = False
        return proto

    def test_handle_ping_emits_pong(self):
        proto = self._make_slave_proto()
        ping_inner = HiveMessage(HiveMessageType.PING, {
            "ping_id": "sat-ping-1",
            "timestamp": 1000.0,
            "peer": "master::sess0",
            "site_id": "hub",
        })
        outer = HiveMessage(HiveMessageType.PROPAGATE, payload=ping_inner)
        proto._handle_ping(outer)
        proto.hm.emit.assert_called_once()
        sent = proto.hm.emit.call_args[0][0]
        self.assertEqual(sent.msg_type, HiveMessageType.PROPAGATE)
        self.assertEqual(sent.payload.msg_type, HiveMessageType.PONG)

    def test_handle_ping_pong_contains_correct_ping_id(self):
        proto = self._make_slave_proto()
        ping_inner = HiveMessage(HiveMessageType.PING, {
            "ping_id": "unique-ping-id",
            "timestamp": 1000.0,
            "peer": "master::sess0",
        })
        outer = HiveMessage(HiveMessageType.PROPAGATE, payload=ping_inner)
        proto._handle_ping(outer)
        sent = proto.hm.emit.call_args[0][0]
        pong_data = sent.payload.payload
        self.assertEqual(pong_data["ping_id"], "unique-ping-id")

    def test_handle_ping_pong_includes_satellite_site_id(self):
        proto = self._make_slave_proto()
        ping_inner = HiveMessage(HiveMessageType.PING, {
            "ping_id": "p1",
            "timestamp": 1000.0,
            "peer": "master::sess0",
        })
        outer = HiveMessage(HiveMessageType.PROPAGATE, payload=ping_inner)
        proto._handle_ping(outer)
        sent = proto.hm.emit.call_args[0][0]
        pong_data = sent.payload.payload
        self.assertEqual(pong_data["site_id"], "test-room")

    def test_handle_ping_emits_bus_event(self):
        proto = self._make_slave_proto()
        ping_inner = HiveMessage(HiveMessageType.PING, {
            "ping_id": "p1",
            "timestamp": 1000.0,
            "peer": "master::sess0",
        })
        outer = HiveMessage(HiveMessageType.PROPAGATE, payload=ping_inner)
        proto._handle_ping(outer)
        proto.internal_protocol.bus.emit.assert_called()
        emitted = proto.internal_protocol.bus.emit.call_args[0][0]
        self.assertEqual(emitted.msg_type, "hive.ping.received")

    def test_handle_pong_emits_bus_event(self):
        proto = self._make_slave_proto()
        pong_inner = HiveMessage(HiveMessageType.PONG, {
            "ping_id": "p1",
            "timestamp": 1000.0,
            "pong_timestamp": 1001.0,
            "peer": "other-node::s2",
            "site_id": "garage",
        })
        outer = HiveMessage(HiveMessageType.PROPAGATE, payload=pong_inner)
        proto._handle_pong(outer)
        proto.internal_protocol.bus.emit.assert_called()
        emitted = proto.internal_protocol.bus.emit.call_args[0][0]
        self.assertEqual(emitted.msg_type, "hive.pong.received")

    def test_handle_propagate_dispatches_ping(self):
        """handle_propagate should call _handle_ping for PING inner types."""
        proto = self._make_slave_proto()
        ping_inner = HiveMessage(HiveMessageType.PING, {
            "ping_id": "p1",
            "timestamp": 1000.0,
            "peer": "master::sess0",
        })
        outer = HiveMessage(HiveMessageType.PROPAGATE, payload=ping_inner)
        proto.handle_propagate(outer)
        # emit was called (PONG + bus event)
        proto.hm.emit.assert_called()

    def test_handle_propagate_dispatches_pong(self):
        """handle_propagate should call _handle_pong for PONG inner types."""
        proto = self._make_slave_proto()
        pong_inner = HiveMessage(HiveMessageType.PONG, {
            "ping_id": "p1",
            "timestamp": 1000.0,
            "pong_timestamp": 1001.0,
            "peer": "other::s2",
            "site_id": "",
        })
        outer = HiveMessage(HiveMessageType.PROPAGATE, payload=pong_inner)
        proto.handle_propagate(outer)
        proto.internal_protocol.bus.emit.assert_called()
        calls = [c[0][0].msg_type for c in proto.internal_protocol.bus.emit.call_args_list]
        self.assertIn("hive.pong.received", calls)


if __name__ == "__main__":
    unittest.main()
