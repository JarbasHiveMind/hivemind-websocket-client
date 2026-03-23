"""Tests for hivemind_bus_client.protocol — HiveMindSlaveProtocol PING handling."""
from unittest.mock import MagicMock, patch
import pytest

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol
from hivemind_bus_client.identity import NodeIdentity


def _make_protocol() -> HiveMindSlaveProtocol:
    """Create a minimal HiveMindSlaveProtocol with mocked dependencies."""
    hm = MagicMock()
    hm.session_id = "test-session"
    identity = MagicMock(spec=NodeIdentity)
    identity.name = "test-node"
    identity.password = "test"
    proto = HiveMindSlaveProtocol(hm=hm, identity=identity, site_id="living-room")
    proto._seen_flood_ids = set()
    return proto


class TestHandlePing:
    def test_sends_responsive_ping(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "abc", "peer": "other"})
        outer = HiveMessage(HiveMessageType.PROPAGATE, inner)
        proto._handle_ping(outer)

        proto.hm.emit.assert_called_once()
        sent = proto.hm.emit.call_args[0][0]
        assert sent.msg_type == HiveMessageType.PROPAGATE
        inner_sent = sent.payload
        assert isinstance(inner_sent, HiveMessage)
        assert inner_sent.msg_type == HiveMessageType.PING
        payload = inner_sent.payload
        assert payload["flood_id"] == "abc"
        assert payload["peer"] == "test-node::test-session"
        assert payload["site_id"] == "living-room"

    def test_duplicate_flood_id_ignored(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "abc", "peer": "other"})
        outer = HiveMessage(HiveMessageType.PROPAGATE, inner)
        proto._handle_ping(outer)
        proto.hm.emit.reset_mock()

        # Second call with same flood_id
        proto._handle_ping(outer)
        proto.hm.emit.assert_not_called()

    def test_empty_flood_id_ignored(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "", "peer": "other"})
        outer = HiveMessage(HiveMessageType.PROPAGATE, inner)
        proto._handle_ping(outer)
        proto.hm.emit.assert_not_called()

    def test_flood_id_set_capped(self):
        """When _seen_flood_ids reaches 1000, oldest entries are evicted."""
        proto = _make_protocol()
        proto._seen_flood_ids = {str(i) for i in range(1000)}
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "new", "peer": "other"})
        outer = HiveMessage(HiveMessageType.PROPAGATE, inner)
        proto._handle_ping(outer)
        assert "new" in proto._seen_flood_ids
        assert len(proto._seen_flood_ids) == 1000

    def test_different_flood_ids_both_processed(self):
        proto = _make_protocol()
        for fid in ["flood1", "flood2"]:
            inner = HiveMessage(HiveMessageType.PING, {"flood_id": fid, "peer": "other"})
            outer = HiveMessage(HiveMessageType.PROPAGATE, inner)
            proto._handle_ping(outer)
        assert proto.hm.emit.call_count == 2


class TestHandleQuery:
    def _make_protocol_with_bus(self):
        proto = _make_protocol()
        proto.internal_protocol = MagicMock()
        proto.internal_protocol.node_id = "master-1"
        proto.internal_protocol.bus = MagicMock()
        return proto

    def test_bus_payload_dispatches_to_handle_bus(self):
        """QUERY with inner BUS payload should call handle_bus."""
        proto = self._make_protocol_with_bus()
        inner_bus = HiveMessage(HiveMessageType.BUS,
                                {"type": "speak", "data": {"utterance": "hello"}, "context": {}})
        query_msg = HiveMessage(HiveMessageType.QUERY, payload=inner_bus)

        with patch.object(proto, 'handle_bus') as mock_bus:
            proto.handle_query(query_msg)
            mock_bus.assert_called_once_with(query_msg)

    def test_intercom_payload_dispatches_to_handle_intercom(self):
        """QUERY with inner INTERCOM payload should call handle_intercom."""
        proto = self._make_protocol_with_bus()
        inner_bus = HiveMessage(HiveMessageType.BUS,
                                {"type": "speak", "data": {}, "context": {}})
        inner_intercom = HiveMessage(HiveMessageType.INTERCOM, payload=inner_bus)
        query_msg = HiveMessage(HiveMessageType.QUERY, payload=inner_intercom)

        with patch.object(proto, 'handle_intercom') as mock_intercom:
            proto.handle_query(query_msg)
            mock_intercom.assert_called_once_with(query_msg)

    def test_invalid_inner_type_raises(self):
        """QUERY with non-BUS/INTERCOM inner payload should raise AssertionError."""
        proto = self._make_protocol_with_bus()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "x"})
        query_msg = HiveMessage(HiveMessageType.QUERY, payload=inner)

        with pytest.raises(AssertionError):
            proto.handle_query(query_msg)


class TestHandleCascade:
    def _make_protocol_with_bus(self):
        proto = _make_protocol()
        proto.internal_protocol = MagicMock()
        proto.internal_protocol.node_id = "master-1"
        proto.internal_protocol.bus = MagicMock()
        return proto

    def test_bus_payload_dispatches_to_handle_bus(self):
        """CASCADE with inner BUS payload should call handle_bus."""
        proto = self._make_protocol_with_bus()
        inner_bus = HiveMessage(HiveMessageType.BUS,
                                {"type": "speak", "data": {"utterance": "hi"}, "context": {}})
        cascade_msg = HiveMessage(HiveMessageType.CASCADE, payload=inner_bus)

        with patch.object(proto, 'handle_bus') as mock_bus:
            proto.handle_cascade(cascade_msg)
            mock_bus.assert_called_once_with(cascade_msg)

    def test_intercom_payload_dispatches_to_handle_intercom(self):
        """CASCADE with inner INTERCOM payload should call handle_intercom."""
        proto = self._make_protocol_with_bus()
        inner_bus = HiveMessage(HiveMessageType.BUS,
                                {"type": "speak", "data": {}, "context": {}})
        inner_intercom = HiveMessage(HiveMessageType.INTERCOM, payload=inner_bus)
        cascade_msg = HiveMessage(HiveMessageType.CASCADE, payload=inner_intercom)

        with patch.object(proto, 'handle_intercom') as mock_intercom:
            proto.handle_cascade(cascade_msg)
            mock_intercom.assert_called_once_with(cascade_msg)

    def test_invalid_inner_type_raises(self):
        """CASCADE with non-BUS/INTERCOM inner payload should raise AssertionError."""
        proto = self._make_protocol_with_bus()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "x"})
        cascade_msg = HiveMessage(HiveMessageType.CASCADE, payload=inner)

        with pytest.raises(AssertionError):
            proto.handle_cascade(cascade_msg)


class TestHandlePropagate:
    def test_ping_dispatched(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "abc", "peer": "x"})
        outer = HiveMessage(HiveMessageType.PROPAGATE, inner)

        with patch.object(proto, '_handle_ping') as mock_ping:
            proto.handle_propagate(outer)
            mock_ping.assert_called_once_with(outer)
