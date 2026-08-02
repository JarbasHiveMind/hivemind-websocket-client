"""Tests for hivemind_bus_client.message — HiveMessage, HiveMessageType, HiveMindBinaryPayloadType."""
import json
import pytest
from ovos_bus_client.message import Message
from hivemind_bus_client.message import HiveMessage, HiveMessageType, HiveMindBinaryPayloadType


class TestHiveMessageType:
    """Verify enum values match the wire protocol."""

    def test_all_types_are_strings(self):
        for member in HiveMessageType:
            assert isinstance(member.value, str)

    def test_known_values(self):
        assert HiveMessageType.BUS == "bus"
        assert HiveMessageType.PROPAGATE == "propagate"
        assert HiveMessageType.PING == "ping"
        assert HiveMessageType.BINARY == "bin"
        assert HiveMessageType.HANDSHAKE == "shake"

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="Unknown HiveMessage.msg_type"):
            HiveMessage("nonexistent", {})


class TestHiveMindBinaryPayloadType:
    def test_values_are_ints(self):
        for member in HiveMindBinaryPayloadType:
            assert isinstance(member.value, int)

    def test_bin_type_only_for_binary(self):
        with pytest.raises(ValueError, match="bin_type can only be set"):
            HiveMessage(HiveMessageType.BUS, Message("test", {}),
                        bin_type=HiveMindBinaryPayloadType.TTS_AUDIO)


class TestHiveMessageInit:
    """Constructor and payload normalization."""

    def test_from_mycroft_message(self):
        msg = Message("speak", {"utterance": "hi"})
        hm = HiveMessage(HiveMessageType.BUS, msg)
        assert hm._payload["type"] == "speak"
        assert hm._payload["data"]["utterance"] == "hi"

    def test_from_json_string(self):
        payload_str = json.dumps({"type": "speak", "data": {"utterance": "hi"}, "context": {}})
        hm = HiveMessage(HiveMessageType.BUS, payload_str)
        assert hm._payload["type"] == "speak"

    def test_from_dict(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {"custom": "data"})
        assert hm._payload["custom"] == "data"

    def test_none_payload_becomes_empty_dict(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY)
        assert hm._payload == {}

    def test_binary_requires_bytes(self):
        with pytest.raises(ValueError, match="expected 'bytes'"):
            HiveMessage(HiveMessageType.BINARY, "not bytes")

    def test_binary_with_bytes(self):
        data = b"\x00\x01\x02"
        hm = HiveMessage(HiveMessageType.BINARY, data,
                          bin_type=HiveMindBinaryPayloadType.RAW_AUDIO)
        assert hm.payload == data
        assert hm.bin_type == HiveMindBinaryPayloadType.RAW_AUDIO


class TestHiveMessagePayloadProperty:
    """Test the payload getter reconstructs correct types."""

    def test_bus_returns_mycroft_message(self):
        hm = HiveMessage(HiveMessageType.BUS,
                          Message("speak", {"utterance": "hello"}))
        payload = hm.payload
        assert isinstance(payload, Message)
        assert payload.msg_type == "speak"

    def test_propagate_returns_hive_message(self):
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "x"})
        outer = HiveMessage(HiveMessageType.PROPAGATE, inner)
        payload = outer.payload
        assert isinstance(payload, HiveMessage)
        assert payload.msg_type == HiveMessageType.PING

    def test_thirdparty_returns_dict(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {"foo": "bar"})
        assert isinstance(hm.payload, dict)
        assert hm.payload["foo"] == "bar"


class TestHiveMessageSerialization:
    def test_serialize_deserialize_roundtrip(self):
        msg = Message("speak", {"utterance": "hi"}, {"source": "test"})
        hm = HiveMessage(HiveMessageType.BUS, msg,
                          target_site_id="kitchen")
        serialized = hm.serialize()
        restored = HiveMessage.deserialize(serialized)
        assert restored.msg_type == HiveMessageType.BUS
        assert restored.target_site_id == "kitchen"

    def test_deserialize_from_dict(self):
        d = {"msg_type": "ping", "payload": {"flood_id": "abc"},
             "metadata": {}}
        restored = HiveMessage.deserialize(d)
        assert restored.msg_type == HiveMessageType.PING
        assert restored.payload["flood_id"] == "abc"

    def test_deserialize_mycroft_message(self):
        d = {"type": "speak", "data": {"utterance": "hi"}, "context": {}}
        restored = HiveMessage.deserialize(d)
        assert restored.msg_type == HiveMessageType.BUS

    def test_deserialize_unknown_falls_to_thirdparty(self):
        d = {"random_key": "value"}
        restored = HiveMessage.deserialize(d)
        assert restored.msg_type == HiveMessageType.THIRDPRTY

    def test_as_dict(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {"k": "v"},
                          node="node1", source_peer="peer1")
        d = hm.as_dict
        assert d["msg_type"] == HiveMessageType.THIRDPRTY
        assert d["payload"] == {"k": "v"}
        assert d["node"] == "node1"
        assert d["source_peer"] == "peer1"

    def test_binary_as_dict_raises(self):
        hm = HiveMessage(HiveMessageType.BINARY, b"\x00")
        with pytest.raises(ValueError, match="BINARY"):
            hm.as_dict


class TestHiveMessageRouting:
    def test_route_filters_incomplete_hops(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {},
                          route=[{"source": "a", "targets": ["b"]},
                                 {"source": "", "targets": []},
                                 {"source": "c", "targets": []}])
        # only hops with both source and targets are kept
        assert len(hm.route) == 1
        assert hm.route[0]["source"] == "a"

    def test_target_peers_defaults_to_source(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {},
                          source_peer="peer1")
        assert hm.target_peers == ["peer1"]

    def test_update_hop_data(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {},
                          source_peer="a", target_peers=["b"])
        hm.update_hop_data()
        assert len(hm._route) == 1
        assert hm._route[0]["source"] == "a"

    def test_replace_route(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {})
        new_route = [{"source": "x", "targets": ["y"]}]
        hm.replace_route(new_route)
        assert hm.route == new_route

    def test_add_remove_target_peer(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {})
        hm.add_target_peer("peer1")
        assert "peer1" in hm._targets
        hm.remove_target_peer("peer1")
        assert "peer1" not in hm._targets

    def test_update_source_peer(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {})
        result = hm.update_source_peer("new_peer")
        assert hm.source_peer == "new_peer"
        assert result is hm  # returns self for chaining


class TestHiveMessageItemAccess:
    def test_getitem(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {"key": "value"})
        assert hm["key"] == "value"
        assert hm["missing"] is None

    def test_setitem(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {"key": "old"})
        hm["key"] = "new"
        assert hm["key"] == "new"

    def test_getitem_non_dict_raises(self):
        hm = HiveMessage(HiveMessageType.BINARY, b"\x00")
        with pytest.raises(TypeError):
            _ = hm["key"]

    def test_setitem_non_dict_raises(self):
        hm = HiveMessage(HiveMessageType.BINARY, b"\x00")
        with pytest.raises(TypeError):
            hm["key"] = "value"


class TestHiveMessageStr:
    def test_str_normal(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {"k": "v"})
        s = str(hm)
        parsed = json.loads(s)
        assert parsed["msg_type"] == "3rdparty"

    def test_str_binary(self):
        hm = HiveMessage(HiveMessageType.BINARY, b"\x00\x01\x02")
        assert "BINARY" in str(hm)
        assert "3" in str(hm)  # length


class TestHiveMessagePayloadSetter:
    def test_set_message_payload(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {"old": "data"})
        new_msg = Message("speak", {"utterance": "hi"})
        hm.payload = new_msg
        # Stored as dict internally
        assert isinstance(hm._payload, dict)

    def test_set_hive_message_payload(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {"old": "data"})
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "x"})
        hm.payload = inner
        assert isinstance(hm._payload, dict)

    def test_set_dict_payload(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {"old": "data"})
        hm.payload = {"new": "data"}
        assert hm._payload == {"new": "data"}

    def test_set_bytes_payload(self):
        hm = HiveMessage(HiveMessageType.BINARY, b"\x00")
        hm.payload = b"\x01\x02"
        assert hm._payload == b"\x01\x02"


class TestHiveMessageTargetPeers:
    def test_target_peers_with_source_peer_fallback(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {},
                          source_peer="peer1")
        assert hm.target_peers == ["peer1"]

    def test_target_peers_explicit(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {},
                          source_peer="peer1", target_peers=["peer2"])
        assert hm.target_peers == ["peer2"]

    def test_target_peers_no_source(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {})
        assert hm.target_peers == []


class TestHiveMessageUpdateHopData:
    def test_update_hop_with_data_merge(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {},
                          source_peer="a", target_peers=["b"])
        hm.update_hop_data(data={"extra": "info"})
        assert len(hm._route) == 1
        assert hm._route[0]["extra"] == "info"

    def test_update_hop_same_source_no_duplicate(self):
        hm = HiveMessage(HiveMessageType.THIRDPRTY, {},
                          source_peer="a", target_peers=["b"])
        hm.update_hop_data()
        hm.update_hop_data()  # same source, should not duplicate
        assert len(hm._route) == 1


class TestDeserializePreservesFields:
    """Regression tests for deserialize() restoring serialized fields."""

    def test_serialize_deserialize_preserves_route(self):
        route = [{"source": "peer-A", "targets": ["peer-B", "peer-C"]}]
        msg = HiveMessage(HiveMessageType.BUS,
                          payload=Message("test", {}, {}),
                          source_peer="peer-A", target_peers=["peer-B", "peer-C"])
        msg.replace_route(route)
        restored = HiveMessage.deserialize(msg.as_dict)
        assert restored.route == route

    def test_source_peer_not_preserved_through_deserialize(self):
        """source_peer is per-hop transient — intentionally NOT restored."""
        msg = HiveMessage(HiveMessageType.BUS,
                          payload=Message("test", {}, {}),
                          source_peer="peer-X")
        restored = HiveMessage.deserialize(msg.serialize())
        assert restored.source_peer is None

    def test_node_not_preserved_through_deserialize(self):
        """node is per-hop transient — intentionally NOT restored."""
        msg = HiveMessage(HiveMessageType.BUS,
                          payload=Message("test", {}, {}),
                          node="node-42")
        restored = HiveMessage.deserialize(msg.serialize())
        assert restored.node_id is None

    def test_route_entries_are_dicts(self):
        route = [{"source": "p1", "targets": ["p2"]}, {"source": "p2", "targets": ["p3"]}]
        msg = HiveMessage(HiveMessageType.BUS, payload=Message("t", {}, {}))
        msg.replace_route(route)
        for hop in msg.route:
            assert isinstance(hop, dict)
            assert "source" in hop
            assert "targets" in hop


class TestForward:
    """forward() must not lose envelope fields."""

    @staticmethod
    def _full():
        return HiveMessage(HiveMessageType.PROPAGATE,
                           payload={"msg_type": "bus", "payload": {"type": "t"}},
                           node="node-1",
                           source_peer="peer-A",
                           route=[{"source": "peer-A", "targets": ["peer-B"]}],
                           target_peers=["peer-B", "peer-C"],
                           target_site_id="site-1",
                           target_pubkey="pubkey-1",
                           metadata={"k": "v"})

    def test_forward_preserves_every_field(self):
        original = self._full()
        fwd = original.forward()
        assert fwd.msg_type == original.msg_type
        assert fwd._payload == original._payload
        assert fwd.node_id == "node-1"
        assert fwd.source_peer == "peer-A"
        assert fwd.route == original.route
        assert fwd._targets == ["peer-B", "peer-C"]
        assert fwd.target_site_id == "site-1"
        assert fwd.target_public_key == "pubkey-1"
        assert fwd.metadata == {"k": "v"}
        assert fwd.bin_type == original.bin_type

    def test_forward_preserves_constructor_only_fields(self):
        """metadata, target_site_id, target_pubkey, node and bin_type have no
        setter, so a hand-rebuilt envelope is where they go missing."""
        fwd = self._full().forward(source_peer="peer-B", target_peers=["peer-D"])
        assert fwd.metadata == {"k": "v"}
        assert fwd.target_site_id == "site-1"
        assert fwd.target_public_key == "pubkey-1"
        assert fwd.node_id == "node-1"

    def test_forward_preserves_bin_type(self):
        original = HiveMessage(HiveMessageType.BINARY, payload=b"\x01\x02",
                               bin_type=HiveMindBinaryPayloadType.RAW_AUDIO)
        assert original.forward().bin_type == HiveMindBinaryPayloadType.RAW_AUDIO

    def test_explicit_override_wins(self):
        fwd = self._full().forward(msg_type=HiveMessageType.CASCADE,
                                   source_peer="peer-B",
                                   target_peers=["peer-D"],
                                   metadata={"other": 1},
                                   route=[],
                                   payload={"msg_type": "bus", "payload": {"type": "u"}})
        assert fwd.msg_type == HiveMessageType.CASCADE
        assert fwd.source_peer == "peer-B"
        assert fwd._targets == ["peer-D"]
        assert fwd.metadata == {"other": 1}
        assert fwd.route == []
        assert fwd._payload["payload"]["type"] == "u"

    def test_explicit_none_drops_the_field(self):
        fwd = self._full().forward(target_site_id=None, target_pubkey=None)
        assert fwd.target_site_id is None
        assert fwd.target_public_key is None

    def test_forward_does_not_mutate_the_original(self):
        original = self._full()
        fwd = original.forward()
        fwd.add_target_peer("peer-Z")
        fwd.replace_route([])
        assert original._targets == ["peer-B", "peer-C"]
        assert original.route == [{"source": "peer-A", "targets": ["peer-B"]}]


class TestAsDictRoundTrip:
    """HiveMessage(**msg.as_dict) must be faithful."""

    def test_constructor_round_trip_is_faithful(self):
        msg = HiveMessage(HiveMessageType.BUS, payload=Message("t", {"a": 1}, {}),
                          node="node-1", source_peer="peer-A",
                          route=[{"source": "peer-A", "targets": ["peer-B"]}],
                          target_site_id="site-1", target_pubkey="pubkey-1",
                          metadata={"k": "v"})
        clone = HiveMessage(**msg.as_dict)
        assert clone.as_dict == msg.as_dict

    def test_target_peers_stays_off_the_wire(self):
        """target_peers is a next-hop decision carried by forward(), not a wire
        field. See TestWireSizeCeiling for why it cannot become one."""
        msg = HiveMessage(HiveMessageType.BUS, payload=Message("t", {}, {}),
                          target_peers=["peer-B"])
        assert "target_peers" not in msg.as_dict
        assert msg.forward()._targets == ["peer-B"]

    def test_frame_from_an_older_peer_still_deserializes(self):
        old_frame = json.dumps({"msg_type": "bus",
                                "payload": {"type": "t", "data": {}, "context": {}},
                                "metadata": {}, "route": [], "node": None,
                                "target_site_id": None, "target_pubkey": None,
                                "source_peer": None})
        restored = HiveMessage.deserialize(old_frame)
        assert restored.msg_type == HiveMessageType.BUS
        assert restored._targets == []

    def test_unknown_future_keys_are_ignored(self):
        """A peer that sends keys we do not know must not break us."""
        frame = json.dumps({"msg_type": "bus", "payload": {"type": "t"},
                            "target_peers": ["peer-B"],
                            "some_future_field": "ignore me"})
        assert HiveMessage.deserialize(frame).msg_type == HiveMessageType.BUS


class TestWireSizeCeiling:
    """A serialized envelope must fit one RSA block.

    hivemind-core encrypts an INTERCOM inner body with raw RSA (PKCS1-OAEP),
    which cannot be split across blocks. With 2048-bit identity keys the
    ceiling is 214 bytes. The smallest useful BUS envelope is already ~207,
    so the format has almost no headroom: adding one short key to as_dict
    ("target_peers": [] costs 20 bytes) pushes real INTERCOM traffic over the
    limit and a satellite that worked yesterday starts failing on payload
    size. If this test fails because you added a field to as_dict, the field
    does not go on the wire - carry it through forward() instead.
    """

    RSA_2048_OAEP_MAX_BYTES = 214

    def test_minimal_bus_envelope_fits_one_rsa_block(self):
        inner = HiveMessage(HiveMessageType.BUS,
                            payload=Message("recognizer_loop:utterance", {}))
        size = len(inner.serialize().encode("utf-8"))
        assert size <= self.RSA_2048_OAEP_MAX_BYTES, (
            f"serialized envelope grew to {size} bytes, over the "
            f"{self.RSA_2048_OAEP_MAX_BYTES}-byte RSA block limit; "
            f"INTERCOM traffic will fail with 'Plaintext is too long'")

    def test_as_dict_keys_are_pinned(self):
        """Pinned on purpose. Changing this set changes every frame on the
        wire, so it should be a deliberate edit with a size measurement."""
        msg = HiveMessage(HiveMessageType.BUS, payload=Message("t", {}, {}))
        assert set(msg.as_dict) == {"msg_type", "payload", "metadata", "route",
                                    "node", "target_site_id", "target_pubkey",
                                    "source_peer"}


class TestPayloadIdentity:
    """Repeated payload access must return the same object."""

    def test_bus_payload_is_stable(self):
        msg = HiveMessage(HiveMessageType.BUS, payload=Message("t", {"a": 1}, {}))
        assert msg.payload is msg.payload

    def test_wrapper_payload_is_stable(self):
        msg = HiveMessage(HiveMessageType.PROPAGATE,
                          payload={"msg_type": "bus", "payload": {"type": "t"}})
        assert msg.payload is msg.payload

    def test_mutation_through_payload_survives(self):
        msg = HiveMessage(HiveMessageType.BUS, payload=Message("t", {"a": 1}, {}))
        msg.payload.context["session"] = "sess-1"
        assert msg.payload.context["session"] == "sess-1"

    def test_dict_payload_is_stable(self):
        msg = HiveMessage(HiveMessageType.THIRDPRTY, payload={"a": 1})
        assert msg.payload is msg.payload

    def test_setting_payload_invalidates_the_cached_view(self):
        msg = HiveMessage(HiveMessageType.BUS, payload=Message("t", {"a": 1}, {}))
        assert msg.payload.msg_type == "t"
        msg.payload = Message("u", {}, {})
        assert msg.payload.msg_type == "u"

    def test_item_assignment_invalidates_the_cached_view(self):
        msg = HiveMessage(HiveMessageType.BUS, payload=Message("t", {"a": 1}, {}))
        assert msg.payload.msg_type == "t"
        msg["type"] = "u"
        assert msg.payload.msg_type == "u"
