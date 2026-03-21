import json
import unittest

from ovos_bus_client import Message

from hivemind_bus_client.message import HiveMessage, HiveMessageType, HiveMindBinaryPayloadType


class TestHiveMessageType(unittest.TestCase):
    def test_all_types_are_strings(self):
        for t in HiveMessageType:
            self.assertIsInstance(t.value, str)

    def test_known_types_exist(self):
        self.assertEqual(HiveMessageType.BUS.value, "bus")
        self.assertEqual(HiveMessageType.HANDSHAKE.value, "shake")
        self.assertEqual(HiveMessageType.BINARY.value, "bin")


class TestHiveMessageCreation(unittest.TestCase):
    def test_bus_message(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={"type": "test", "data": {}, "context": {}})
        self.assertEqual(msg.msg_type, HiveMessageType.BUS)

    def test_binary_message(self):
        msg = HiveMessage(HiveMessageType.BINARY, payload=b"\x00\x01\x02",
                          bin_type=HiveMindBinaryPayloadType.RAW_AUDIO)
        self.assertEqual(msg.msg_type, HiveMessageType.BINARY)
        self.assertEqual(msg.bin_type, HiveMindBinaryPayloadType.RAW_AUDIO)

    def test_invalid_msg_type_raises(self):
        with self.assertRaises(ValueError):
            HiveMessage("not_a_real_type")

    def test_binary_without_bytes_payload_raises(self):
        with self.assertRaises(ValueError):
            HiveMessage(HiveMessageType.BINARY, payload={"not": "bytes"})

    def test_bin_type_on_non_binary_raises(self):
        with self.assertRaises(ValueError):
            HiveMessage(HiveMessageType.BUS, payload={},
                        bin_type=HiveMindBinaryPayloadType.RAW_AUDIO)

    def test_string_payload_parsed_as_json(self):
        data = json.dumps({"type": "test", "data": {}, "context": {}})
        msg = HiveMessage(HiveMessageType.BUS, payload=data)
        self.assertIsInstance(msg._payload, dict)

    def test_ovos_message_payload_normalized(self):
        m = Message("speak", {"utterance": "hello"})
        msg = HiveMessage(HiveMessageType.BUS, payload=m)
        self.assertIsInstance(msg._payload, dict)
        self.assertEqual(msg._payload["type"], "speak")


class TestHiveMessageProperties(unittest.TestCase):
    def test_node_id(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={}, node="node-1")
        self.assertEqual(msg.node_id, "node-1")

    def test_source_peer(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={}, source_peer="peer-1")
        self.assertEqual(msg.source_peer, "peer-1")

    def test_target_peers_defaults_to_source(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={}, source_peer="peer-1")
        self.assertEqual(msg.target_peers, ["peer-1"])

    def test_explicit_target_peers(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={}, target_peers=["p1", "p2"])
        self.assertIn("p1", msg.target_peers)
        self.assertIn("p2", msg.target_peers)

    def test_metadata(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={}, metadata={"key": "val"})
        self.assertEqual(msg.metadata["key"], "val")

    def test_target_site_id(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={}, target_site_id="site-1")
        self.assertEqual(msg.target_site_id, "site-1")

    def test_target_public_key(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={}, target_pubkey="pubkey-abc")
        self.assertEqual(msg.target_public_key, "pubkey-abc")


class TestHiveMessagePayloadProperty(unittest.TestCase):
    def test_bus_payload_returns_message(self):
        m = Message("speak", {"utterance": "hello"})
        msg = HiveMessage(HiveMessageType.BUS, payload=m)
        result = msg.payload
        self.assertIsInstance(result, Message)
        self.assertEqual(result.msg_type, "speak")

    def test_shared_bus_payload_returns_message(self):
        m = Message("test.event", {})
        msg = HiveMessage(HiveMessageType.SHARED_BUS, payload=m)
        self.assertIsInstance(msg.payload, Message)

    def test_binary_payload_returns_bytes(self):
        msg = HiveMessage(HiveMessageType.BINARY, payload=b"\xff\xfe")
        self.assertEqual(msg.payload, b"\xff\xfe")

    def test_thirdparty_payload_returns_dict(self):
        msg = HiveMessage(HiveMessageType.THIRDPRTY, payload={"custom": "data"})
        self.assertIsInstance(msg.payload, dict)


class TestHiveMessageSerialization(unittest.TestCase):
    def test_as_dict(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={"type": "test", "data": {}, "context": {}},
                          node="n1", source_peer="p1")
        d = msg.as_dict
        self.assertIn("msg_type", d)
        self.assertIn("payload", d)
        self.assertEqual(d["node"], "n1")

    def test_binary_as_dict_raises(self):
        msg = HiveMessage(HiveMessageType.BINARY, payload=b"\x00")
        with self.assertRaises(ValueError):
            _ = msg.as_dict

    def test_as_json(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={"type": "test", "data": {}, "context": {}})
        j = msg.as_json
        self.assertIsInstance(j, str)
        parsed = json.loads(j)
        self.assertEqual(parsed["msg_type"], "bus")

    def test_serialize(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={"type": "t", "data": {}, "context": {}})
        s = msg.serialize()
        self.assertEqual(s, msg.as_json)

    def test_deserialize_hivemessage(self):
        original = HiveMessage(HiveMessageType.BUS,
                                payload={"type": "speak", "data": {"utterance": "hi"}, "context": {}})
        serialized = original.serialize()
        restored = HiveMessage.deserialize(serialized)
        self.assertEqual(restored.msg_type, "bus")

    def test_deserialize_plain_mycroft_message(self):
        m = Message("speak", {"utterance": "hello"})
        restored = HiveMessage.deserialize(m.serialize())
        self.assertIsNotNone(restored)


class TestHiveMessageMutation(unittest.TestCase):
    def test_update_source_peer(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={}, source_peer="old")
        msg.update_source_peer("new")
        self.assertEqual(msg.source_peer, "new")

    def test_add_target_peer(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={})
        msg.add_target_peer("peer-1")
        self.assertIn("peer-1", msg._targets)

    def test_remove_target_peer(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={}, target_peers=["p1", "p2"])
        msg.remove_target_peer("p1")
        self.assertNotIn("p1", msg._targets)

    def test_replace_route(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={})
        route = [{"source": "s1", "targets": ["t1"]}]
        msg.replace_route(route)
        self.assertEqual(msg._route, route)

    def test_item_access(self):
        msg = HiveMessage(HiveMessageType.THIRDPRTY, payload={"key": "value"})
        self.assertEqual(msg["key"], "value")

    def test_item_set(self):
        msg = HiveMessage(HiveMessageType.THIRDPRTY, payload={})
        msg["key"] = "value"
        self.assertEqual(msg["key"], "value")

    def test_item_access_non_dict_raises(self):
        msg = HiveMessage(HiveMessageType.BINARY, payload=b"\x00")
        with self.assertRaises(TypeError):
            _ = msg["key"]


class TestHiveMessageStr(unittest.TestCase):
    def test_str_non_binary(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={"type": "t", "data": {}, "context": {}})
        s = str(msg)
        self.assertIsInstance(s, str)

    def test_str_binary(self):
        msg = HiveMessage(HiveMessageType.BINARY, payload=b"\x00\x01")
        s = str(msg)
        self.assertIn("BINARY", s)


class TestHiveMessageInitNormalization(unittest.TestCase):
    """Regression tests for HiveMessage.__init__ payload normalization."""

    def test_nested_hivemessage_payload_normalized_to_dict(self):
        """Regression: __init__ did not normalize HiveMessage payloads to dict (only the
        payload.setter did). Passing a nested HiveMessage caused _payload to hold a
        HiveMessage object, making message.payload crash with TypeError: argument after
        ** must be a mapping, not HiveMessage."""
        inner = HiveMessage(HiveMessageType.BUS,
                            payload={"type": "test", "data": {}, "context": {}})
        outer = HiveMessage(HiveMessageType.BROADCAST, payload=inner)
        self.assertIsInstance(outer._payload, dict,
                              "_payload must be dict, not a HiveMessage object")

    def test_nested_hivemessage_payload_property_works(self):
        """payload property must return a reconstructed HiveMessage without crashing."""
        inner = HiveMessage(HiveMessageType.BUS,
                            payload={"type": "test", "data": {}, "context": {}})
        outer = HiveMessage(HiveMessageType.BROADCAST, payload=inner)
        result = outer.payload
        self.assertIsInstance(result, HiveMessage)
        self.assertEqual(result.msg_type, HiveMessageType.BUS)

    def test_broadcast_with_nested_hivemessage_serializes(self):
        """as_dict must work when payload is originally a HiveMessage."""
        inner = HiveMessage(HiveMessageType.BUS,
                            payload={"type": "test", "data": {}, "context": {}})
        outer = HiveMessage(HiveMessageType.BROADCAST, payload=inner)
        d = outer.as_dict
        self.assertIn("msg_type", d)
        self.assertEqual(d["msg_type"], HiveMessageType.BROADCAST)


class TestDeserializePreservesFields(unittest.TestCase):
    """Regression tests for deserialize() restoring all serialized fields."""

    def test_serialize_deserialize_preserves_route(self):
        """Route data must survive as_dict → deserialize() roundtrip."""
        route = [{"source": "peer-A", "targets": ["peer-B", "peer-C"]}]
        msg = HiveMessage(HiveMessageType.BUS,
                          payload={"type": "test", "data": {}, "context": {}},
                          source_peer="peer-A", target_peers=["peer-B", "peer-C"])
        msg.replace_route(route)
        restored = HiveMessage.deserialize(msg.as_dict)
        self.assertEqual(restored.route, route)

    def test_serialize_deserialize_preserves_source_peer(self):
        """source_peer must survive roundtrip."""
        msg = HiveMessage(HiveMessageType.BUS,
                          payload={"type": "test", "data": {}, "context": {}},
                          source_peer="peer-X")
        restored = HiveMessage.deserialize(msg.serialize())
        self.assertEqual(restored.source_peer, "peer-X")

    def test_serialize_deserialize_preserves_node(self):
        """node must survive roundtrip."""
        msg = HiveMessage(HiveMessageType.BUS,
                          payload={"type": "test", "data": {}, "context": {}},
                          node="node-42")
        restored = HiveMessage.deserialize(msg.serialize())
        self.assertEqual(restored.node_id, "node-42")

    def test_route_type_is_list_of_dicts(self):
        """Route entries are dicts with 'source' and 'targets' keys, not strings."""
        route = [{"source": "p1", "targets": ["p2"]}, {"source": "p2", "targets": ["p3"]}]
        msg = HiveMessage(HiveMessageType.BUS,
                          payload={"type": "t", "data": {}, "context": {}})
        msg.replace_route(route)
        for hop in msg.route:
            self.assertIsInstance(hop, dict)
            self.assertIn("source", hop)
            self.assertIn("targets", hop)


if __name__ == "__main__":
    unittest.main()
