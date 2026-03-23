import unittest

from ovos_bus_client import Message

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.util import (
    compress_payload, decompress_payload,
    cast2bytes, bytes2str,
    serialize_message, get_payload, get_hivemsg, get_mycroft_msg,
)


class TestCompressDecompress(unittest.TestCase):
    def test_compress_string(self):
        result = compress_payload("hello world")
        self.assertIsInstance(result, bytes)

    def test_compress_bytes(self):
        result = compress_payload(b"hello world")
        self.assertIsInstance(result, bytes)

    def test_roundtrip(self):
        text = "The quick brown fox jumps over the lazy dog."
        compressed = compress_payload(text)
        decompressed = decompress_payload(compressed)
        self.assertEqual(decompressed, text.encode("utf-8"))

    def test_roundtrip_bytes(self):
        data = b"\x00\x01\x02\xff"
        compressed = compress_payload(data)
        decompressed = decompress_payload(compressed)
        self.assertEqual(decompressed, data)

    def test_compressed_smaller_for_large_text(self):
        text = "a" * 10000
        compressed = compress_payload(text)
        self.assertLess(len(compressed), len(text.encode("utf-8")))


class TestCast2Bytes(unittest.TestCase):
    def test_dict_to_bytes(self):
        result = cast2bytes({"key": "val"})
        self.assertIsInstance(result, bytes)

    def test_string_to_bytes(self):
        result = cast2bytes("hello")
        self.assertIsInstance(result, bytes)

    def test_bytes_passthrough(self):
        result = cast2bytes("hello".encode())
        self.assertIsInstance(result, bytes)

    def test_compressed_dict(self):
        result = cast2bytes({"key": "val"}, compressed=True)
        self.assertIsInstance(result, bytes)


class TestBytes2Str(unittest.TestCase):
    def test_plain_bytes(self):
        result = bytes2str(b"hello")
        self.assertEqual(result, "hello")

    def test_compressed_bytes(self):
        text = "hello world"
        compressed = compress_payload(text)
        result = bytes2str(compressed, compressed=True)
        self.assertEqual(result, text)


class TestSerializeMessage(unittest.TestCase):
    def test_hivemessage(self):
        msg = HiveMessage(HiveMessageType.BUS, payload={"type": "test", "data": {}, "context": {}})
        s = serialize_message(msg)
        self.assertIsInstance(s, str)

    def test_ovos_message(self):
        msg = Message("speak", {"utterance": "hello"})
        s = serialize_message(msg)
        self.assertIsInstance(s, str)

    def test_dict(self):
        d = {"key": "value"}
        s = serialize_message(d)
        self.assertIsInstance(s, str)


class TestGetPayload(unittest.TestCase):
    def test_from_hivemessage_bus(self):
        m = Message("speak", {"utterance": "hello"})
        hm = HiveMessage(HiveMessageType.BUS, payload=m)
        payload = get_payload(hm)
        # payload of BUS type is a Message, get_payload then serializes it
        self.assertIsNotNone(payload)

    def test_from_string(self):
        d = {"type": "test", "data": {}, "context": {}}
        import json
        result = get_payload(json.dumps(d))
        self.assertEqual(result, d)

    def test_from_dict(self):
        d = {"type": "test", "data": {}, "context": {}}
        result = get_payload(d)
        self.assertEqual(result, d)


class TestGetHiveMsg(unittest.TestCase):
    def test_from_ovos_message(self):
        m = Message("speak", {"utterance": "hello"})
        hm = get_hivemsg(m)
        self.assertIsInstance(hm, HiveMessage)
        self.assertEqual(hm.msg_type, HiveMessageType.BUS)

    def test_from_dict(self):
        d = {"msg_type": "bus", "payload": {"type": "t", "data": {}, "context": {}},
             "metadata": {}, "route": [], "node": None, "target_site_id": None,
             "target_pubkey": None, "source_peer": None}
        hm = get_hivemsg(d)
        self.assertIsInstance(hm, HiveMessage)

    def test_from_json_string(self):
        import json
        d = {"msg_type": "bus", "payload": {"type": "t", "data": {}, "context": {}},
             "metadata": {}, "route": [], "node": None, "target_site_id": None,
             "target_pubkey": None, "source_peer": None}
        hm = get_hivemsg(json.dumps(d))
        self.assertIsInstance(hm, HiveMessage)


class TestGetMycroftMsg(unittest.TestCase):
    def test_from_hivemessage(self):
        m = Message("speak", {"utterance": "hello"})
        hm = HiveMessage(HiveMessageType.BUS, payload=m)
        result = get_mycroft_msg(hm)
        self.assertIsInstance(result, Message)
        self.assertEqual(result.msg_type, "speak")

    def test_from_dict(self):
        d = {"type": "speak", "data": {"utterance": "hello"}, "context": {}}
        result = get_mycroft_msg(d)
        self.assertIsInstance(result, Message)
        self.assertEqual(result.msg_type, "speak")

    def test_from_string(self):
        import json
        d = {"type": "speak", "data": {"utterance": "hello"}, "context": {}}
        result = get_mycroft_msg(json.dumps(d))
        self.assertIsInstance(result, Message)


if __name__ == "__main__":
    unittest.main()
