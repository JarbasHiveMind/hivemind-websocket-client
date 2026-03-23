"""Tests for hivemind_bus_client.serialization — bitstring encode/decode roundtrips."""
import pytest
from ovos_bus_client.message import Message

from hivemind_bus_client.serialization import (
    get_bitstring, decode_bitstring,
    HiveMessageType, HiveMindBinaryPayloadType,
)
from hivemind_bus_client.message import HiveMessage


class TestBitstringRoundtrip:
    @pytest.mark.parametrize("hive_type", [
        HiveMessageType.BUS,
        HiveMessageType.PROPAGATE,
        HiveMessageType.ESCALATE,
        HiveMessageType.THIRDPRTY,
        HiveMessageType.PING,
    ])
    def test_roundtrip_message_types(self, hive_type):
        payload = HiveMessage(hive_type, {"test": "data"})
        bitstr = get_bitstring(hive_type=hive_type, payload=payload, compressed=False)
        decoded = decode_bitstring(bitstr)
        assert decoded.msg_type == hive_type

    def test_bus_message_roundtrip(self):
        msg = Message("speak", {"utterance": "hello"})
        payload = HiveMessage(HiveMessageType.BUS, msg)
        bitstr = get_bitstring(hive_type=HiveMessageType.BUS, payload=payload, compressed=False)
        decoded = decode_bitstring(bitstr)
        assert decoded.msg_type == HiveMessageType.BUS

    @pytest.mark.parametrize("compressed", [True, False])
    def test_compression_flag(self, compressed):
        msg = Message("speak", {"utterance": "hello world " * 50})
        payload = HiveMessage(HiveMessageType.BUS, msg)
        bitstr = get_bitstring(hive_type=HiveMessageType.BUS, payload=payload, compressed=compressed)
        decoded = decode_bitstring(bitstr)
        assert decoded.msg_type == HiveMessageType.BUS

    def test_auto_compression(self):
        """compressed=None should auto-select the smaller representation."""
        msg = Message("speak", {"utterance": "hello world " * 100})
        payload = HiveMessage(HiveMessageType.BUS, msg)
        bitstr = get_bitstring(hive_type=HiveMessageType.BUS, payload=payload, compressed=None)
        decoded = decode_bitstring(bitstr)
        assert decoded.msg_type == HiveMessageType.BUS

    def test_binary_payload(self):
        data = b"\x00\x01\x02\x03" * 10
        bitstr = get_bitstring(hive_type=HiveMessageType.BINARY, payload=data,
                               binary_type=HiveMindBinaryPayloadType.TTS_AUDIO)
        decoded = decode_bitstring(bitstr)
        assert decoded.msg_type == HiveMessageType.BINARY
        assert decoded.bin_type == HiveMindBinaryPayloadType.TTS_AUDIO
        assert decoded.payload == data

    def test_versioned_roundtrip(self):
        msg = Message("test", {})
        payload = HiveMessage(HiveMessageType.BUS, msg)
        bitstr = get_bitstring(hive_type=HiveMessageType.BUS, payload=payload,
                               compressed=False, versioned=True)
        decoded = decode_bitstring(bitstr)
        assert decoded.msg_type == HiveMessageType.BUS
