"""The binary codec works on bitstring 4.x and 5.x alike.

The package declares ``bitstring>=4.1.1``, so a fresh install takes whichever
major version is newest for the interpreter: 4.x on Python 3.10, 5.x from
3.11. bitstring 5 removed ``BitStream`` and ``ConstBitStream`` and reversed
the argument order of ``BitArray.insert()``. The codec imported ``BitStream``
at module load, so on bitstring 5 nothing that imports
``hivemind_bus_client.client`` could start.

``TestOnlySharedApi`` runs the codec in a child interpreter against the
installed bitstring with both removals applied by hand. That way the suite
proves the codec does not lean on either one, whichever major version CI
installed.
"""
import subprocess
import sys
import textwrap
import unittest

from bitstring import BitArray, Bits, ReadError

from hivemind_bus_client.exceptions import MalformedBinaryFrame
from hivemind_bus_client.message import HiveMessageType, HiveMindBinaryPayloadType
from hivemind_bus_client.serialization import decode_bitstring, get_bitstring


class TestOnlySharedApi(unittest.TestCase):

    def test_the_codec_needs_neither_bitstream_nor_the_old_insert(self):
        script = textwrap.dedent("""
            import bitstring

            # What bitstring 5 took away, taken away here as well, so that
            # bitstring 4 cannot hide a dependence on it.
            for name in ("BitStream", "ConstBitStream"):
                if hasattr(bitstring, name):
                    delattr(bitstring, name)
            _insert = bitstring.BitArray.insert

            def insert(self, *args, **kwargs):
                if args and not isinstance(args[0], int):
                    raise TypeError("insert() takes the bit position first")
                return _insert(self, *args, **kwargs)

            bitstring.BitArray.insert = insert

            from hivemind_bus_client.exceptions import MalformedBinaryFrame
            from hivemind_bus_client.message import (
                HiveMessageType, HiveMindBinaryPayloadType)
            from hivemind_bus_client.serialization import (
                decode_bitstring, get_bitstring)

            bus = {"type": "speak", "data": {"utterance": "ola"}, "context": {}}
            for compressed in (False, True):
                for versioned in (False, True):
                    frame = get_bitstring(HiveMessageType.BUS, payload=bus,
                                          compressed=compressed,
                                          versioned=versioned)
                    decoded = decode_bitstring(frame.tobytes())
                    assert decoded.msg_type == HiveMessageType.BUS, decoded
                    assert decoded.payload.msg_type == "speak", decoded

            frame = get_bitstring(
                HiveMessageType.BINARY, payload=b"\\x00\\x01\\xfe\\xff",
                compressed=False,
                binary_type=HiveMindBinaryPayloadType.RAW_AUDIO)
            decoded = decode_bitstring(frame.tobytes())
            assert decoded.payload == b"\\x00\\x01\\xfe\\xff", decoded.payload
            assert decoded.bin_type == HiveMindBinaryPayloadType.RAW_AUDIO

            try:
                decode_bitstring(frame.tobytes()[:1])
            except MalformedBinaryFrame:
                pass
            else:
                raise AssertionError("a truncated frame decoded")
            print("ok")
        """)
        result = subprocess.run([sys.executable, "-c", script],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")


def _FrameReader(frame):
    # Imported per call so that the rest of this module still collects
    # against a codec that has no reader of its own.
    from hivemind_bus_client.serialization import _FrameReader as reader
    return reader(frame)


class TestFrameReader(unittest.TestCase):

    def test_reads_fields_in_order(self):
        reader = _FrameReader(b"\xa5\x0f")
        self.assertEqual(len(reader), 16)
        self.assertTrue(reader.read(1).bool)
        self.assertFalse(reader.read(1).bool)
        self.assertEqual(reader.read(6).uint, 0b100101)
        self.assertEqual(reader.pos, 8)
        self.assertEqual(reader.read(8).bytes, b"\x0f")
        self.assertEqual(reader.pos, 16)

    def test_a_read_past_the_end_raises_read_error_and_does_not_move(self):
        reader = _FrameReader(b"\xff")
        reader.read(5)
        with self.assertRaises(ReadError):
            reader.read(4)
        self.assertEqual(reader.pos, 5)
        self.assertEqual(reader.read(3).uint, 0b111)

    def test_a_zero_length_read_at_the_end_is_empty(self):
        reader = _FrameReader(b"\x01")
        reader.read(8)
        self.assertEqual(len(reader.read(0)), 0)

    def test_a_negative_read_is_refused(self):
        with self.assertRaises(ReadError):
            _FrameReader(b"\x01").read(-1)

    def test_accepts_every_frame_type_the_callers_pass(self):
        for frame in (b"\x81", bytearray(b"\x81"), memoryview(b"\x81"),
                      BitArray(b"\x81"), Bits(b"\x81")):
            with self.subTest(frame=type(frame).__name__):
                reader = _FrameReader(frame)
                self.assertEqual(len(reader), 8)
                self.assertEqual(reader.read(8).uint, 0x81)


class TestEncoderPadding(unittest.TestCase):

    def test_frames_are_left_padded_to_a_byte_boundary(self):
        """The padding is 0 bits ahead of the 1-bit start marker."""
        for payload in (b"", b"\x01", b"\x01\x02\x03"):
            with self.subTest(payload=payload):
                frame = get_bitstring(
                    HiveMessageType.BINARY, payload=payload, compressed=False,
                    binary_type=HiveMindBinaryPayloadType.UNDEFINED)
                self.assertEqual(len(frame) % 8, 0)
                wire = frame.bin
                # marker(1) versioned(1) type(5) compressed(1) metalen(8)
                # metadata(16 for "{}") bin_type(4) payload
                unpadded = 1 + 1 + 5 + 1 + 8 + 16 + 4 + 8 * len(payload)
                pad = len(wire) - unpadded
                self.assertEqual(pad, -unpadded % 8)
                self.assertEqual(wire[:pad], "0" * pad)
                self.assertEqual(wire[pad], "1")

    def test_a_bitarray_and_its_bytes_decode_the_same(self):
        frame = get_bitstring(HiveMessageType.BUS,
                              payload={"type": "t", "data": {}, "context": {}},
                              compressed=False)
        from_bits = decode_bitstring(frame)
        from_bytes = decode_bitstring(frame.tobytes())
        self.assertEqual(from_bits.serialize(), from_bytes.serialize())

    def test_a_truncated_frame_is_malformed(self):
        frame = get_bitstring(HiveMessageType.BUS,
                              payload={"type": "t", "data": {}, "context": {}},
                              compressed=False).tobytes()
        with self.assertRaises(MalformedBinaryFrame):
            decode_bitstring(frame[:2])


if __name__ == "__main__":
    unittest.main()
