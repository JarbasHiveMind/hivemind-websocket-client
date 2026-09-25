"""The binary send path refuses a payload shape §4 does not allow.

HIVEMIND-MSG-1 §4 gives the payload a form per ``msg_type``:

* For ``BINARY``, "the payload is an opaque byte string with an associated
  handling instruction".
* For ``BUS`` and ``SHARED_BUS`` it is a Layer-1 bus message, and for the
  routing types it is a nested HiveMessage. Both are objects.

The text path got its single validated door in #290, ``from_wire``. The
binary path had none, and ``BitArray.append`` does not supply one, so four
shapes reached the wire or raised from inside bitstring:

* ``BUS`` with a ``str`` was written to the frame as raw bytes. No peer can
  parse it, so the far end dropped the message and the sender never learned
  of it.
* ``BUS`` with a ``list`` or an ``int`` raised a bare ``AssertionError``
  that named neither the payload nor the rule.
* ``BINARY`` with a ``dict`` became a SINGLE BIT on the wire.
  ``BitArray().append({"a": 1})`` reads the mapping as a one-bit token, so
  the whole payload was lost and the frame still went out.
* ``BINARY`` with a ``str`` raised ``ValueError: Can't parse token`` from
  bitstring, which reads a string as a format specification.

Each is now refused at the sender with ``MalformedWirePayload``.

A valid payload must still encode byte for byte as before. That is the point
of ``test_a_valid_payload_encodes_byte_identically``: this change adds a
refusal and must change no frame that was already correct.
"""
import unittest

from bitstring import BitArray, BitStream
from ovos_bus_client.message import Message

from hivemind_bus_client.message import (HiveMessageType,
                                         HiveMindBinaryPayloadType,
                                         MalformedWirePayload)
from hivemind_bus_client.serialization import get_bitstring

#: the object-payload types that WIRE-1 §4.2 assigns a code and that §4
#: requires to carry an object
OBJECT_TYPES = (HiveMessageType.BUS, HiveMessageType.SHARED_BUS,
                HiveMessageType.BROADCAST, HiveMessageType.PROPAGATE,
                HiveMessageType.ESCALATE)

#: every shape §4 refuses for an object payload. A str is included twice
#: over: text that is not JSON at all, and JSON text that decodes to
#: something other than an object.
REFUSED_OBJECT = ("a string", "not json {", '"a json string"', "[1, 2]",
                  "7", "null", ["a", "list"], 7, 1.5, True)

#: every shape §4 refuses for an opaque byte string
REFUSED_BINARY = ({"a": 1}, "a string", ["a", "list"], 7)


class TestTheBinarySendPathRefusesABadShape(unittest.TestCase):

    def test_an_object_type_refuses_a_non_object_payload(self):
        """A str used to reach the wire as raw bytes the peer cannot parse."""
        for hive_type in OBJECT_TYPES:
            for payload in REFUSED_OBJECT:
                with self.subTest(hive_type=hive_type, payload=payload):
                    with self.assertRaises(MalformedWirePayload):
                        get_bitstring(hive_type=hive_type, payload=payload,
                                      compressed=False)

    def test_binary_refuses_anything_but_bytes(self):
        """A dict used to become one bit, and a str raised from bitstring."""
        for payload in REFUSED_BINARY:
            with self.subTest(payload=payload):
                with self.assertRaises(MalformedWirePayload):
                    get_bitstring(hive_type=HiveMessageType.BINARY,
                                  payload=payload, compressed=False,
                                  binary_type=HiveMindBinaryPayloadType.RAW_AUDIO)

    def test_the_refusal_names_the_type_and_the_clause(self):
        """An operator reading the log must learn what was wrong and why.

        The old failures named nothing: a bare AssertionError, or a bitstring
        token error about a 'Dtype name'.
        """
        with self.assertRaises(MalformedWirePayload) as caught:
            get_bitstring(hive_type=HiveMessageType.BUS, payload="a string",
                          compressed=False)
        said = str(caught.exception)
        self.assertIn("not JSON", said)
        self.assertIn("HIVEMIND-MSG-1 §4", said)

        with self.assertRaises(MalformedWirePayload) as caught:
            get_bitstring(hive_type=HiveMessageType.BUS, payload="[1, 2]",
                          compressed=False)
        said = str(caught.exception)
        self.assertIn("JSON object", said)
        self.assertIn("list", said)
        self.assertIn("HIVEMIND-MSG-1 §4", said)

        with self.assertRaises(MalformedWirePayload) as caught:
            get_bitstring(hive_type=HiveMessageType.BUS, payload=7,
                          compressed=False)
        said = str(caught.exception)
        self.assertIn("int", said)
        self.assertIn("JSON object", said)
        self.assertIn("HIVEMIND-MSG-1 §4", said)

        with self.assertRaises(MalformedWirePayload) as caught:
            get_bitstring(hive_type=HiveMessageType.BINARY, payload={"a": 1},
                          compressed=False)
        said = str(caught.exception)
        self.assertIn("dict", said)
        self.assertIn("opaque byte string", said)
        self.assertIn("HIVEMIND-MSG-1 §4", said)

    def test_a_dict_payload_that_lost_itself_is_not_encoded(self):
        """The one-bit frame is the defect this guards, so measure it.

        A guard that only checked for a raised error would still pass if the
        refusal moved somewhere that let a truncated frame out first.
        """
        probe = BitArray()
        probe.append({"a": 1})
        self.assertEqual(len(probe), 1,
                         "bitstring still reads a mapping as one bit, which is "
                         "why the payload has to be refused before append()")


class TestAValidPayloadIsUnchanged(unittest.TestCase):

    def test_a_valid_payload_encodes_byte_identically(self):
        """This change adds a refusal and must move no correct frame.

        The lengths below were confirmed equal on the unpatched function and
        this one, so a change in the encoder trips this rather than passing
        quietly.
        """
        cases = (
            (dict(hive_type=HiveMessageType.BUS,
                  payload={"type": "speak", "data": {"utterance": "ola"}},
                  compressed=False), 51),
            (dict(hive_type=HiveMessageType.BROADCAST,
                  payload={"msg_type": "bus", "payload": {}},
                  compressed=False), 38),
            (dict(hive_type=HiveMessageType.BINARY, payload=b"\x00\xff\x10ab",
                  compressed=False,
                  binary_type=HiveMindBinaryPayloadType.RAW_AUDIO), 10),
        )
        for kwargs, expected_len in cases:
            with self.subTest(hive_type=kwargs["hive_type"]):
                frame = get_bitstring(**kwargs).tobytes()
                self.assertEqual(len(frame), expected_len)

    def test_json_object_text_is_accepted(self):
        """A Message reaches the encoder as its own JSON text.

        So text is a legitimate payload form: the same object, already
        encoded. A check that refused every str would refuse the pre-
        serialized form the library itself produces, and it did: it broke 18
        existing cases before this case was added.
        """
        frame = get_bitstring(hive_type=HiveMessageType.BUS,
                              payload='{"type": "speak", "data": {}}',
                              compressed=False)
        self.assertGreater(len(frame.tobytes()), 0)

    def test_object_text_and_the_dict_encode_the_same_frame(self):
        """The two accepted forms are the same bytes, which is why both pass."""
        as_dict = get_bitstring(hive_type=HiveMessageType.BUS,
                                payload={"type": "speak"},
                                compressed=False).tobytes()
        as_text = get_bitstring(hive_type=HiveMessageType.BUS,
                                payload='{"type": "speak"}',
                                compressed=False).tobytes()
        self.assertEqual(as_dict, as_text)

    def test_a_bus_message_object_still_serializes(self):
        """The production BUS path passes a Message, not a dict.

        It has ``.serialize()``, so the object check must accept it. A check
        that demanded a dict would refuse every real BUS send.
        """
        frame = get_bitstring(hive_type=HiveMessageType.BUS,
                              payload=Message("speak", {"utterance": "ola"}),
                              compressed=False)
        self.assertGreater(len(frame.tobytes()), 0)

    def test_a_bitarray_binary_payload_is_accepted(self):
        """BINARY accepts the bit types the encoder itself produces."""
        for payload in (b"ab", bytearray(b"ab"), memoryview(b"ab"),
                        BitArray(bytes=b"ab"), BitStream(bytes=b"ab")):
            with self.subTest(payload=type(payload).__name__):
                frame = get_bitstring(
                    hive_type=HiveMessageType.BINARY, payload=payload,
                    compressed=False,
                    binary_type=HiveMindBinaryPayloadType.RAW_AUDIO)
                self.assertGreater(len(frame.tobytes()), 0)
