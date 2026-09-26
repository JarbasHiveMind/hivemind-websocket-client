"""A wire payload must be a JSON object, and nothing repairs it.

HIVEMIND-MSG-1 §4: the HANDSHAKE and HELLO payload MUST be a JSON object,
``{}`` the only empty form; a node rejects any other shape and never repairs
it.

Two repairs used to defeat that, and both were in this library:

* ``__init__`` turned ``None`` into ``{}``. On the wire that accepted a
  ``"payload": null`` frame.
* ``as_dict`` ran ``json.loads`` on a string payload. A HELLO whose payload
  was the STRING ``'{"site_id": "injected"}'`` was parsed into an object and
  acted on, and the connection ended up with that site id.

The Python constructor keeps its own default: ``HiveMessage(TYPE)`` with no
payload builds ``{}``. That is an API convenience and not a repair, because
no wire value was read. The wire goes through ``from_wire``.
"""
import json
import subprocess
import sys
import unittest

from hivemind_bus_client.message import (HiveMessage, HiveMessageType,
                                         MalformedWirePayload)

WIRE_TYPES = (HiveMessageType.HELLO, HiveMessageType.HANDSHAKE)

#: every shape §4 refuses, as it appears in a JSON frame
REFUSED = (
    ("null", None),
    ("a list", ["session"]),
    ("a bare string", "session"),
    ("a JSON-encoded object", '{"site_id": "injected"}'),
    ("a number", 7),
    ("a bool", True),
)


class TestFromWireRefusesANonObjectPayload(unittest.TestCase):

    def test_every_refused_shape_raises(self):
        for msg_type in WIRE_TYPES:
            for label, payload in REFUSED:
                with self.subTest(msg_type=msg_type, payload=label):
                    frame = {"msg_type": msg_type.value, "payload": payload}
                    with self.assertRaises(MalformedWirePayload):
                        HiveMessage.from_wire(frame)
                    with self.assertRaises(MalformedWirePayload):
                        HiveMessage.from_wire(json.dumps(frame))

    def test_an_absent_payload_is_refused(self):
        for msg_type in WIRE_TYPES:
            with self.subTest(msg_type=msg_type):
                with self.assertRaises(MalformedWirePayload):
                    HiveMessage.from_wire({"msg_type": msg_type.value})

    def test_a_type_that_carries_no_payload_may_omit_the_key(self):
        """Absence is refused only where §4 requires a payload.

        A PING frame is the whole message and has nothing to put in a
        payload. Refusing it here would reject a legitimate frame, which an
        existing dispatch test caught: the first cut of this parser did
        exactly that.
        """
        msg = HiveMessage.from_wire({"msg_type": HiveMessageType.PING.value})
        self.assertEqual(msg.msg_type, HiveMessageType.PING)
        self.assertEqual(msg.payload, {})

    def test_a_type_that_carries_no_payload_still_refuses_a_bad_one(self):
        # omitting it is allowed; sending the wrong shape is not
        with self.assertRaises(MalformedWirePayload):
            HiveMessage.from_wire(
                {"msg_type": HiveMessageType.PING.value, "payload": "nope"})

    def test_the_empty_object_is_accepted(self):
        """The control. ``{}`` is the one empty form §4 allows."""
        for msg_type in WIRE_TYPES:
            with self.subTest(msg_type=msg_type):
                msg = HiveMessage.from_wire(
                    {"msg_type": msg_type.value, "payload": {}})
                self.assertEqual(msg.payload, {})
                self.assertEqual(msg.msg_type, msg_type)

    def test_a_real_payload_survives_with_its_per_hop_fields(self):
        """`from_wire` keeps what `deserialize` drops.

        A client reads ``source_peer`` to decide whether a PROPAGATE is
        trusted, so a wire parser that dropped it would change that decision
        without saying so.
        """
        frame = {"msg_type": HiveMessageType.HELLO.value,
                 "payload": {"site_id": "kitchen"},
                 "source_peer": "hub:1"}
        msg = HiveMessage.from_wire(frame)
        self.assertEqual(msg.payload, {"site_id": "kitchen"})
        self.assertEqual(msg.source_peer, "hub:1")

    def test_the_json_string_payload_is_never_parsed_back(self):
        """The defect this file exists for, stated as one case.

        Before the fix this frame yielded ``{"site_id": "injected"}`` and a
        node read the site id straight out of it.
        """
        frame = {"msg_type": HiveMessageType.HELLO.value,
                 "payload": '{"site_id": "injected"}'}
        with self.assertRaises(MalformedWirePayload):
            HiveMessage.from_wire(frame)


class TestDeserializeRefusesTheSameShapes(unittest.TestCase):
    """`deserialize` is the other wire door and answers the same way."""

    def test_refused_shapes_do_not_become_messages(self):
        for label, payload in REFUSED:
            with self.subTest(payload=label):
                frame = {"msg_type": HiveMessageType.HELLO.value,
                         "payload": payload}
                with self.assertRaises(ValueError):
                    HiveMessage.deserialize(frame)

    def test_the_empty_object_still_deserializes(self):
        msg = HiveMessage.deserialize(
            {"msg_type": HiveMessageType.HELLO.value, "payload": {}})
        self.assertEqual(msg.payload, {})


class TestTheConstructorKeepsItsApiDefault(unittest.TestCase):

    def test_an_omitted_payload_is_the_empty_object(self):
        # in-process construction, no wire value read, so no repair
        self.assertEqual(HiveMessage(HiveMessageType.HELLO).payload, {})

    def test_as_dict_does_not_parse_a_string_payload(self):
        msg = HiveMessage(HiveMessageType.HELLO)
        msg._payload = '{"site_id": "injected"}'
        with self.assertRaises(MalformedWirePayload):
            msg.as_dict

    def test_the_as_dict_guard_survives_python_dash_o(self):
        """`python -O` compiles an assert out; this guard must remain.

        protocol.py carries the same note about an assert this project
        already lost that way, so the guard is run under -O rather than
        trusted. A source-text check would pass on a comment.
        """
        program = (
            "from hivemind_bus_client.message import ("
            "HiveMessage, HiveMessageType, MalformedWirePayload)\n"
            "msg = HiveMessage(HiveMessageType.HELLO)\n"
            "msg._payload = '{\"site_id\": \"injected\"}'\n"
            "try:\n"
            "    msg.as_dict\n"
            "except MalformedWirePayload:\n"
            "    print('REFUSED')\n"
            "else:\n"
            "    print('EMITTED')\n")
        result = subprocess.run([sys.executable, "-O", "-c", program],
                                capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "REFUSED", result.stderr)

    def test_a_string_payload_is_refused_by_the_constructor(self):
        with self.assertRaises(MalformedWirePayload):
            HiveMessage(HiveMessageType.HELLO, '{"site_id": "injected"}')


class TestAWrappedPayloadGetsTheSameDoor(unittest.TestCase):
    """The repair used to survive one level of wrapping.

    `HiveMessage.payload` builds the inner view with
    `HiveMessage(**self._payload)`, so while the constructor parsed a string
    the exact shape `from_wire` refuses was repaired one level down. A PING
    travels PROPAGATE-wrapped (§4), and `handle_ping` then read `flood_id`
    off the repaired object. §4 also forbids a node to rewrite the inner
    payload of a wrapped routing message.
    """

    WRAPPERS = (HiveMessageType.PROPAGATE, HiveMessageType.BROADCAST,
                HiveMessageType.ESCALATE)

    INNER = (
        (HiveMessageType.PING, '{"flood_id": "forged", "peer": "attacker"}'),
        (HiveMessageType.HELLO, '{"site_id": "attacker"}'),
        (HiveMessageType.INTERCOM, '{"encrypted_key": "x"}'),
    )

    def test_a_wrapped_string_payload_is_refused(self):
        for wrapper in self.WRAPPERS:
            for inner_type, inner_payload in self.INNER:
                with self.subTest(wrapper=wrapper, inner=inner_type):
                    frame = {"msg_type": wrapper.value,
                             "payload": {"msg_type": inner_type.value,
                                         "payload": inner_payload}}
                    outer = HiveMessage.from_wire(frame)
                    with self.assertRaises(MalformedWirePayload):
                        outer.payload

    def test_no_wrapped_shape_reaches_a_handler_as_an_object(self):
        # the control the first cut of this file lacked: the same frames at
        # the top level were already refused, and the wrapped form must not
        # be the way in
        for label, payload in REFUSED:
            if not isinstance(payload, str):
                continue
            with self.subTest(payload=label):
                frame = {"msg_type": HiveMessageType.PROPAGATE.value,
                         "payload": {"msg_type": HiveMessageType.PING.value,
                                     "payload": payload}}
                outer = HiveMessage.from_wire(frame)
                with self.assertRaises(MalformedWirePayload):
                    outer.payload

    def test_a_wrapped_object_payload_still_works(self):
        """Control: the legitimate wrapped PING is untouched."""
        frame = {"msg_type": HiveMessageType.PROPAGATE.value,
                 "payload": {"msg_type": HiveMessageType.PING.value,
                             "payload": {"flood_id": "abc"}}}
        inner = HiveMessage.from_wire(frame).payload
        self.assertEqual(inner.msg_type, HiveMessageType.PING)
        self.assertEqual(inner.payload, {"flood_id": "abc"})

    def test_a_wrapped_bus_message_still_works(self):
        """Control: a PROPAGATE(BUS), the ordinary traffic shape."""
        frame = {"msg_type": HiveMessageType.PROPAGATE.value,
                 "payload": {"msg_type": HiveMessageType.BUS.value,
                             "payload": {"type": "speak",
                                         "data": {"utterance": "hi"}}}}
        inner = HiveMessage.from_wire(frame).payload
        self.assertEqual(inner.msg_type, HiveMessageType.BUS)
        self.assertEqual(inner.payload.msg_type, "speak")


class TestTheBinaryFrameDoorRefusesTheSameShapes(unittest.TestCase):
    """`decode_bitstring` is a wire door too.

    It used to hand the payload to the constructor as JSON TEXT and let the
    constructor parse it, which is the repair this change removes. It now
    parses the text itself and checks the result against §4.
    """

    def _frame(self, payload_text):
        """Assemble the frame directly, bypassing the sender's own guard.

        ``get_bitstring`` used to build these frames, but it now refuses a
        payload §4 does not allow, so it can no longer produce the malformed
        frame this decoder test needs. That refusal is the point of the
        sender guard; the decoder still has to be tested against a frame a
        non-conforming peer can send, so the bits are laid out here instead,
        per HIVEMIND-WIRE-1 §4.1.
        """
        from bitstring import BitArray
        from hivemind_bus_client.serialization import _TYPE2INT
        from hivemind_bus_client.util import cast2bytes

        meta = cast2bytes({}, False)
        s = BitArray()
        s.append('uint:1=1')                                   # start marker
        s.append('uint:1=0')                                   # not versioned
        s.append(f'uint:5={_TYPE2INT[HiveMessageType.PING]}')   # msg type
        s.append('uint:1=0')                                   # not compressed
        s.append(f'uint:8={len(meta)}')                         # metadata len
        s.append(meta)
        s.append(cast2bytes(payload_text, False))               # payload block
        while len(s) % 8 != 0:
            s.insert('uint:1=0', 0)
        return s

    def test_a_binary_frame_whose_payload_is_not_an_object_is_refused(self):
        """The decoder wraps the refusal in its own wire-error type.

        `MalformedBinaryFrame` is what every other bad binary frame raises,
        so the refusal reaches a caller in the shape that caller expects,
        and the §4 reason travels in the text.
        """
        from hivemind_bus_client.exceptions import MalformedBinaryFrame
        from hivemind_bus_client.serialization import decode_bitstring
        for label, payload in REFUSED:
            if payload is None:
                continue  # an absent payload is the frame's own shape
            with self.subTest(payload=label):
                frame = self._frame(json.dumps(payload))
                with self.assertRaises(
                        (MalformedWirePayload, MalformedBinaryFrame)) as caught:
                    decode_bitstring(frame)
                self.assertIn("HIVEMIND-MSG-1", str(caught.exception))

    def test_a_binary_frame_with_an_object_payload_still_decodes(self):
        """Control: the ordinary binary frame is untouched."""
        from hivemind_bus_client.serialization import (decode_bitstring,
                                                       get_bitstring)
        from ovos_bus_client.message import Message
        frame = get_bitstring(hive_type=HiveMessageType.BUS,
                              payload=Message("speak", {"utterance": "hi"}),
                              compressed=False)
        msg = decode_bitstring(frame)
        self.assertEqual(msg.msg_type, HiveMessageType.BUS)
        self.assertEqual(msg.payload.msg_type, "speak")


if __name__ == "__main__":
    unittest.main()
