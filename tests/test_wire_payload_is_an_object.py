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
        with self.assertRaises(AssertionError):
            msg.as_dict


if __name__ == "__main__":
    unittest.main()
