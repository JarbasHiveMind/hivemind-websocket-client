"""A payload-less frame is refused at the door, not seven frames later.

Settled by architecture under T-4702. HIVEMIND-MSG-1 §4 gives ten of the
thirteen registry types a payload that cannot be absent: a Layer-1 bus message
for ``BUS`` and ``SHARED_BUS``, a nested HiveMessage for ``BROADCAST``,
``PROPAGATE``, ``ESCALATE``, ``QUERY`` and ``CASCADE``, "an opaque byte string"
for ``BINARY``, and the control fields their types require for ``HANDSHAKE``
and ``HELLO``. §2's envelope table marking ``payload`` Required "yes" is right
for all ten.

``_PAYLOAD_REQUIRED`` held only HELLO and HANDSHAKE. Measured on the other
eleven, with a frame of ``{"msg_type": t}`` and no payload key:

* seven were ADMITTED and raised only when something read ``.payload`` --
  ``BUS`` and ``SHARED_BUS`` with ``KeyError``, and the five routing types with
  ``TypeError``. A payload-less ``PROPAGATE`` entered the node and blew up
  frames later in whatever read it.
* ``BINARY`` was refused, but incidentally, by the constructor's bytes check,
  citing no clause.
* ``INTERCOM``, ``PING`` and ``RENDEZVOUS`` read ``{}``.

A refusal that happens by crash cannot be logged as a malformed frame, cannot
name the field, and a caller cannot tell it from a bug. That is what this
closes.

ONE TYPE STAYS OUT. ``PING`` may carry ``{}``, because §4 says its payload
"MAY be empty".

``INTERCOM`` and ``RENDEZVOUS`` were out of this list too, on the premise that
§4 named no form for either. That premise expired. Architecture wrote both
forms into JarbasHiveMind/architecture#32, at 567ddf1: an INTERCOM payload is
"a JSON object carrying a ciphertext encrypted to the target peer's public key
and a signature made by the originator", which "is never absent and never the
empty object"; a RENDEZVOUS payload is "a JSON object naming the outcome of
one mailbox exchange", whose reply carries ``status`` and ``mailbox_node``. An
absent payload carries no ciphertext and no status, so both types join the
list. That is this library enforcing a rule, not inventing one, which is the
bar T-4687 set.

The KEY NAMES inside the INTERCOM object stay with HIVEMIND-CRYPTO-1 and are
NOT checked here: architecture T-4733 is open on them.

The clause is in an OPEN draft. This cites the pull request rather than a
merged ref, and #32 merging is what settles it.
"""
import unittest

from hivemind_bus_client.message import (HiveMessage, HiveMessageType,
                                         MalformedWirePayload,
                                         _PAYLOAD_REQUIRED)

#: §4 gives each of these a payload that cannot be absent
REQUIRED = (HiveMessageType.HANDSHAKE, HiveMessageType.HELLO,
            HiveMessageType.BUS, HiveMessageType.SHARED_BUS,
            HiveMessageType.BROADCAST, HiveMessageType.PROPAGATE,
            HiveMessageType.ESCALATE, HiveMessageType.QUERY,
            HiveMessageType.CASCADE, HiveMessageType.BINARY,
            HiveMessageType.INTERCOM, HiveMessageType.RENDEZVOUS)

#: left out on purpose
PING_MAY_BE_EMPTY = (HiveMessageType.PING,)

#: empty since architecture#32 at 567ddf1 gave INTERCOM and RENDEZVOUS a §4
#: form. Kept, rather than deleted, because the next type that arrives without
#: one belongs here and the reader needs to see the list exists.
UNSPECIFIED_IN_SECTION_4 = ()


class TestAPayloadLessFrameIsRefusedAtTheDoor(unittest.TestCase):

    def test_every_type_section_4_gives_a_payload_is_refused(self):
        for msg_type in REQUIRED:
            with self.subTest(msg_type=msg_type.value):
                with self.assertRaises(MalformedWirePayload):
                    HiveMessage.from_wire({"msg_type": msg_type.value})

    def test_the_refusal_names_the_type_and_the_clause(self):
        """An operator must learn which frame and which rule, not just that
        something failed. The old behaviour named neither: it was a KeyError
        or a TypeError from whatever happened to read the payload."""
        with self.assertRaises(MalformedWirePayload) as caught:
            HiveMessage.from_wire({"msg_type": HiveMessageType.PROPAGATE.value})
        said = str(caught.exception)
        self.assertIn("propagate", said)
        self.assertIn("payload", said)

    def test_the_wire_form_is_matched_and_not_only_the_enum(self):
        """A frame off the wire carries the STRING, so both forms must be in
        the tuple. Listing only the enums would leave every wire frame
        admitted while the unit tests passed on enum input."""
        for msg_type in REQUIRED:
            with self.subTest(msg_type=msg_type.value):
                self.assertIn(msg_type, _PAYLOAD_REQUIRED)
                self.assertIn(msg_type.value, _PAYLOAD_REQUIRED)

    def test_no_required_type_crashes_later_instead(self):
        """The defect was the LATENESS, so assert nothing is admitted.

        A frame that got past the door raised KeyError or TypeError only when
        something read .payload. If a type were dropped from the list, this
        catches it here rather than in a reader.
        """
        for msg_type in REQUIRED:
            with self.subTest(msg_type=msg_type.value):
                try:
                    message = HiveMessage.from_wire({"msg_type": msg_type.value})
                except MalformedWirePayload:
                    continue
                self.fail(f"{msg_type.value} was admitted; reading its payload "
                          f"gives {type(message.payload).__name__}")


class TestTheThreeLeftOut(unittest.TestCase):

    def test_ping_may_carry_an_empty_payload(self):
        """§4: a PING payload "MAY be empty"."""
        message = HiveMessage.from_wire(
            {"msg_type": HiveMessageType.PING.value})
        self.assertEqual(message.payload, {})

    def test_no_registry_type_is_left_without_a_section_4_form(self):
        """The list is empty, and an empty list must be asserted, not looped.

        A loop over ``()`` passes whatever the library does, so the emptiness
        is stated directly. When a type arrives without a §4 form, this is
        the line that has to change.
        """
        self.assertEqual(UNSPECIFIED_IN_SECTION_4, ())

    def test_intercom_and_rendezvous_are_now_required(self):
        """The types the emptied list used to hold, asserted one by one."""
        for msg_type in (HiveMessageType.INTERCOM,
                         HiveMessageType.RENDEZVOUS):
            with self.subTest(msg_type=msg_type.value):
                self.assertIn(msg_type, _PAYLOAD_REQUIRED)
                with self.assertRaises(MalformedWirePayload):
                    HiveMessage.from_wire({"msg_type": msg_type.value})

    def test_ping_alone_is_out_of_the_required_list(self):
        for msg_type in PING_MAY_BE_EMPTY:
            with self.subTest(msg_type=msg_type.value):
                self.assertNotIn(msg_type, _PAYLOAD_REQUIRED)
                self.assertNotIn(msg_type.value, _PAYLOAD_REQUIRED)


#: a payload of the form §4 gives each type, so the control exercises a frame
#: that is actually valid rather than any dict
_VALID_PAYLOAD = {
    HiveMessageType.HANDSHAKE: {"pubkey": "x"},
    HiveMessageType.HELLO: {"pubkey": "x"},
    HiveMessageType.BUS: {"type": "speak", "data": {}},
    HiveMessageType.SHARED_BUS: {"type": "speak", "data": {}},
    HiveMessageType.BROADCAST: {"msg_type": "bus",
                                "payload": {"type": "speak", "data": {}}},
    HiveMessageType.PROPAGATE: {"msg_type": "bus",
                                "payload": {"type": "speak", "data": {}}},
    HiveMessageType.ESCALATE: {"msg_type": "bus",
                               "payload": {"type": "speak", "data": {}}},
    HiveMessageType.QUERY: {"msg_type": "bus",
                            "payload": {"type": "speak", "data": {}}},
    HiveMessageType.CASCADE: {"msg_type": "bus",
                              "payload": {"type": "speak", "data": {}}},
    # §4 fixes the INTERCOM payload as an object and leaves the key NAMES to
    # HIVEMIND-CRYPTO-1, so this stands in for a signed ciphertext without
    # asserting what it is called.
    HiveMessageType.INTERCOM: {"ciphertext": "x", "signature": "y"},
    HiveMessageType.RENDEZVOUS: {"status": "ok", "mailbox_node": None},
}


class TestAFrameWithAPayloadIsUnaffected(unittest.TestCase):
    """The control. A presence check must refuse absence and nothing else."""

    def test_every_required_type_accepts_its_own_valid_payload(self):
        """Each type gets the form §4 gives it, not any dict.

        A first version of this control passed ``{"a": 1}`` to every type and
        failed on seven of them, which is the control being wrong rather than
        the change: §4 gives BUS a Layer-1 bus message and the routing types a
        nested HiveMessage, so an arbitrary dict was never a valid frame for
        them.
        """
        for msg_type, payload in _VALID_PAYLOAD.items():
            with self.subTest(msg_type=msg_type.value):
                message = HiveMessage.from_wire(
                    {"msg_type": msg_type.value, "payload": payload})
                self.assertEqual(message.msg_type, msg_type.value)
                self.assertIsNotNone(message.payload)


#: §4 gives each of these an ENVELOPE, so an empty object is malformed
ENVELOPE_CARRYING = (HiveMessageType.BUS, HiveMessageType.SHARED_BUS,
                     HiveMessageType.BROADCAST, HiveMessageType.PROPAGATE,
                     HiveMessageType.ESCALATE, HiveMessageType.QUERY,
                     HiveMessageType.CASCADE)


class TestAnEmptyEnvelopePayloadIsRefused(unittest.TestCase):
    """Architecture ruled this under T-4728, recorded in architecture#32.

    A present-but-empty payload is MALFORMED for the seven types §4 gives an
    envelope, not a legal degenerate they tolerate. §4 says a BUS or
    SHARED_BUS payload "is a single Layer-1 bus message" and a routing type's
    "is itself a HiveMessage"; each carries a required type field and ``{}``
    carries none. The tolerate-it reading fails on §2's own rule that a
    receiver MUST treat a message whose ``msg_type`` is not in the registry as
    unroutable and MUST NOT interpret its payload: there is nothing to
    tolerate an empty inner envelope into.

    This class asserted the OPPOSITE until the ruling: that ``{}`` was
    admitted and raised only when something read ``.payload``, KeyError for
    the bus types and TypeError for the routing types. That was recorded as a
    gap to be settled, and this is the settlement.
    """

    def test_an_empty_payload_is_refused_at_the_door(self):
        for msg_type in ENVELOPE_CARRYING:
            with self.subTest(msg_type=msg_type.value):
                with self.assertRaises(MalformedWirePayload):
                    HiveMessage.from_wire(
                        {"msg_type": msg_type.value, "payload": {}})

    def test_the_refusal_names_the_clause_and_the_reason(self):
        """Not just that it failed: which rule, and why {} cannot satisfy it.

        The old behaviour named neither, because it was a KeyError or a
        TypeError from whatever happened to read the payload.
        """
        with self.assertRaises(MalformedWirePayload) as caught:
            HiveMessage.from_wire(
                {"msg_type": HiveMessageType.PROPAGATE.value, "payload": {}})
        said = str(caught.exception)
        self.assertIn("empty", said)
        self.assertIn("HIVEMIND-MSG-1 §4", said)
        self.assertIn("envelope", said)

    def test_nothing_is_admitted_to_crash_later(self):
        """The defect was the lateness, so assert nothing gets past the door."""
        for msg_type in ENVELOPE_CARRYING:
            with self.subTest(msg_type=msg_type.value):
                try:
                    message = HiveMessage.from_wire(
                        {"msg_type": msg_type.value, "payload": {}})
                except MalformedWirePayload:
                    continue
                self.fail(f"{msg_type.value} admitted an empty payload; "
                          f"reading it gives "
                          f"{type(message.payload).__name__}")

    def test_a_populated_envelope_is_still_accepted(self):
        """The control. Refusing emptiness must refuse nothing else."""
        for msg_type in ENVELOPE_CARRYING:
            with self.subTest(msg_type=msg_type.value):
                message = HiveMessage.from_wire(
                    {"msg_type": msg_type.value,
                     "payload": _VALID_PAYLOAD[msg_type]})
                self.assertIsNotNone(message.payload)


class TestEmptinessStaysLegalWhereSection4GrantsIt(unittest.TestCase):
    """§4 lets HANDSHAKE, HELLO and PING carry an empty payload.

    These are the control for the class above: a change that refused emptiness
    everywhere would pass every test there and fail every one here.
    """

    def test_handshake_hello_and_ping_accept_an_empty_payload(self):
        for msg_type in (HiveMessageType.HANDSHAKE, HiveMessageType.HELLO,
                         HiveMessageType.PING):
            with self.subTest(msg_type=msg_type.value):
                message = HiveMessage.from_wire(
                    {"msg_type": msg_type.value, "payload": {}})
                self.assertEqual(message.payload, {})

    def test_an_empty_rendezvous_payload_is_still_admitted(self):
        """§4 names no empty form for RENDEZVOUS and says nothing against one.

        So absence is refused and emptiness is not. The library does not
        extend a rule the specification did not write, and this line is the
        boundary: it fails the day a change refuses emptiness everywhere.
        """
        message = HiveMessage.from_wire(
            {"msg_type": HiveMessageType.RENDEZVOUS.value, "payload": {}})
        self.assertEqual(message.payload, {})


class TestAnEmptyIntercomPayloadIsRefused(unittest.TestCase):
    """§4 at architecture#32 567ddf1: the INTERCOM payload "is never absent
    and never the empty object, because neither carries a ciphertext or a
    signature".

    A separate rule from the envelope one, so it carries its own reason: an
    INTERCOM payload is not an envelope, and a refusal that told the sender
    its envelope was empty would name the wrong clause.
    """

    def test_an_empty_intercom_payload_is_refused_at_the_door(self):
        with self.assertRaises(MalformedWirePayload):
            HiveMessage.from_wire(
                {"msg_type": HiveMessageType.INTERCOM.value, "payload": {}})

    def test_the_refusal_names_the_clause_and_the_reason(self):
        with self.assertRaises(MalformedWirePayload) as caught:
            HiveMessage.from_wire(
                {"msg_type": HiveMessageType.INTERCOM.value, "payload": {}})
        said = str(caught.exception)
        self.assertIn("HIVEMIND-MSG-1 §4", said)
        self.assertIn("ciphertext", said)
        self.assertNotIn("envelope", said)

    def test_a_populated_intercom_payload_is_accepted(self):
        """The control, and it also proves no key name is enforced here:
        HIVEMIND-CRYPTO-1 owns those, and architecture T-4733 is open."""
        for payload in ({"ciphertext": "x", "signature": "y"},
                        {"whatever_crypto_1_ends_up_calling_it": "x"}):
            with self.subTest(payload=sorted(payload)):
                message = HiveMessage.from_wire(
                    {"msg_type": HiveMessageType.INTERCOM.value,
                     "payload": payload})
                self.assertEqual(message.payload, payload)
