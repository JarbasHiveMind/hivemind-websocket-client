"""A malformed frame is dropped, and the connection stays up.

HIVEMIND-MSG-1 §3: "A node MUST forward or ignore a payload it does not
understand. It MUST NOT reject the connection over it, and it MUST NOT stop
its own handler over it." §6 repeats it in the MUST NOT list: "reject a
connection over a payload it does not understand (§3)".

The refusal added by this branch raised out of ``on_message``. The transport
catches whatever the callback raises and calls ``on_error``, and the client's
error path clears its state and closes. So one ``{}`` PROPAGATE from the peer
ended the session: exactly the rejection §3 forbids, reached by a frame rather
than by a close.

These tests drive the REAL ``WebSocketApp._callback``, the same path the
transport uses, rather than calling ``on_message`` directly. Calling the
callback directly would never exercise the transport's own try/except, which
is the half that turns a raised refusal into a closed connection, and the test
would pass with the defect present.
"""
import json
import unittest
from unittest.mock import MagicMock, patch

from websocket import WebSocketApp

from hivemind_bus_client.message import HiveMessageType

from test_client import _make_client


class TestAMalformedFrameDoesNotCloseTheConnection(unittest.TestCase):

    def setUp(self):
        self.client = _make_client()
        self.client.crypto_key = None
        self.client.handshake_event.set()
        self.client._handle_hive_protocol = MagicMock()

    def _on_message(self, frame):
        """Run the real receive callback under the transport's dispatcher."""
        app = WebSocketApp.__new__(WebSocketApp)
        app.sock = MagicMock()
        errors = []
        app.on_error = lambda _a, e: errors.append(e)
        app._callback(lambda _a, m: self.client.on_message(m), frame)
        return errors

    def test_an_empty_propagate_payload_is_dropped_and_the_socket_stays_up(self):
        with patch.object(self.client, "close") as close:
            errors = self._on_message(
                json.dumps({"msg_type": "propagate", "payload": {}}))

        self.assertEqual(errors, [], "the refusal reached the error path")
        close.assert_not_called()
        self.client._handle_hive_protocol.assert_not_called()

    def test_a_payload_less_frame_is_dropped_and_the_socket_stays_up(self):
        with patch.object(self.client, "close") as close:
            errors = self._on_message(json.dumps({"msg_type": "bus"}))

        self.assertEqual(errors, [])
        close.assert_not_called()
        self.client._handle_hive_protocol.assert_not_called()

    def test_a_non_json_frame_is_dropped_and_the_socket_stays_up(self):
        """The broadest malformed frame of all, and the one that still closed.

        ``from_wire`` calls ``json.loads`` first, and ``JSONDecodeError`` is
        NOT a subclass of ``MalformedWirePayload``, so a truncated or non-JSON
        text frame raised straight out of the callback and the error path
        closed the session. The guard catches both now. The subject of this
        change claims the whole class §3 names, and this frame is the reason
        the claim was not yet true.
        """
        with patch.object(self.client, "close") as close:
            errors = self._on_message("not json at all")

        self.assertEqual(errors, [], "the refusal reached the error path")
        close.assert_not_called()
        self.client._handle_hive_protocol.assert_not_called()

    def test_a_truncated_json_frame_is_dropped_and_the_socket_stays_up(self):
        """The same class, arriving the way it actually arrives on a wire."""
        with patch.object(self.client, "close") as close:
            errors = self._on_message('{"msg_type":"bus","payload":{"type":')

        self.assertEqual(errors, [])
        close.assert_not_called()
        self.client._handle_hive_protocol.assert_not_called()

    def test_a_binary_frame_with_an_object_payload_keeps_the_session(self):
        """The one refusal that escaped the guard, and it cleared the state.

        A BINARY frame whose payload is an object never reached
        ``_wire_payload``: the constructor's own bytes check refused it first,
        and it raised a BARE ``ValueError``, which is neither
        ``MalformedWirePayload`` nor ``json.JSONDecodeError``. So this one
        frame of the class raised out of the callback, reached ``on_error``,
        and ``on_error`` calls ``_clear_connection_state`` and emits an
        ``"error"`` event to application listeners: §3's second half, "it MUST
        NOT stop its own handler over it". The check now raises
        ``MalformedWirePayload`` and cites §4's "opaque byte string".
        """
        with patch.object(self.client, "close") as close, \
                patch.object(self.client, "_clear_connection_state") as cleared:
            errors = self._on_message(
                json.dumps({"msg_type": "bin", "payload": {}}))

        self.assertEqual(errors, [], "the refusal reached the error path")
        cleared.assert_not_called()
        close.assert_not_called()
        self.client._handle_hive_protocol.assert_not_called()

    def test_a_well_formed_frame_is_still_handled(self):
        """The control. Dropping the malformed frame must drop nothing else."""
        frame = json.dumps({"msg_type": "propagate",
                            "payload": {"msg_type": "bus",
                                        "payload": {"type": "speak",
                                                    "data": {}}}})
        with patch.object(self.client, "close") as close:
            errors = self._on_message(frame)

        self.assertEqual(errors, [])
        close.assert_not_called()
        self.client._handle_hive_protocol.assert_called_once()
        handled = self.client._handle_hive_protocol.call_args[0][0]
        self.assertEqual(handled.msg_type, HiveMessageType.PROPAGATE)

    def test_an_unknown_msg_type_is_dropped_and_a_later_message_still_arrives(self):
        """``_parse_or_drop``'s own except tuple did not catch this one.

        ``from_wire`` calls ``HiveMessage(msg_type, **kwargs)``, and the
        constructor raises a bare ``ValueError`` for a ``msg_type`` it does
        not recognize -- not ``MalformedWirePayload``, not
        ``json.JSONDecodeError``. An unknown ``msg_type`` is exactly "a
        payload it does not understand" under HIVEMIND-MSG-1 §3, and the
        clause does not carve out an exception for it. Asserting no
        exception is not enough here: the socket stayed open for this frame
        even before this fix, and what broke was the delivery of the next
        message, so that delivery is what this test asserts.
        """
        good_frame = json.dumps({"msg_type": "propagate",
                                 "payload": {"msg_type": "bus",
                                             "payload": {"type": "speak",
                                                         "data": {}}}})
        with patch.object(self.client, "close") as close:
            errors = self._on_message(
                json.dumps({"msg_type": "nonsense", "payload": {}}))
            self.assertEqual(errors, [], "the refusal reached the error path")
            close.assert_not_called()
            self.client._handle_hive_protocol.assert_not_called()

            errors = self._on_message(good_frame)

        self.assertEqual(errors, [])
        self.client._handle_hive_protocol.assert_called_once()
        handled = self.client._handle_hive_protocol.call_args[0][0]
        self.assertEqual(handled.msg_type, HiveMessageType.PROPAGATE)


class TestTheOtherTwoDoorsDropTheSameFrames(unittest.TestCase):
    """``_parse_or_drop`` is copied into three clients, and only one was driven.

    `client.py`, `async_client.py` and `http_client.py` each carry a copy. The
    tests above prove the sync one. Three copies of one function with one under
    test is the shape that lets a later edit silently unguard two doors, and one
    of them is the door a satellite on the HTTP transport depends on.

    Two kinds of row run here. The ``_parse_or_drop`` rows call the door one
    layer below ``on_message`` and prove that it RETURNS rather than raises.
    The ``on_message`` rows drive each client's real receive callback, which is
    the caller whose ``try``/``except`` the guard lives in: without them the
    ``except`` clause in the async and the HTTP copy can be deleted and the
    suite stays green, measured. The transport half beyond the callback is
    proven once, above, on the sync door where the close path lives.
    """

    MALFORMED = ('not json at all',
                 '{"msg_type":"bus","payload":{"type":',
                 json.dumps({"msg_type": "propagate", "payload": {}}),
                 json.dumps({"msg_type": "bus"}),
                 json.dumps({"msg_type": "nonsense", "payload": {}}))

    def _async_client(self):
        from test_async_client import _bare_client
        bus = _bare_client()
        bus.crypto_key = None
        bus.handshake_event = MagicMock()
        bus.handshake_event.is_set.return_value = True
        bus._handle_hive_protocol = MagicMock()
        bus.emitter = MagicMock()
        return bus

    def _http_client(self):
        from test_http_client import _client
        client = _client()
        client.crypto_key = None
        client._handle_hive_protocol = MagicMock()
        client.emitter = MagicMock()
        return client

    def test_the_async_door_drops_and_does_not_raise(self):
        bus = self._async_client()
        for frame in self.MALFORMED:
            with self.subTest(frame=frame[:32]):
                self.assertIsNone(bus._parse_or_drop(frame))
        bus._handle_hive_protocol.assert_not_called()

    def test_the_http_door_drops_and_does_not_raise(self):
        client = self._http_client()
        for frame in self.MALFORMED:
            with self.subTest(frame=frame[:32]):
                self.assertIsNone(client._parse_or_drop(frame))
        client._handle_hive_protocol.assert_not_called()

    def test_the_async_receive_callback_swallows_a_malformed_frame(self):
        """The guard lives in ``on_message``'s ``except``, so drive that.

        Without this row the ``except`` clause in ``async_client`` can be
        replaced by one that catches nothing a malformed frame raises, and the
        whole suite stays green.
        """
        bus = self._async_client()
        for frame in self.MALFORMED:
            with self.subTest(frame=frame[:32]):
                self.assertIsNone(bus.on_message(frame))
        bus._handle_hive_protocol.assert_not_called()

    def test_the_http_receive_callback_swallows_a_malformed_frame(self):
        """The same, for the door an HTTP satellite depends on."""
        client = self._http_client()
        for frame in self.MALFORMED:
            with self.subTest(frame=frame[:32]):
                self.assertIsNone(client.on_message(frame))
        client._handle_hive_protocol.assert_not_called()

    def test_an_unknown_msg_type_does_not_block_a_later_message_on_either_door(self):
        """The same proof as the sync door's own test, for the other two.

        An unknown ``msg_type`` raises a bare ``ValueError`` out of the
        constructor, which the old ``except (MalformedWirePayload,
        json.JSONDecodeError)`` tuple did not catch. Asserting no exception
        would not tell a widened-enough tuple from one that drops the frame
        but leaves the handler stopped, so this drives a well-formed frame
        straight after and asserts it still reaches
        ``_handle_hive_protocol``.
        """
        frame = json.dumps({"msg_type": "nonsense", "payload": {}})
        good_frame = json.dumps({"msg_type": "propagate",
                                 "payload": {"msg_type": "bus",
                                             "payload": {"type": "speak",
                                                         "data": {}}}})
        for client in (self._async_client(), self._http_client()):
            with self.subTest(client=type(client).__name__):
                self.assertIsNone(client.on_message(frame))
                client._handle_hive_protocol.assert_not_called()
                client.on_message(good_frame)
                client._handle_hive_protocol.assert_called_once()
                handled = client._handle_hive_protocol.call_args[0][0]
                self.assertEqual(handled.msg_type, HiveMessageType.PROPAGATE)

    def test_both_receive_callbacks_still_handle_a_well_formed_frame(self):
        """The control for the two rows above.

        A callback that swallowed everything would pass them. This one proves
        each callback still reaches ``_handle_hive_protocol``.
        """
        frame = json.dumps({"msg_type": "propagate",
                            "payload": {"msg_type": "bus",
                                        "payload": {"type": "speak",
                                                    "data": {}}}})
        for client in (self._async_client(), self._http_client()):
            with self.subTest(client=type(client).__name__):
                client.on_message(frame)
                client._handle_hive_protocol.assert_called_once()
                handled = client._handle_hive_protocol.call_args[0][0]
                self.assertEqual(handled.msg_type, HiveMessageType.PROPAGATE)

    def test_all_three_doors_still_build_a_well_formed_frame(self):
        """The control: a guard that returned None for everything would pass
        every row above."""
        from hivemind_bus_client.client import HiveMessageBusClient
        from hivemind_bus_client.async_client import AsyncHiveMessageBusClient
        from hivemind_bus_client.http_client import HiveMindHTTPClient

        frame = json.dumps({"msg_type": "propagate",
                            "payload": {"msg_type": "bus",
                                        "payload": {"type": "speak",
                                                    "data": {}}}})
        for door in (HiveMessageBusClient._parse_or_drop,
                     AsyncHiveMessageBusClient._parse_or_drop,
                     HiveMindHTTPClient._parse_or_drop):
            with self.subTest(door=door.__qualname__):
                built = door(frame)
                self.assertIsNotNone(built)
                self.assertEqual(built.msg_type, HiveMessageType.PROPAGATE)


if __name__ == "__main__":
    unittest.main()
