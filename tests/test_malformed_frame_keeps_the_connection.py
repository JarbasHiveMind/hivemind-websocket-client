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

from tests.test_client import _make_client


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


if __name__ == "__main__":
    unittest.main()
