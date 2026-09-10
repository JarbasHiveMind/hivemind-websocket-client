"""A refused identity must fail fast and say why.

The server closes with RFC6455 code 1008 when it rejects the credentials.
websocket-client delivers that CLOSE to ``on_error`` as an ``ABNF`` control
frame, not to ``on_close`` and not as an exception, so the client used to
classify it as a transport blip and reconnect forever. The operator saw a
repeating raw close frame and a command that never returned.

Retrying cannot help: the identity is identical on every attempt.
"""
from unittest.mock import MagicMock

import pytest
from websocket import ABNF

from hivemind_bus_client.client import HiveMessageBusClient


def _close_frame(code: int, reason: bytes = b"") -> ABNF:
    payload = bytes([code >> 8, code & 0xFF]) + reason
    return ABNF(opcode=ABNF.OPCODE_CLOSE, data=payload)


@pytest.fixture
def client():
    node = object.__new__(HiveMessageBusClient)
    node._auth_rejected = None
    node.emitter = MagicMock()
    node._clear_connection_state = MagicMock()
    node.close = MagicMock()
    return node


class TestRefusedIdentityIsFatal:
    def test_a_1008_close_stops_the_client_instead_of_reconnecting(self, client):
        client.on_error(None, _close_frame(1008, b"invalid api key"))

        assert client._auth_rejected == "invalid api key", \
            "the reason from the server must reach the operator verbatim"
        client.close.assert_called_once()

    def test_the_reason_is_optional(self, client):
        client.on_error(None, _close_frame(1008))
        assert client._auth_rejected == "credentials refused"

    def test_a_non_utf8_reason_does_not_crash_the_error_handler(self, client):
        client.on_error(None, _close_frame(1008, b"\xff\xfe"))
        assert client._auth_rejected == "credentials refused"


class TestOrdinaryDisconnectsStillReconnect:
    """The fix must not turn a network blip into a permanent failure."""

    @pytest.mark.parametrize("code", [1000, 1001, 1006, 1011])
    def test_any_other_close_code_leaves_the_client_reconnecting(self, client, code):
        client.on_error(None, _close_frame(code, b"bye"))

        assert client._auth_rejected is None, f"close {code} is not an auth refusal"
        client.close.assert_not_called()

    def test_a_truncated_close_frame_is_not_read_as_a_refusal(self, client):
        client.on_error(None, ABNF(opcode=ABNF.OPCODE_CLOSE, data=b"\x03"))
        assert client._auth_rejected is None

    def test_a_non_close_control_frame_is_ignored(self, client):
        client.on_error(None, ABNF(opcode=ABNF.OPCODE_PING, data=b"\x03\xf0"))
        assert client._auth_rejected is None
        client.close.assert_not_called()
