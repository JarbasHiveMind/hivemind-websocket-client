"""wait_for_handshake meets a socket that a refusal closed.

The waiter wakes from its timeout, sees the connection flag still set, and
calls start_handshake. If the refusal has closed the socket in between, the
send raises ValueError from emit. The waiter must report the refusal, which
is the reason the socket went away, not the bare send failure.
"""
from unittest.mock import MagicMock

import pytest

from tests.test_client import _make_client


def _refused_mid_retry(client, reason):
    """start_handshake that finds the socket closed by a refusal."""
    def start_handshake():
        client.connected_event.clear()
        client.started_running = False
        client._auth_rejected = reason
        raise ValueError("You must execute run_forever() before emitting messages")
    return start_handshake


def test_a_refusal_during_the_retry_is_reported_as_the_refusal():
    client = _make_client()
    client.protocol = MagicMock()
    client.protocol.start_handshake.side_effect = _refused_mid_retry(
        client, "the server Noise static key does not match the pinned key. "
                "Run 'hivemind-client forget-server'")
    client.connected_event.set()
    client.handshake_event.clear()
    with pytest.raises(ConnectionRefusedError, match="forget-server"):
        client.wait_for_handshake(timeout=0.01, max_retries=3)
    client.protocol.start_handshake.assert_called_once()


def test_a_plain_drop_during_the_retry_keeps_waiting():
    client = _make_client()
    client.protocol = MagicMock()
    calls = []

    def dropped():
        calls.append(1)
        raise RuntimeError("Can not send messages before opening the websocket connection")
    client.protocol.start_handshake.side_effect = dropped
    client.connected_event.set()
    client.handshake_event.clear()
    with pytest.raises(RuntimeError, match="timed out waiting for handshake"):
        client.wait_for_handshake(timeout=0.01, max_retries=2)
    assert len(calls) == 2
