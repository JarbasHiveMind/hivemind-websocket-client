"""A client object reconnects after the listener restarts.

The listener going away ends the session without a ``/disconnect``, so the
previous session's handshake event and Noise transport survive on the client.
``HiveMindHTTPClient.run`` documents reconnecting on the same object, and a
reused object must therefore handshake again rather than resume a session the
server has forgotten.
"""
from unittest.mock import MagicMock, patch

from hivemind_bus_client.http_client import HiveMindHTTPClient


def _client():
    with patch.object(HiveMindHTTPClient, "start", lambda self: None):
        return HiveMindHTTPClient(key="k", password="p",
                                  host="http://127.0.0.1", port=1234)


def _connect_with_stale_session(client, protocol):
    """Drive connect() on a client left holding a dead session."""
    stale_transport = object()
    client.handshake_event.set()
    client.noise_transport = stale_transport
    client.connected.set()

    response = MagicMock(ok=True)
    response.json.return_value = {}
    with patch("hivemind_bus_client.http_client.requests.post",
               return_value=response):
        client.connect(protocol=protocol, handshake_max_retries=1)
    return stale_transport


def test_connect_drops_the_previous_sessions_noise_transport():
    client = _client()
    protocol = MagicMock()
    # the handshake the protocol would complete for the new session
    protocol.start_handshake.side_effect = lambda: client.handshake_event.set()

    stale_transport = _connect_with_stale_session(client, protocol)

    assert client.noise_transport is not stale_transport


def test_connect_handshakes_again_after_a_listener_restart():
    client = _client()
    protocol = MagicMock()
    protocol.start_handshake.side_effect = lambda: client.handshake_event.set()

    _connect_with_stale_session(client, protocol)

    assert protocol.start_handshake.called, (
        "connect() resumed the previous session instead of handshaking: "
        "wait_for_handshake() returned on the stale handshake_event"
    )
