"""Tests for hivemind_bus_client.http_client — HiveMindHTTPClient.emit()
context injection, without any real HTTP traffic.
"""
from unittest.mock import MagicMock, patch

from ovos_bus_client.message import Message as MycroftMessage

from hivemind_bus_client.http_client import HiveMindHTTPClient
from hivemind_bus_client.message import HiveMessage, HiveMessageType


def _client():
    """A minimal HiveMindHTTPClient that never touches a real socket."""
    client = object.__new__(HiveMindHTTPClient)
    client.connected = MagicMock(is_set=lambda: True)
    client.crypto_key = None
    client.compress = False
    client.binarize = False
    client.protocol = MagicMock(binarize=False)
    client._name = "http-agent"
    client._access_key = "k"
    client._host = "http://127.0.0.1"
    client._port = 5678
    client.session_id = "conn-default-session"
    client._site_id = "conn-default-site"
    return client


def _emit_and_capture_context(client, message):
    """The HTTP client's emit() rebuilds the wire HiveMessage from a plain
    dict, so the caller's original Message object is never mutated in
    place - the routing context has to be read back off the payload that
    was actually about to be serialized and sent."""
    with patch("hivemind_bus_client.http_client.serialize_message") as ser, \
            patch("hivemind_bus_client.http_client.requests.post") as post:
        ser.return_value = "{}"
        post.return_value = MagicMock()
        client.emit(message)
    sent_message = ser.call_args.args[0]
    return sent_message.payload.context


class TestEmitRespectsCallerSession:
    """Same contract as the sync/async clients: an explicit per-message
    session must survive emit(), only a missing one gets the connection
    default filled in."""

    def test_explicit_session_id_is_not_overwritten(self):
        client = _client()
        message = MycroftMessage("speak", {"utterance": "hi"},
                                 context={"session": {"session_id": "call-42"}})
        ctx = _emit_and_capture_context(client, message)
        assert ctx["session"]["session_id"] == "call-42"

    def test_missing_session_id_falls_back_to_connection_default(self):
        client = _client()
        message = MycroftMessage("speak", {"utterance": "hi"})
        ctx = _emit_and_capture_context(client, message)
        assert ctx["session"]["session_id"] == "conn-default-session"

    def test_explicit_site_id_is_not_overwritten(self):
        client = _client()
        message = MycroftMessage("speak", {"utterance": "hi"},
                                 context={"session": {"site_id": "remote-site"}})
        ctx = _emit_and_capture_context(client, message)
        assert ctx["session"]["site_id"] == "remote-site"

    def test_missing_site_id_falls_back_to_connection_default(self):
        client = _client()
        message = MycroftMessage("speak", {"utterance": "hi"})
        ctx = _emit_and_capture_context(client, message)
        assert ctx["session"]["site_id"] == "conn-default-site"
