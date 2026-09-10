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
    client.http_timeout = 30
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


# ---------------------------------------------------------------------------
# transport hardening
# ---------------------------------------------------------------------------
import inspect
import threading

import pytest

from hivemind_bus_client import http_client as _hc


class TestBoundedHandshake:
    """wait_for_handshake used to self-recurse forever on a hub that never
    completes the handshake, ending in RecursionError."""

    def test_raises_after_bound_instead_of_recursing(self):
        client = _client()
        client.handshake_event = threading.Event()  # never set
        client.protocol = MagicMock()
        with pytest.raises(ConnectionRefusedError):
            client.wait_for_handshake(timeout=0, max_retries=3)
        assert client.protocol.start_handshake.call_count == 3


class TestConnectChecksStatus:
    """connect() must surface an HTTP-level failure instead of marking the
    connection up and falling into the handshake loop."""

    def _connect_client(self):
        client = _client()
        client.connected = threading.Event()
        client.handshake_event = threading.Event()
        client.identity = MagicMock()
        client.share_bus = False
        client.protocol = MagicMock()
        client.wait_for_handshake = MagicMock()
        return client

    def test_non_2xx_connect_raises(self):
        client = self._connect_client()
        with patch("hivemind_bus_client.http_client.requests.post") as post:
            post.return_value = MagicMock(ok=False, status_code=401)
            with pytest.raises(ConnectionRefusedError):
                client.connect(protocol=client.protocol)
        assert not client.connected.is_set()
        client.wait_for_handshake.assert_not_called()

    def test_error_payload_connect_raises(self):
        client = self._connect_client()
        with patch("hivemind_bus_client.http_client.requests.post") as post:
            post.return_value = MagicMock(
                ok=True, status_code=200,
                json=MagicMock(return_value={"error": "bad key"}))
            with pytest.raises(ConnectionRefusedError):
                client.connect(protocol=client.protocol)
        assert not client.connected.is_set()


class TestRequestsCarryTimeout:
    """A dead/slow hub without a timeout hangs the receive loop forever."""

    def test_emit_passes_timeout(self):
        client = _client()
        message = MycroftMessage("speak", {"utterance": "hi"})
        with patch("hivemind_bus_client.http_client.serialize_message",
                   return_value="{}"), \
                patch("hivemind_bus_client.http_client.requests.post") as post:
            post.return_value = MagicMock()
            client.emit(message)
        assert post.call_args.kwargs.get("timeout") == 30

    def test_get_messages_passes_timeout(self):
        client = _client()
        with patch("hivemind_bus_client.http_client.requests.get") as get:
            get.return_value = MagicMock(
                json=MagicMock(return_value={"messages": []}))
            client.get_messages()
        assert get.call_args.kwargs.get("timeout") == 30

    def test_get_binary_messages_passes_timeout(self):
        client = _client()
        with patch("hivemind_bus_client.http_client.requests.get") as get:
            get.return_value = MagicMock(
                json=MagicMock(return_value={"b64_messages": []}))
            client.get_binary_messages()
        assert get.call_args.kwargs.get("timeout") == 30

    def test_disconnect_passes_timeout(self):
        client = _client()
        client.connected = threading.Event()
        client.handshake_event = threading.Event()
        with patch("hivemind_bus_client.http_client.requests.post") as post:
            post.return_value = MagicMock(json=MagicMock(return_value={}))
            client.disconnect()
        assert post.call_args.kwargs.get("timeout") == 30


class TestReceiveThreadSurvivesServerError:
    """A server-error payload must not kill the daemon receive thread while
    leaving connected set — the caller would keep emitting into a dead link.
    The loop ends the session and goes back to waiting for connect(); it
    returns once the caller shuts the client down."""

    def test_run_disconnects_on_server_error(self):
        client = _client()
        client.connected = threading.Event()
        client.connected.set()
        client.stopped = threading.Event()
        client.get_messages = MagicMock(side_effect=RuntimeError("boom"))
        client.get_binary_messages = MagicMock(return_value=[])

        def disconnect():
            client.connected.clear()
            client.stopped.set()  # the caller shuts down after the error

        client.disconnect = MagicMock(side_effect=disconnect)

        client.run()  # must return cleanly, not raise out of the thread

        assert client.disconnect.called
        assert not client.connected.is_set()


class TestNoMutableDefaults:
    def test_bin_callbacks_default_is_none(self):
        sig = inspect.signature(_hc.HiveMindHTTPClient.__init__)
        assert sig.parameters["bin_callbacks"].default is None

    def test_connect_bus_default_is_none(self):
        sig = inspect.signature(_hc.HiveMindHTTPClient.connect)
        assert sig.parameters["bus"].default is None


class TestProtocolHandlersRunOnce:
    """bind() registers the protocol's handlers through on(); the dispatcher
    must not call them a second time by name. Over HTTP a second
    handle_handshake re-entered the Noise exchange and aborted the session."""

    @pytest.mark.parametrize("msg_type, handler", [
        (HiveMessageType.HANDSHAKE, "handle_handshake"),
        (HiveMessageType.HELLO, "handle_hello"),
        (HiveMessageType.BUS, "handle_bus"),
        (HiveMessageType.BROADCAST, "handle_broadcast"),
        (HiveMessageType.PROPAGATE, "handle_propagate"),
        (HiveMessageType.INTERCOM, "handle_intercom"),
        (HiveMessageType.ESCALATE, "handle_illegal_msg"),
        (HiveMessageType.SHARED_BUS, "handle_illegal_msg"),
    ])
    def test_each_protocol_handler_runs_exactly_once(self, msg_type, handler):
        from hivemind_bus_client.protocol import HiveMindSlaveProtocol
        client = _client()
        client._handlers = {}
        client._agent_handlers = {}
        proto = MagicMock(spec=HiveMindSlaveProtocol)
        client.protocol = proto
        # what HiveMindSlaveProtocol.bind() does with the client
        for t, name in [(HiveMessageType.HELLO, "handle_hello"),
                        (HiveMessageType.BROADCAST, "handle_broadcast"),
                        (HiveMessageType.PROPAGATE, "handle_propagate"),
                        (HiveMessageType.INTERCOM, "handle_intercom"),
                        (HiveMessageType.ESCALATE, "handle_illegal_msg"),
                        (HiveMessageType.SHARED_BUS, "handle_illegal_msg"),
                        (HiveMessageType.QUERY, "handle_query"),
                        (HiveMessageType.CASCADE, "handle_cascade"),
                        (HiveMessageType.BUS, "handle_bus"),
                        (HiveMessageType.HANDSHAKE, "handle_handshake")]:
            client.on(t, getattr(proto, name))
        payload = MycroftMessage("speak", {"utterance": "hi"}) \
            if msg_type == HiveMessageType.BUS else {"pubkey": "x"}
        client._handle_hive_protocol(HiveMessage(msg_type, payload))
        assert getattr(proto, handler).call_count == 1
