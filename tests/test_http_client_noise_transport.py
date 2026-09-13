"""HiveMindHTTPClient must speak the protocol v3 Noise transport.

The websocket client did; the HTTP client had no send or receive path for
it. Against a HiveMind-core 5.x listener the handshake completed and then
the first message -- the HELLO -- went out in the clear, the listener closed
the session with 1008, and nothing was ever deliverable.
"""
import json
import threading
from unittest.mock import MagicMock, patch

import pybase64
import pytest
import requests
from ovos_bus_client import Message as MycroftMessage

from hivemind_bus_client.http_client import HiveMindHTTPClient
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.noise import (
    NOISE_PATTERN_XX,
    NOISE_SUITE_CHACHA,
    NoiseTransport,
    NoiseTransportFailed,
    build_prologue,
    start_noise_handshake,
)


def _client(transport=None):
    c = HiveMindHTTPClient.__new__(HiveMindHTTPClient)
    c.noise_transport = transport
    c.crypto_key = None
    c.protocol = MagicMock(binarize=False)
    c.binarize = False
    c.compress = False
    c.connected = threading.Event(); c.connected.set()
    c.handshake_event = threading.Event()
    c.stopped = threading.Event()
    c._host, c._port = "http://127.0.0.1", 5679
    c._name, c._access_key, c._site_id = "ua", "k", "site"
    c.session_id = "sess"
    c.http_timeout = 5
    c._handle_hive_protocol = MagicMock()
    return c


def _ok_response(body=None):
    response = MagicMock(ok=True, status_code=200)
    response.json.return_value = body if body is not None else {"status": "ok"}
    return response


def _hello():
    return HiveMessage(HiveMessageType.HELLO, {"pubkey": "pem"})


# --- sending -----------------------------------------------------------------

def test_emit_on_a_v3_session_goes_through_the_noise_transport():
    transport = MagicMock()
    c = _client(transport)

    c.emit(_hello())

    transport.send_message.assert_called_once()
    plaintext, send = transport.send_message.call_args[0]
    with patch.object(c, "_send_noise_frame") as send_noise_frame:
        send(b"frame")
    send_noise_frame.assert_called_once_with(b"frame", transport)
    assert json.loads(plaintext)["msg_type"] == "hello"


def test_a_binarized_message_hands_the_transport_the_bitstring_bytes():
    """The binary framing is negotiated separately from the encryption: a
    binarized message is the bitstring's bytes inside the Noise frame."""
    transport = MagicMock()
    c = _client(transport)
    c.binarize = True
    c.protocol.binarize = True
    message = HiveMessage(HiveMessageType.BUS, MycroftMessage("speak", {"utterance": "hi"}))
    bitstr = MagicMock(bytes=b"\x00\x01bits")
    with patch("hivemind_bus_client.http_client.get_bitstring", return_value=bitstr):
        c.emit(message)

    plaintext, _send = transport.send_message.call_args[0]
    assert plaintext == b"\x00\x01bits"


def test_a_frame_is_posted_base64_encoded_and_flagged_binary():
    c = _client(MagicMock())
    with patch("hivemind_bus_client.http_client.requests.post",
               return_value=_ok_response()) as post:
        c._send_noise_frame(b"\x01\x02frame", c.noise_transport)

    data = post.call_args.kwargs["data"]
    assert data["binary"] == "1"
    assert pybase64.b64decode(data["message"]) == b"\x01\x02frame"
    assert post.call_args.kwargs["params"] == {"authorization": c.auth}
    assert post.call_args.kwargs["timeout"] == c.http_timeout


def test_a_rejected_frame_invalidates_the_session_and_raises():
    """The send counter advanced for the frame; if the failure were swallowed
    the next emit() would reuse a counter the hub rejects, and every later
    message would silently die."""
    c = _client(MagicMock())
    with patch("hivemind_bus_client.http_client.requests.post",
               return_value=MagicMock(ok=False, status_code=403)):
        with pytest.raises(ConnectionError):
            c._send_noise_frame(b"frame", c.noise_transport)

    assert c.noise_transport is None
    assert not c.connected.is_set()
    c.protocol.reset_connection_state.assert_called_once()


def test_an_error_body_under_http_200_is_a_rejection_too():
    """The listener answers "Client is not connected" with HTTP 200 and an
    error body once it dropped the session; that is exactly the case this
    transport exists to notice."""
    c = _client(MagicMock())
    with patch("hivemind_bus_client.http_client.requests.post",
               return_value=_ok_response({"error": "Client is not connected"})):
        with pytest.raises(ConnectionError, match="not connected"):
            c._send_noise_frame(b"frame", c.noise_transport)

    assert c.noise_transport is None
    assert not c.connected.is_set()


def test_a_buffered_chunk_acknowledgement_is_success():
    c = _client(MagicMock())
    with patch("hivemind_bus_client.http_client.requests.post",
               return_value=_ok_response({"status": "buffered"})):
        c._send_noise_frame(b"chunk", c.noise_transport)

    assert c.connected.is_set()


def test_a_non_json_body_under_http_200_is_success():
    c = _client(MagicMock())
    response = MagicMock(ok=True, status_code=200)
    response.json.side_effect = ValueError("not json")
    with patch("hivemind_bus_client.http_client.requests.post", return_value=response):
        c._send_noise_frame(b"frame", c.noise_transport)

    assert c.connected.is_set()


def test_a_send_exception_also_invalidates_the_session():
    c = _client(MagicMock())
    with patch("hivemind_bus_client.http_client.requests.post",
               side_effect=OSError("connection reset")):
        with pytest.raises(OSError):
            c._send_noise_frame(b"frame", c.noise_transport)

    assert c.noise_transport is None
    assert not c.connected.is_set()


def test_a_stale_transports_rejection_does_not_invalidate_the_current_session():
    """emit() captures noise_transport before the POST; if connect() installs
    a new transport while that POST is still in flight, the stale transport's
    rejection must not clear the session the new transport now owns."""
    stale = MagicMock()
    c = _client(stale)
    current = MagicMock()
    c.noise_transport = current  # connect() already installed the new one

    with patch("hivemind_bus_client.http_client.requests.post",
               return_value=MagicMock(ok=False, status_code=403)):
        with pytest.raises(ConnectionError):
            c._send_noise_frame(b"frame", stale)

    assert c.noise_transport is current
    assert c.connected.is_set()
    c.protocol.reset_connection_state.assert_not_called()


def test_the_current_transports_rejection_still_invalidates_the_session():
    transport = MagicMock()
    c = _client(transport)

    with patch("hivemind_bus_client.http_client.requests.post",
               return_value=MagicMock(ok=False, status_code=403)):
        with pytest.raises(ConnectionError):
            c._send_noise_frame(b"frame", transport)

    assert c.noise_transport is None
    assert not c.connected.is_set()


# --- receiving ---------------------------------------------------------------

def test_received_frames_are_decrypted_then_dispatched():
    transport = MagicMock()
    transport.decrypt_frame.return_value = _hello().serialize()
    c = _client(transport)

    c.on_message(b"ciphertext")

    transport.decrypt_frame.assert_called_once_with(b"ciphertext")
    dispatched = c._handle_hive_protocol.call_args[0][0]
    assert dispatched.msg_type == HiveMessageType.HELLO


def test_a_cleartext_message_on_a_v3_session_is_dropped():
    c = _client(MagicMock())

    c.on_message(_hello().serialize())

    c._handle_hive_protocol.assert_not_called()


def test_a_buffered_chunk_dispatches_nothing():
    transport = MagicMock()
    transport.decrypt_frame.return_value = None
    c = _client(transport)

    c.on_message(b"chunk")

    c._handle_hive_protocol.assert_not_called()


def test_a_tampered_frame_closes_the_session():
    transport = MagicMock()
    transport.decrypt_frame.side_effect = NoiseTransportFailed("bad tag")
    c = _client(transport)
    c.disconnect = MagicMock(side_effect=c._invalidate_local_session)

    c.on_message(b"tampered")

    c.disconnect.assert_called_once()
    c._handle_hive_protocol.assert_not_called()
    assert c.noise_transport is None


def test_a_frame_after_the_session_is_invalidated_is_not_processed_cleartext():
    """run() keeps iterating a batch it already drained. After a Noise failure
    invalidated the session, a following frame must not reach the legacy
    path just because noise_transport is None by then."""
    c = _client(None)
    c.connected.clear()

    c.on_message(_hello().serialize())

    c._handle_hive_protocol.assert_not_called()


# --- session lifecycle -------------------------------------------------------

def test_disconnect_forgets_the_transport_and_resets_the_protocol():
    c = _client(MagicMock())
    with patch("hivemind_bus_client.http_client.requests.post",
               return_value=_ok_response({})):
        c.disconnect()

    assert c.noise_transport is None
    assert not c.connected.is_set()
    c.protocol.reset_connection_state.assert_called_once()


def test_disconnect_invalidates_even_when_the_request_fails():
    c = _client(MagicMock())
    with patch("hivemind_bus_client.http_client.requests.post",
               side_effect=OSError("timeout")):
        with pytest.raises(OSError):
            c.disconnect()

    assert c.noise_transport is None
    assert not c.connected.is_set()


def test_close_connection_releases_the_session_for_abort_noise():
    """HiveMindSlaveProtocol._abort_noise calls close_connection() on the
    bound client after a failed or tampered exchange."""
    c = _client(MagicMock())
    c.disconnect = MagicMock(side_effect=c._invalidate_local_session)

    c.close_connection()

    c.disconnect.assert_called_once()
    assert not c.connected.is_set()


def test_wait_for_handshake_reports_a_session_the_hub_closed():
    """A hub that rejected us is not a slow hub: restarting the handshake on
    a reset protocol would only report "not connected"."""
    c = _client(MagicMock())
    c.connected.clear()

    with pytest.raises(ConnectionRefusedError, match="closed the session"):
        c.wait_for_handshake(timeout=0.01, max_retries=3)

    c.protocol.start_handshake.assert_not_called()


def test_the_receive_loop_survives_an_invalidation_and_resumes_after_connect():
    """A failure inside frame handling ends the session, not the thread: the
    loop goes back to waiting for connect(), so a client can reconnect."""
    c = _client(MagicMock())
    polls = []
    resumed = threading.Event()

    def get_messages():
        polls.append(c.connected.is_set())
        if len(polls) == 1:
            return ["first-batch"]
        resumed.set()
        return []

    c.get_messages = get_messages
    c.get_binary_messages = lambda: []
    c.on_message = MagicMock(side_effect=lambda m: c._invalidate_local_session())
    c.stopped.clear()
    thread = threading.Thread(target=c.run, daemon=True)
    thread.start()

    # the first batch invalidated the session; the loop must still be alive
    for _ in range(100):
        if len(polls) == 1 and not c.connected.is_set():
            break
        threading.Event().wait(0.02)
    assert not c.connected.is_set()
    assert thread.is_alive()

    c.connected.set()  # a later connect()
    assert resumed.wait(5), "polling did not resume after reconnecting"
    c.connected.clear()  # no real /disconnect POST from the exiting loop
    c.stopped.set()
    thread.join(5)
    assert not thread.is_alive()


def test_a_get_messages_error_survives_a_hub_that_times_out_on_disconnect():
    """A RuntimeError/ConnectionError from get_messages() ends the session
    through close_connection(), which swallows a failed /disconnect POST.
    Routing it through disconnect() instead would let a hub that times out
    on /disconnect re-raise and kill this reconnectable receive thread."""
    c = _client(MagicMock())
    polls = []

    def get_messages():
        polls.append(1)
        raise RuntimeError("Client is not connected")

    c.get_messages = get_messages
    c.get_binary_messages = lambda: []
    c.connected.set()
    c.stopped.clear()
    with patch("hivemind_bus_client.http_client.requests.post",
               side_effect=requests.Timeout("hub did not answer")):
        thread = threading.Thread(target=c.run, daemon=True)
        thread.start()
        for _ in range(100):
            if polls and not c.connected.is_set():
                break
            threading.Event().wait(0.02)
        assert not c.connected.is_set()
        assert thread.is_alive(), "the receive thread died on a failed /disconnect POST"
        c.stopped.set()
        thread.join(5)
    assert not thread.is_alive()


def test_a_shutdown_that_lands_before_the_loop_starts_still_wins():
    """__init__ starts the worker thread; a shutdown() racing that start must
    not be undone by the loop re-arming its own stop flag."""
    c = _client()
    polls = []

    def get_messages():
        polls.append(1)
        c.stopped.set()  # bound the loop should it wrongly start
        return []

    c.get_messages = get_messages
    c.get_binary_messages = list
    c.connected.set()
    c.stopped.set()
    with patch("hivemind_bus_client.http_client.requests.post") as post:
        c.run()
    assert polls == [], "the loop polled after shutdown() had been called"
    assert c.stopped.is_set()
    post.assert_called_once()  # the live session is still torn down


def test_concurrent_callers_share_one_session_lock():
    """Two threads reaching the lazy lock path on an instance built without
    __init__ must not each create their own lock."""
    c = HiveMindHTTPClient.__new__(HiveMindHTTPClient)
    assert "_session_lock_" not in c.__dict__
    seen = []
    go = threading.Barrier(8)

    def grab():
        go.wait(5)
        seen.append(c._session_lock())

    threads = [threading.Thread(target=grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert len(seen) == 8
    assert len({id(lock) for lock in seen}) == 1


def test_init_creates_the_session_lock_up_front():
    # key and password together bypass the saved node identity, which a CI
    # runner does not have
    with patch("hivemind_bus_client.http_client.threading.Thread"):
        c = HiveMindHTTPClient(key="k", password="pw",
                               host="http://localhost", port=5678)
    assert isinstance(c.__dict__.get("_session_lock_"), type(threading.RLock()))
    assert c._session_lock() is c.__dict__["_session_lock_"]


# --- the whole path, with real crypto ---------------------------------------

def _transport_pair():
    node_id = "hub-node"
    prologue = build_prologue({"node_id": node_id, "handshake": True},
                              NOISE_PATTERN_XX, NOISE_SUITE_CHACHA)
    password = "harness-" + "deadbeef"
    initiator = start_noise_handshake(
        initiator=True, pattern=NOISE_PATTERN_XX, suite=NOISE_SUITE_CHACHA,
        password=password, node_id=node_id, prologue=prologue)
    responder = start_noise_handshake(
        initiator=False, pattern=NOISE_PATTERN_XX, suite=NOISE_SUITE_CHACHA,
        password=password, node_id=node_id, prologue=prologue)
    responder.read_message(initiator.write_message())
    initiator.read_message(responder.write_message())
    responder.read_message(initiator.write_message())
    return NoiseTransport(initiator), NoiseTransport(responder)


@pytest.mark.parametrize("size", [64, 200_000])
def test_a_message_survives_the_round_trip_through_real_noise_transports(size):
    """emit() -> base64 frames over POST -> on_message() on the other side,
    with the transport chunking anything over one frame."""
    sender_transport, receiver_transport = _transport_pair()
    sender = _client(sender_transport)
    receiver = _client(receiver_transport)
    posted = []

    def capture(url, data, params, timeout):
        posted.append(pybase64.b64decode(data["message"]))
        assert data["binary"] == "1"
        return _ok_response({"status": "ok"})

    payload = {"text": "x" * size}
    with patch("hivemind_bus_client.http_client.requests.post", side_effect=capture):
        sender.emit(HiveMessage(HiveMessageType.HELLO, payload))

    assert len(posted) >= (2 if size > 65_000 else 1)
    for frame in posted:
        receiver.on_message(frame)

    receiver._handle_hive_protocol.assert_called_once()
    received = receiver._handle_hive_protocol.call_args[0][0]
    assert received.msg_type == HiveMessageType.HELLO
    assert received.payload == payload
