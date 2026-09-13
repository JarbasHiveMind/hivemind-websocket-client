"""A hub that accepts TCP but never answers the websocket upgrade.

A stopped hivemind-core process (SIGSTOP), a wedged listener or a black hole
still completes the TCP handshake in the kernel, so the client's upgrade
request is sent and no response ever comes. websocket-client reads that
response with the socket's default timeout, which is None, so
``WebSocketApp.run_forever()`` never returns. The reconnect loop in
``HiveMessageBusClient._run_forever`` only schedules the next attempt after
``run_forever()`` returns, so the satellite never retried: on the ser9 QA rig
it sat for 47 minutes with no further attempt. ``close()`` could not stop that
worker either, because closing the websocket does not wake a thread blocked
in a socket read.

These tests use a real listening socket that accepts connections and never
replies, and a real client.
"""
import socket
import threading
import time
from unittest.mock import MagicMock, patch

from ovos_utils.fakebus import FakeBus

from hivemind_bus_client.client import HiveMessageBusClient


class _SilentHub:
    """Accept TCP connections, keep them open, never send a byte."""

    def __init__(self):
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self.port = self._srv.getsockname()[1]
        self.accepted = []
        self._conns = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            self._conns.append(conn)
            self.accepted.append(time.monotonic())

    def close(self):
        self._srv.close()
        for conn in self._conns:
            try:
                conn.close()
            except OSError:
                pass


def _client(port):
    return HiveMessageBusClient(
        key="t1046-key", password="t1046-password", host="ws://127.0.0.1",
        port=port, useragent="t1046", self_signed=False, internal_bus=FakeBus(),
        websocket_ping_interval=None, websocket_ping_timeout=None)


def _wait(predicate, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def test_a_hub_that_never_answers_the_upgrade_is_retried():
    """The attempt is abandoned after the connect timeout and the reconnect
    loop tries again (dev: one connection, then nothing)."""
    hub = _SilentHub()
    client = _client(hub.port)
    client.websocket_connect_timeout = 0.5
    try:
        # keep the jittered reconnect delay short so the test stays fast
        with patch("hivemind_bus_client.client.random.uniform", return_value=0.05):
            client.run_in_thread()
            assert _wait(lambda: len(hub.accepted) >= 3, timeout=8), (
                f"the client connected {len(hub.accepted)} time(s) to a hub that "
                "never answers the upgrade; it must keep retrying")
    finally:
        client.close(timeout=3)
        hub.close()


def test_close_stops_a_worker_waiting_for_the_upgrade():
    """close() ends a worker blocked in the upgrade read, even with no connect
    timeout (dev: the worker thread stays alive)."""
    hub = _SilentHub()
    client = _client(hub.port)
    client.websocket_connect_timeout = None
    try:
        thread = client.run_in_thread()
        assert _wait(lambda: len(hub.accepted) >= 1, timeout=5), "the client never connected"
        time.sleep(0.2)  # the upgrade request is now waiting for a response
        started = time.monotonic()
        client.close(timeout=3)
        assert not thread.is_alive(), "close() did not stop a worker blocked in the upgrade"
        assert time.monotonic() - started < 3
    finally:
        hub.close()


def test_the_watchdog_leaves_an_opened_connection_alone():
    """Once on_open has fired for this attempt, the watchdog does nothing."""
    client = _client(5678)
    app = MagicMock()
    opened = threading.Event()
    opened.set()

    client._abort_stalled_connect(app, opened)

    app.sock.sock.shutdown.assert_not_called()
    assert app.keep_running is not False
