"""A hub that answers the websocket upgrade and then sends nothing.

Two faults, both with a real loopback socket and a real client:

1. ``close()`` on such a connection often left the reconnect worker alive.
   The worker waits in ``select()`` on the socket. ``WebSocketApp.close()``
   closes the file descriptor from the calling thread, and that does not wake
   ``select()`` on the worker thread. On dev the worker outlived ``close()``
   in most of 30 runs.
2. The connect watchdog stopped at ``on_open``. A hub that completes the
   upgrade and never sends HELLO or a handshake kept the client waiting for
   ever, with no retry.
"""
import base64
import hashlib
import socket
import threading
import time
from unittest.mock import patch

from ovos_utils.fakebus import FakeBus

from hivemind_bus_client.client import HiveMessageBusClient

_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _UpgradeThenSilentHub:
    """Answer the websocket upgrade, then send nothing (or one text frame)."""

    def __init__(self, send_frame: bool = False):
        self.send_frame = send_frame
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
            threading.Thread(target=self._upgrade, args=(conn,), daemon=True).start()

    def _upgrade(self, conn):
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            key = [line.split(b":", 1)[1].strip() for line in data.split(b"\r\n")
                   if line.lower().startswith(b"sec-websocket-key")][0]
            accept = base64.b64encode(hashlib.sha1(key + _GUID).digest())
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                         b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                         b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
            if self.send_frame:
                # an unmasked text frame "{}": the hub is not silent
                conn.sendall(b"\x81\x02{}")
        except OSError:
            return

    def close(self):
        self._srv.close()
        for conn in self._conns:
            try:
                conn.close()
            except OSError:
                pass


def _client(port):
    return HiveMessageBusClient(
        key="t1349-key", password="t1349-password", host="ws://127.0.0.1",
        port=port, useragent="t1349", self_signed=False, internal_bus=FakeBus(),
        websocket_ping_interval=None, websocket_ping_timeout=None)


def _wait(predicate, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_close_stops_the_worker_of_an_opened_silent_connection_30_runs():
    """30 runs: close() stops the worker every time (dev: 27 of 30 stayed
    alive, each close() took 8 s)."""
    alive = 0
    slow = 0
    for _ in range(30):
        hub = _UpgradeThenSilentHub()
        client = _client(hub.port)
        try:
            thread = client.run_in_thread()
            assert _wait(client.connected_event.is_set, timeout=5), "never opened"
            time.sleep(0.05)  # the worker is now waiting for a frame
            started = time.monotonic()
            client.close(timeout=2)
            if time.monotonic() - started >= 2:
                slow += 1
            if thread.is_alive():
                alive += 1
        finally:
            hub.close()
    assert alive == 0, f"the worker outlived close() in {alive} of 30 runs"
    assert slow == 0, f"close() hit its join timeout in {slow} of 30 runs"


def test_a_hub_silent_after_the_upgrade_is_retried():
    """The watchdog abandons an opened connection that received no frame
    (dev: one connection, then nothing)."""
    hub = _UpgradeThenSilentHub()
    client = _client(hub.port)
    client.websocket_connect_timeout = 0.5
    try:
        with patch("hivemind_bus_client.client.random.uniform", return_value=0.05):
            client.run_in_thread()
            assert _wait(lambda: len(hub.accepted) >= 3, timeout=8), (
                f"the client connected {len(hub.accepted)} time(s) to a hub that "
                "sends nothing after the upgrade; it must retry")
    finally:
        client.close(timeout=3)
        hub.close()


def test_a_hub_that_sends_a_frame_is_left_alone():
    """Control: one frame after the upgrade stops the watchdog."""
    hub = _UpgradeThenSilentHub(send_frame=True)
    client = _client(hub.port)
    client.websocket_connect_timeout = 0.5
    try:
        with patch("hivemind_bus_client.client.random.uniform", return_value=0.05):
            client.run_in_thread()
            assert _wait(lambda: len(hub.accepted) >= 1, timeout=5)
            time.sleep(2.0)
            assert len(hub.accepted) == 1, (
                f"{len(hub.accepted)} connections to a hub that answered")
    finally:
        client.close(timeout=3)
        hub.close()
