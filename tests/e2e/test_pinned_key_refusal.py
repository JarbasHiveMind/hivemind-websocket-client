"""A client-side pinned-key refusal, against a real hub.

The client pinned a server key, and the server presents another key. The
client must stop after the first refusal and name forget-server. It used to
reconnect every few seconds forever.
"""
import time

import pytest
from json_database import JsonStorage

from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.identity import NodeIdentity
from hivescope import TopologyBuilder

PASSWORD = "pinned-horse-battery-staple-92"
KEY = "pinned-key"


def _client(tmp_path, url, name):
    host, port = url.replace("ws://", "").rstrip("/").split(":")
    identity = NodeIdentity(identity_file=JsonStorage(str(tmp_path / f"{name}.json")))
    identity.access_key = KEY
    identity.password = PASSWORD
    identity.name = name
    identity.noise_key = str(tmp_path / f"{name}.noise")
    return HiveMessageBusClient(key=KEY, password=PASSWORD, host=f"ws://{host}",
                                port=int(port), useragent=name,
                                self_signed=False, identity=identity)


@pytest.fixture
def master():
    b = TopologyBuilder()
    m = b.add_master("M0", use_loopback=True)
    m.register_satellite(KEY, password=PASSWORD)
    b.start_all()
    try:
        yield m
    finally:
        b.stop_all()


def test_a_server_key_that_contradicts_the_pin_stops_the_client(tmp_path, master):
    url = master.network_protocol.url
    first = _client(tmp_path, url, "dev-a")
    first.connect(site_id="s")
    first.wait_for_handshake(timeout=10)
    pin_id = first.protocol._noise_pin_id
    first.close()

    client = _client(tmp_path, url, "dev-a")
    client.identity.pin_noise_key(pin_id, "00" * 32)
    opened = []
    client.emitter.on("open", lambda *a: opened.append(1))
    with pytest.raises(ConnectionRefusedError, match="forget-server"):
        client.connect(site_id="s", handshake_max_retries=3)
    time.sleep(8)  # longer than one reconnect delay
    try:
        assert client._auth_rejected and "forget-server" in client._auth_rejected
        assert len(opened) <= 2, f"client reconnected {len(opened)} times"
        assert client.identity.get_pinned_noise_key(pin_id) == "00" * 32
    finally:
        client.close()

