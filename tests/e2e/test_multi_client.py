"""Multiple HiveMessageBusClient instances against one loopback master."""

import time

from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.identity import NodeIdentity

from hivescope import TopologyBuilder


def _make_client(url, key, password, name):
    host, port = url.replace("ws://", "").rstrip("/").split(":")
    port = int(port)
    identity = NodeIdentity()
    identity.access_key = key
    identity.password = password
    identity.default_master = f"ws://{host}"
    identity.default_port = port
    identity.name = name
    identity.site_id = f"{name}-site"
    return HiveMessageBusClient(
        key=key, password=password,
        host=f"ws://{host}", port=port,
        useragent=name, self_signed=False,
        identity=identity,
    )


def test_two_clients_register_independently():
    b = TopologyBuilder()
    m = b.add_master("M0", use_loopback=True)
    m.register_satellite("key-a", password="pw-a")
    m.register_satellite("key-b", password="pw-b")
    try:
        b.start_all()
        c1 = _make_client(m.network_protocol.url, "key-a", "pw-a", "client-a")
        c2 = _make_client(m.network_protocol.url, "key-b", "pw-b", "client-b")
        c1.connect(site_id="site-a")
        c2.connect(site_id="site-b")
        c1.wait_for_handshake(timeout=10)
        c2.wait_for_handshake(timeout=10)
        time.sleep(1)
        peers = m.connected_peers()
        assert any("client-a" in p for p in peers), peers
        assert any("client-b" in p for p in peers), peers
        c1.close()
        c2.close()
    finally:
        b.stop_all()


def test_client_can_close_and_reconnect():
    b = TopologyBuilder()
    m = b.add_master("M0", use_loopback=True)
    m.register_satellite("k", password="p")
    try:
        b.start_all()
        c = _make_client(m.network_protocol.url, "k", "p", "reconnect")
        c.connect(site_id="s1")
        c.wait_for_handshake(timeout=10)
        c.close()

        c2 = _make_client(m.network_protocol.url, "k", "p", "reconnect")
        c2.connect(site_id="s2")
        c2.wait_for_handshake(timeout=10)
        # encrypted session established: v2 crypto_key or v3 Noise transport
        assert c2.crypto_key or c2.noise_transport
        c2.close()
    finally:
        b.stop_all()
