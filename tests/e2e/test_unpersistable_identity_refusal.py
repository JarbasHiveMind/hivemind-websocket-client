"""A client whose identity cannot persist must fail closed at connect.

A bare NodeIdentity() with no app_name and no shared file refuses to create
the shared identity file. The first Noise contact must pin the server key,
and that pin needs a write. The client must raise a clear error at once. It
must not hang until a timeout, and it must not keep the pin only in memory.
"""
import asyncio
import time

import pytest
from hivescope import TopologyBuilder

from hivemind_bus_client.async_client import AsyncHiveMessageBusClient
from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.identity import NodeIdentity

PASSWORD = "unpersistable-horse-battery-staple-17"
KEY = "unpersistable-key"


@pytest.fixture
def master(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    b = TopologyBuilder()
    m = b.add_master("M0", use_loopback=True)
    m.register_satellite(KEY, password=PASSWORD)
    b.start_all()
    try:
        yield m
    finally:
        b.stop_all()


def _bare_identity():
    identity = NodeIdentity()
    assert identity.refuses_to_create_shared
    identity.access_key = KEY
    identity.password = PASSWORD
    return identity


def _host_port(m):
    host, port = m.network_protocol.url.replace("ws://", "").rstrip("/").split(":")
    return f"ws://{host}", int(port)


def test_sync_client_refuses_an_unpersistable_identity(master):
    host, port = _host_port(master)
    client = HiveMessageBusClient(key=KEY, password=PASSWORD, host=host,
                                  port=port, useragent="bare", self_signed=False,
                                  identity=_bare_identity())
    start = time.monotonic()
    with pytest.raises(ValueError, match="--shared set-identity"):
        client.connect(handshake_max_retries=3)
    assert time.monotonic() - start < 5
    client.close()


def test_async_client_refuses_an_unpersistable_identity(master):
    host, port = _host_port(master)

    async def go():
        client = AsyncHiveMessageBusClient(key=KEY, password=PASSWORD,
                                           host=host, port=port,
                                           useragent="bare", self_signed=False,
                                           identity=_bare_identity())
        start = time.monotonic()
        with pytest.raises(ValueError, match="--app <your-app>"):
            await asyncio.wait_for(client.connect(handshake_max_retries=3), 30)
        assert time.monotonic() - start < 5
        await client.close()

    asyncio.run(go())
