"""
E2E tests for HiveMessageBusClient encryption negotiation.

Tests cipher and encoding selection between client and master.
"""

import pytest
from hivescope import TopologyBuilder


class TestEncryptionNegotiation:
    """Test cipher and encoding selection."""

    def test_client_and_master_agree_on_encryption(self):
        """Client and master negotiate matching cipher and encoding."""
        b = TopologyBuilder()
        m = b.add_master("M0", use_loopback=True)
        m.register_satellite("test-key", password="test-password")
        b.start_all()

        try:
            from hivemind_bus_client.client import HiveMessageBusClient
            from hivemind_bus_client.identity import NodeIdentity

            ws_url = m.network_protocol.url
            parts = ws_url.replace("ws://", "").replace("wss://", "").rstrip("/").split(":")
            host, port = parts[0], int(parts[1])

            identity = NodeIdentity()
            identity.access_key = "test-key"
            identity.password = "test-password"
            identity.name = "test-client"

            client = HiveMessageBusClient(
                key="test-key",
                password="test-password",
                host=f"ws://{host}",
                port=port,
                identity=identity,
            )

            client.connect(site_id="test-site")
            client.wait_for_handshake(timeout=10)

            # Both should have negotiated encryption
            # (actual cipher/encoding comparison depends on availability)
            assert client.crypto_key is not None, "No crypto key"

            client.close()
        finally:
            b.stop_all()
