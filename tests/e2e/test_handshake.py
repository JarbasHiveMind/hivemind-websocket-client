"""
E2E tests for HiveMessageBusClient handshake via WebSocket.

Tests the production HiveMessageBusClient (websocket-based satellite) against
a loopback master that has a real WebSocket server. Covers:
- Client handshake completion
- Crypto key negotiation
- Session establishment
"""

import pytest
from hivescope import TopologyBuilder
from hivescope.assertions import assert_handshake_complete, assert_client_registered


class TestWebSocketHandshake:
    """Test HiveMessageBusClient handshake via real WebSocket (loopback)."""

    def test_client_completes_handshake_via_websocket(self):
        """HiveMessageBusClient handshakes successfully via loopback WebSocket."""
        # Build a master with loopback network protocol
        b = TopologyBuilder()
        m = b.add_master("M0", use_loopback=True)
        m.register_satellite("test-key", password="test-password")
        b.start_all()

        try:
            # Get the WebSocket URL from the loopback network protocol
            ws_url = m.network_protocol.url  # e.g., ws://127.0.0.1:12345/

            # Create a real HiveMessageBusClient and connect
            from hivemind_bus_client.client import HiveMessageBusClient
            from hivemind_bus_client.identity import NodeIdentity

            # Extract host and port from URL
            # URL format: ws://127.0.0.1:PORT/
            parts = ws_url.replace("ws://", "").replace("wss://", "").rstrip("/").split(":")
            host, port = parts[0], int(parts[1])

            identity = NodeIdentity()
            identity.access_key = "test-key"
            identity.password = "test-password"
            identity.default_master = f"ws://{host}"
            identity.default_port = port
            identity.name = "test-client"

            client = HiveMessageBusClient(
                key="test-key",
                password="test-password",
                host=f"ws://{host}",
                port=port,
                useragent="test-client",
                self_signed=False,
                identity=identity,
            )

            # Connect and wait for handshake
            client.connect(site_id="test-site")
            client.wait_for_handshake(timeout=10)

            # Verify client handshake completed
            assert client.handshake_event.is_set(), "Handshake not complete"
            assert client.crypto_key is not None, "No crypto key negotiated"

            # Verify master registered the client
            assert len(m.connected_peers()) == 1, "Client not registered at master"

            client.close()
        finally:
            b.stop_all()

    def test_client_crypto_key_set_after_handshake(self):
        """HiveMessageBusClient has crypto_key after handshake."""
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

            # Verify crypto key is set
            assert isinstance(client.crypto_key, str), "crypto_key should be a string"
            assert len(client.crypto_key) > 0, "crypto_key should not be empty"

            client.close()
        finally:
            b.stop_all()
