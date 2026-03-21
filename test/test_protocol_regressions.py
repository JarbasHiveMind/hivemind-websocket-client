"""
Regression tests for bugs fixed in hivemind_bus_client.protocol.HiveMindSlaveProtocol.
"""
import unittest
from unittest.mock import MagicMock, patch

from hivemind_bus_client.message import HiveMessage, HiveMessageType


class TestHandleBroadcastIntercomRecursion(unittest.TestCase):
    """Regression: handle_broadcast passed the outer BROADCAST message to handle_intercom
    instead of the inner INTERCOM payload. When target_public_key was not set, handle_intercom
    would see msg_type=BROADCAST and call handle_broadcast again → infinite recursion.
    Fix: pass message.payload (the inner INTERCOM) to handle_intercom, not the outer message."""

    def _make_slave_protocol(self):
        from hivemind_bus_client.protocol import HiveMindSlaveProtocol
        from hivemind_bus_client.identity import NodeIdentity

        hm = MagicMock()
        identity = MagicMock(spec=NodeIdentity)
        identity.public_key = "test-pubkey"
        identity.private_key = None

        slave = HiveMindSlaveProtocol(hm=hm, identity=identity, site_id="test-site")
        slave.internal_protocol = MagicMock()
        slave.internal_protocol.bus = MagicMock()
        slave.internal_protocol.node_id = "test-node"
        return slave

    def test_broadcast_wrapping_intercom_does_not_recurse(self):
        """Regression: handle_broadcast(BROADCAST(INTERCOM)) must not call itself recursively."""
        slave = self._make_slave_protocol()

        inner_intercom = HiveMessage(HiveMessageType.INTERCOM,
                                     payload={"data": "test"})
        broadcast = HiveMessage(HiveMessageType.BROADCAST, payload=inner_intercom)

        # Should not raise RecursionError
        try:
            slave.handle_broadcast(broadcast)
        except RecursionError:
            self.fail("handle_broadcast caused infinite recursion when wrapping INTERCOM payload")

    def test_propagate_wrapping_intercom_does_not_recurse(self):
        """Regression: handle_propagate(PROPAGATE(INTERCOM)) must not call itself recursively."""
        slave = self._make_slave_protocol()

        inner_intercom = HiveMessage(HiveMessageType.INTERCOM,
                                     payload={"data": "test"})
        propagate = HiveMessage(HiveMessageType.PROPAGATE, payload=inner_intercom)

        # Should not raise RecursionError
        try:
            slave.handle_propagate(propagate)
        except RecursionError:
            self.fail("handle_propagate caused infinite recursion when wrapping INTERCOM payload")

    def test_handle_intercom_receives_intercom_message(self):
        """handle_intercom must be called with the inner INTERCOM, not the outer wrapper.
        Verified by ensuring that handle_intercom is called with msg_type=INTERCOM."""
        slave = self._make_slave_protocol()

        received = []
        orig_handle_intercom = slave.handle_intercom
        slave.handle_intercom = lambda msg: received.append(msg.msg_type) or False

        inner_intercom = HiveMessage(HiveMessageType.INTERCOM,
                                     payload={"data": "test"})
        broadcast = HiveMessage(HiveMessageType.BROADCAST, payload=inner_intercom)

        slave.handle_broadcast(broadcast)

        self.assertEqual(len(received), 1,
                         "handle_intercom must be called exactly once")
        self.assertEqual(received[0], HiveMessageType.INTERCOM,
                         "handle_intercom must receive the inner INTERCOM message, "
                         f"not the outer wrapper (got {received[0]!r})")


if __name__ == "__main__":
    unittest.main()
