"""
Unit tests for CRIT-3 in HiveMindSlaveProtocol.handle_intercom:

Before the fix, handle_intercom dispatched on message.msg_type (always INTERCOM)
instead of the inner message's type.  All dispatch branches were unreachable —
the decrypted inner message was silently dropped.

After the fix, dispatch is on inner.msg_type, so the inner message is delivered.
"""
import unittest
from unittest.mock import MagicMock, patch

from hivemind_bus_client.message import HiveMessage, HiveMessageType


class TestSlaveIntercomDispatchInnerType(unittest.TestCase):
    """handle_intercom dispatches on the inner message type after decryption."""

    def _make_slave_protocol(self):
        from hivemind_bus_client.protocol import HiveMindSlaveProtocol
        from hivemind_bus_client.client import HiveMessageBusClient
        from hivemind_bus_client.identity import NodeIdentity

        hm = MagicMock(spec=HiveMessageBusClient)
        identity = MagicMock(spec=NodeIdentity)
        identity.public_key = "my-pubkey"
        identity.private_key = "/tmp/nonexistent.pem"

        slave = HiveMindSlaveProtocol(hm=hm, identity=identity)

        # Bind a fake bus without connecting
        from ovos_utils.fakebus import FakeBus
        bus = FakeBus()
        slave.internal_protocol = MagicMock()
        slave.internal_protocol.node_id = "master-node"
        slave.internal_protocol.bus = bus
        slave.internal_protocol.hm_bus = hm

        return slave

    def test_intercom_wrapping_bus_calls_handle_bus(self):
        """INTERCOM(BUS) → handle_bus called with the inner BUS message."""
        from ovos_bus_client.message import Message as OVOSMessage

        slave = self._make_slave_protocol()
        handled = []
        slave.handle_bus = lambda msg: handled.append(msg)

        inner_bus = HiveMessage(HiveMessageType.BUS,
                                payload=OVOSMessage("test.event", {}, {}))
        intercom = HiveMessage(HiveMessageType.INTERCOM, payload=inner_bus)
        intercom._target_pubkey = None  # addressed to us (no target restriction)

        result = slave.handle_intercom(intercom)

        self.assertTrue(result)
        self.assertEqual(len(handled), 1)
        self.assertEqual(handled[0].msg_type, HiveMessageType.BUS)

    def test_intercom_wrapping_broadcast_calls_handle_broadcast(self):
        """INTERCOM(BROADCAST) → handle_broadcast called with the inner BROADCAST."""
        slave = self._make_slave_protocol()
        handled = []
        slave.handle_broadcast = lambda msg: handled.append(msg)

        inner_thirdprty = HiveMessage(HiveMessageType.THIRDPRTY, payload={"data": "x"})
        broadcast = HiveMessage(HiveMessageType.BROADCAST, payload=inner_thirdprty)
        intercom = HiveMessage(HiveMessageType.INTERCOM, payload=broadcast)
        intercom._target_pubkey = None

        result = slave.handle_intercom(intercom)

        self.assertTrue(result)
        self.assertEqual(len(handled), 1)
        self.assertEqual(handled[0].msg_type, HiveMessageType.BROADCAST)

    def test_intercom_unknown_inner_returns_false(self):
        """INTERCOM(THIRDPRTY) — inner type not in dispatch table → returns False."""
        slave = self._make_slave_protocol()

        inner = HiveMessage(HiveMessageType.THIRDPRTY, payload={"vendor": "x"})
        intercom = HiveMessage(HiveMessageType.INTERCOM, payload=inner)
        intercom._target_pubkey = None

        result = slave.handle_intercom(intercom)
        self.assertFalse(result)

    def test_intercom_wrong_pubkey_returns_false_without_dispatch(self):
        """INTERCOM targeting a different pubkey is not delivered."""
        slave = self._make_slave_protocol()
        slave.identity.public_key = "my-real-key"

        handled = []
        slave.handle_bus = lambda msg: handled.append(msg)

        from ovos_bus_client.message import Message as OVOSMessage
        inner = HiveMessage(HiveMessageType.BUS,
                            payload=OVOSMessage("test", {}, {}))
        intercom = HiveMessage(HiveMessageType.INTERCOM, payload=inner,
                               target_pubkey="someone-else")

        result = slave.handle_intercom(intercom)

        self.assertFalse(result)
        self.assertEqual(len(handled), 0)


if __name__ == "__main__":
    unittest.main()
