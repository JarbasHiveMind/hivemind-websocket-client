"""The slave's upstream doors build an OBJECT payload (HIVEMIND-MSG-1 §4).

``HiveMindSlaveInternalProtocol.handle_outgoing_mycroft`` built both of its
frames with ``payload=message.serialize()``, which is a STRING. Since the
constructor refuses a string payload, every SHARED_BUS forward and every
targeted upstream send raised ``MalformedWirePayload`` out of the internal
bus handler, so passive monitoring and the reply leg were both dead.

The fix passes the ``Message`` itself. The constructor already converts one
to ``{"type": .., "data": .., "context": ..}``, which is the object §4
requires and the shape the payload property reads back.
"""
import unittest

from ovos_bus_client.message import Message

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveInternalProtocol


class _RecordingHiveBus:
    def __init__(self):
        self.emitted = []

    def emit(self, message):
        self.emitted.append(message)


class TestOutgoingPayloadIsAnObject(unittest.TestCase):

    def _proto(self, share_bus):
        return HiveMindSlaveInternalProtocol(hm_bus=_RecordingHiveBus(),
                                             share_bus=share_bus,
                                             node_id="master:1")

    def test_shared_bus_forward_carries_an_object(self):
        proto = self._proto(share_bus=True)
        proto.handle_outgoing_mycroft(Message("speak",
                                              {"utterance": "hello"}))

        self.assertEqual(len(proto.hm_bus.emitted), 1)
        frame = proto.hm_bus.emitted[0]
        self.assertEqual(frame.msg_type, HiveMessageType.SHARED_BUS)
        self.assertIsInstance(frame.as_dict["payload"], dict)
        self.assertEqual(frame.as_dict["payload"]["type"], "speak")
        self.assertEqual(frame.as_dict["payload"]["data"],
                         {"utterance": "hello"})

    def test_the_forwarded_payload_reads_back_as_a_message(self):
        proto = self._proto(share_bus=True)
        proto.handle_outgoing_mycroft(Message("speak",
                                              {"utterance": "monitor me"}))

        payload = proto.hm_bus.emitted[0].payload
        self.assertIsInstance(payload, Message)
        self.assertEqual(payload.msg_type, "speak")
        self.assertEqual(payload.data, {"utterance": "monitor me"})

    def test_a_targeted_reply_carries_an_object(self):
        proto = self._proto(share_bus=False)
        proto.handle_outgoing_mycroft(
            Message("speak", {"utterance": "for the master"},
                    {"destination": ["master:1"]}))

        self.assertEqual(len(proto.hm_bus.emitted), 1)
        frame = proto.hm_bus.emitted[0]
        self.assertEqual(frame.msg_type, HiveMessageType.BUS)
        self.assertIsInstance(frame.as_dict["payload"], dict)
        self.assertEqual(frame.as_dict["payload"]["type"], "speak")

    def test_a_frame_for_nobody_else_is_still_not_emitted(self):
        """The control: share_bus off and no destination emits nothing, so
        the two tests above measure the doors and not the handler."""
        proto = self._proto(share_bus=False)
        proto.handle_outgoing_mycroft(Message("speak", {"utterance": "hi"}))
        self.assertEqual(proto.hm_bus.emitted, [])

    def test_a_string_payload_is_still_refused(self):
        """The guard the fix relies on stays in place."""
        with self.assertRaises(ValueError):
            HiveMessage(HiveMessageType.SHARED_BUS,
                        payload=Message("speak", {}).serialize())


if __name__ == "__main__":
    unittest.main()
