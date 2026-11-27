from time import sleep
from ovos_bus_client import Message
from hivemind_bus_client import HiveMessageBusClient, HiveMessage, \
    HiveMessageType
from hivemind_bus_client.decorators import on_payload, on_escalate, \
    on_shared_bus, on_ping, on_broadcast, on_propagate, on_mycroft_message

# Before this runs, the hub must grant this client the message types it sends:
#   hivemind-core allow-msg "recognizer_loop:utterance" <node_id>
#   hivemind-core allow-msg "speak" <node_id>
# A new client has an empty whitelist and the hub denies everything it sends.

# the access key travels down the wire as an access token
key = "super_secret_access_key"
# the password derives the session key during the handshake
password = "super_secret_password"

bus = HiveMessageBusClient(key, password=password)

bus.run_in_thread()


@on_mycroft_message(payload_type="speak", bus=bus)
def on_speak(msg):
    print(msg.data["utterance"])


mycroft_msg = Message("recognizer_loop:utterance",
                      {"utterances": ["tell me a joke"]})
bus.emit_mycroft(mycroft_msg)


sleep(50)

bus.close()
sleep(5)
