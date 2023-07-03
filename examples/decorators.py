from time import sleep
from ovos_bus_client import Message
from hivemind_bus_client import HiveMessageBusClient, HiveMessage, \
    HiveMessageType
from hivemind_bus_client.decorators import on_payload, on_escalate, \
    on_shared_bus, on_ping, on_broadcast, on_propagate, on_mycroft_message

key = "super_secret_access_key"
crypto_key = "ivf1NQSkQNogWYyr"

bus = HiveMessageBusClient(key, crypto_key=crypto_key)

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
