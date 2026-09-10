from hivemind_bus_client import HiveMessageBusClient, HiveMessage, \
    HiveMessageType
from hivemind_bus_client.decorators import on_hive_message
from ovos_bus_client import Message
from time import sleep

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


@on_hive_message(HiveMessageType.BUS, bus=bus)
def printbusmsg(msg):
    print(msg.msg_type, msg.payload)


# special catch all - receives serialized messages (dict)
def printmsg(msg):
    print(msg)  # dict


bus.on("message", printmsg)

sleep(3)

mycroft_msg = Message("recognizer_loop:utterance",
                      {"utterances": ["tell me a joke"]})
bus.emit_mycroft(mycroft_msg)

sleep(50)

bus.close()
sleep(5)
