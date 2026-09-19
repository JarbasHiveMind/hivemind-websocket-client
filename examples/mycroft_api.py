from hivemind_bus_client import HiveMessageBusClient, HiveMessage, \
    HiveMessageType
from ovos_bus_client import Message

# Before this runs, the hub must grant this client the message types it sends:
#   hivemind-core allow-msg "recognizer_loop:utterance" <node_id>
#   hivemind-core allow-msg "speak" <node_id>
# A new client has an empty whitelist and the hub denies everything it sends.

# these are never equal! the access key travels down the wire as an access token
key = "super_secret_access_key"
# the password derives the session key during the handshake
password = "super_secret_password"

bus = HiveMessageBusClient(key, password=password)
bus.run_in_thread()

# simulate a user utterance
# - tell the hivemind this is for mycroft - HiveMessageType.BUS
# - payload is a regular mycroft Message
# - you need to provide message.context for proper routing
print("User:", "tell me a joke")
mycroft_msg = Message("recognizer_loop:utterance",
                      {"utterances": ["tell me a joke"]})
msg = HiveMessage(HiveMessageType.BUS, mycroft_msg)


# wait for a specific payload
# - mycroft bus Message
# - Message.msg_type == "speak"
response = bus.wait_for_payload_response(message=msg,
                                         reply_type=HiveMessageType.BUS,
                                         payload_type="speak",
                                         timeout=20)
if response:
    print("Mycroft:", response.payload.data["utterance"])
else:
    print("[NO RESPONSE] timed out....")

bus.close()
