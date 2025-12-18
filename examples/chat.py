import threading
from ovos_bus_client.message import Message
from ovos_utils.log import LOG
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.client import HiveMessageBusClient

LOG.set_level("DEBUG")
# not passing args so it uses identity file
client = HiveMessageBusClient()
client.connect() # establish a secure end-to-end encrypted connection

# to handle agent responses, use client.on_mycroft("event", handler)
answered = threading.Event()

def handle_speak(message: Message):
    print(message.data['utterance'])

def utt_handled(message: Message):
    answered.set()

client.on_mycroft("speak", handle_speak)
client.on_mycroft("ovos.utterance.handled", utt_handled)


while True:
    utt = input("> ")
    answered.clear()
    client.emit(HiveMessage(HiveMessageType.BUS,
                            Message("recognizer_loop:utterance", {"utterances": [utt]})))
    answered.wait()