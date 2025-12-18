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
    """
    Print the 'utterance' field from a Hive Message to standard output.
    
    Parameters:
    	message (Message): Hive bus message whose `data` mapping contains an `'utterance'` string to print.
    """
    print(message.data['utterance'])

def utt_handled(message: Message):
    """
    Signal that an utterance has been handled by setting the module-level `answered` event.
    
    Parameters:
        message (Message): Incoming message that triggered the handler; its contents are ignored by this function.
    """
    answered.set()

client.on_mycroft("speak", handle_speak)
client.on_mycroft("ovos.utterance.handled", utt_handled)


while True:
    utt = input("> ")
    answered.clear()
    client.emit(HiveMessage(HiveMessageType.BUS,
                            Message("recognizer_loop:utterance", {"utterances": [utt]})))
    answered.wait()