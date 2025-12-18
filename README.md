[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/JarbasHiveMind/hivemind-websocket-client)

# Hivemind Client

Python client library for [hivemind-core](https://github.com/JarbasHiveMind/HiveMind-core)

## Install

```bash
pip install hivemind_bus_client
```

## Usage

via [hivemind-http-protocol](https://github.com/JarbasHiveMind/hivemind-http-protocol)

```python
from hivemind_bus_client.http_client import HiveMindHTTPClient

# not passing key etc so it uses identity file
client = HiveMindHTTPClient(host="http://localhost", port=5679)
client.connect() # establish a secure end-to-end encrypted connection
```

via [hivemind-websocket-protocol](https://github.com/JarbasHiveMind/hivemind-websocket-protocol)
```python
from hivemind_bus_client.client import HiveMessageBusClient

# not passing key etc so it uses identity file
client = HiveMessageBusClient(host="ws://localhost", port=5678)
client.connect() # establish a secure end-to-end encrypted connection
```

### Example: Simple Chat

```python
import threading
from ovos_bus_client.message import Message
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.client import HiveMessageBusClient

# not passing key etc so it uses identity file
client = HiveMessageBusClient(host="ws://localhost", port=5678)
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
```

### Example: Remote TTS 

if server is running [hivemind-audio-binary-protocol](https://github.com/JarbasHiveMind/hivemind-audio-binary-protocol)

```python
from ovos_bus_client.message import Message
from hivemind_bus_client.client import BinaryDataCallbacks
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.http_client import HiveMindHTTPClient

# To handle binary data subclass BinaryDataCallbacks
class BinaryDataHandler(BinaryDataCallbacks):
    def handle_receive_tts(self, bin_data: bytes,
                           utterance: str,
                           lang: str,
                           file_name: str):
        # we can play it or save to file or whatever
        print(f"got {len(bin_data)} bytes of TTS audio")
        print(f"utterance: {utterance}", f"lang: {lang}", f"file_name: {file_name}")
        # got 33836 bytes of TTS audio
        # utterance: hello world lang: en-US file_name: 5eb63bbbe01eeed093cb22bb8f5acdc3.wav


# not passing key etc so it uses identity file
client = HiveMindHTTPClient(host="http://localhost", port=5679,
                            bin_callbacks=BinaryDataHandler())
client.connect()

# send HiveMessages as usual
client.emit(HiveMessage(HiveMessageType.BUS,
                        Message("speak:synth", {"utterance": "hello world"})))

```

## Cli Usage

```bash
$ hivemind-client --help
Usage: hivemind-client [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  escalate      escalate a single mycroft message
  propagate     propagate a single mycroft message
  send-mycroft  send a single mycroft message
  terminal      simple cli interface to inject utterances and print speech


$ hivemind-client set-identity --help
Usage: hivemind-client set-identity [OPTIONS]

  persist node identity / credentials

Options:
  --key TEXT       HiveMind access key
  --password TEXT  HiveMind password
  --siteid TEXT    location identifier for message.context
  --help           Show this message and exit.


$ hivemind-client terminal --help
Usage: hivemind-client terminal [OPTIONS]

  simple cli interface to inject utterances and print speech

Options:
  --key TEXT      HiveMind access key
  --host TEXT     HiveMind host
  --port INTEGER  HiveMind port number
  --help          Show this message and exit.


$ hivemind-client send-mycroft --help
Usage: hivemind-client send-mycroft [OPTIONS]

  send a single mycroft message

Options:
  --key TEXT      HiveMind access key
  --host TEXT     HiveMind host
  --port INTEGER  HiveMind port number
  --msg TEXT      ovos message type to inject
  --payload TEXT  ovos message json payload
  --help          Show this message and exit.


$ hivemind-client escalate --help
Usage: hivemind-client escalate [OPTIONS]

  escalate a single mycroft message

Options:
  --key TEXT      HiveMind access key
  --host TEXT     HiveMind host
  --port INTEGER  HiveMind port number
  --msg TEXT      ovos message type to inject
  --payload TEXT  ovos message json payload
  --help          Show this message and exit.


$ hivemind-client propagate --help
Usage: hivemind-client propagate [OPTIONS]

  propagate a single mycroft message

Options:
  --key TEXT      HiveMind access key
  --host TEXT     HiveMind host
  --port INTEGER  HiveMind port number
  --msg TEXT      ovos message type to inject
  --payload TEXT  ovos message json payload
  --help          Show this message and exit.

```
