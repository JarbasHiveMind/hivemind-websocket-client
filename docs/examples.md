# Examples

All examples assume credentials have been set up via `hivemind-client set-identity` or are passed directly to the constructor.

---

## Simple chat (WebSocket)

Send utterances and print the spoken responses.

```python
import threading
from ovos_bus_client.message import Message
from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.message import HiveMessage, HiveMessageType

client = HiveMessageBusClient(host="ws://192.168.1.10", port=5678)
client.connect()

answered = threading.Event()

def handle_speak(message: Message):
    print(">>>", message.data["utterance"])

def handle_done(message: Message):
    answered.set()

client.on_mycroft("speak", handle_speak)
client.on_mycroft("ovos.utterance.handled", handle_done)

while True:
    utt = input("> ")
    answered.clear()
    client.emit(HiveMessage(HiveMessageType.BUS,
                            Message("recognizer_loop:utterance", {"utterances": [utt]})))
    answered.wait()
```

---

## Simple chat (HTTP)

Identical API, different transport.

```python
from hivemind_bus_client.http_client import HiveMindHTTPClient

client = HiveMindHTTPClient(host="http://192.168.1.10", port=5679)
client.connect()

# same emit / on_mycroft API applies
```

---

## Remote TTS (receive synthesised audio)

If the hub is running `hivemind-audio-binary-protocol`, you can request TTS and receive the WAV audio as bytes.

```python
from ovos_bus_client.message import Message
from hivemind_bus_client.client import BinaryDataCallbacks, HiveMessageBusClient
from hivemind_bus_client.message import HiveMessage, HiveMessageType

class TTSHandler(BinaryDataCallbacks):
    def handle_receive_tts(self, bin_data: bytes, utterance: str, lang: str, file_name: str):
        print(f"TTS for '{utterance}' ({lang}): {len(bin_data)} bytes → {file_name}")
        with open(file_name, "wb") as f:
            f.write(bin_data)

client = HiveMessageBusClient(
    host="ws://192.168.1.10", port=5678,
    bin_callbacks=TTSHandler(),
)
client.connect()

client.emit(HiveMessage(HiveMessageType.BUS,
                        Message("speak:synth", {"utterance": "hello world"})))
```

---

## Send and wait for a response

```python
from ovos_bus_client.message import Message
from hivemind_bus_client.client import HiveMessageBusClient

client = HiveMessageBusClient(host="ws://192.168.1.10", port=5678)
client.connect()

response = client.wait_for_response(
    Message("recognizer_loop:utterance", {"utterances": ["what is the weather"]}),
    reply_type="speak",
    timeout=15,
)

if response:
    print(response.payload.data["utterance"])
else:
    print("No response within timeout")
```

---

## Peer-to-peer encrypted message (INTERCOM)

Send a message directly to another node using its RSA public key. The message is encrypted so only the target node can read it.

```python
from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from ovos_bus_client.message import Message

client = HiveMessageBusClient(host="ws://192.168.1.10", port=5678)
client.connect()

other_node_pubkey = "-----BEGIN PUBLIC KEY-----\n..."

client.emit_intercom(
    HiveMessage(HiveMessageType.BUS,
                Message("speak", {"utterance": "private message"})),
    pubkey=other_node_pubkey,
)
```

---

## Using NodeIdentity explicitly

```python
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.client import HiveMessageBusClient

identity = NodeIdentity()
identity.access_key     = "42caf3d2405075fb9e7a4e1ff44e4c4f"
identity.password       = "5ae486f7f1c26bd4645bd052e4af3ea3"
identity.default_master = "ws://192.168.1.10"
identity.default_port   = 5678
identity.save()

# Now the client picks up credentials from the identity file
client = HiveMessageBusClient()
client.connect()
```

---

## Broadcast to all connected satellites (admin only)

Requires the connecting client to have admin privileges (`hivemind-core make-admin`).

```python
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from ovos_bus_client.message import Message

announcement = HiveMessage(
    HiveMessageType.BROADCAST,
    payload=HiveMessage(HiveMessageType.BUS,
                        Message("speak", {"utterance": "System going offline in 5 minutes"}))
)
client.emit(announcement)
```
