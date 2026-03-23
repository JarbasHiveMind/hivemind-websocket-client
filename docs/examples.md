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

## QUERY — first-match request-response

QUERY propagates upstream and returns the first answer.

```python
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.decorators import on_query
from ovos_bus_client.message import Message

# send a QUERY
inner = HiveMessage(HiveMessageType.BUS,
                    Message("intent.request", {"utterance": "what time is it"}))
client.emit(HiveMessage(HiveMessageType.QUERY, payload=inner))

# listen for the response
@on_query("speak", client)
def on_answer(msg):
    print("Answer:", msg.data["utterance"])
```

---

## CASCADE — collect responses from all nodes

CASCADE floods the network and collects all answers. The `CascadeAggregator` buffers them and calls `cascade_select_callback` to pick the best.

```python
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from ovos_bus_client.message import Message

inner = HiveMessage(HiveMessageType.BUS,
                    Message("skill.list.request", {}))
client.emit(HiveMessage(HiveMessageType.CASCADE, payload=inner))

# on the protocol side, configure disambiguation:
# proto.cascade_select_callback = lambda responses: best_of(responses)
# proto.hive_mapper = mapper  # enables early resolution
```

---

## Peer-to-peer encrypted message (INTERCOM)

Send a message directly to another node using its RSA public key. Uses hybrid encryption (AES-256-GCM payload + RSA-encrypted ephemeral key) so there is no payload size limit.

```python
other_node_pubkey = "-----BEGIN PUBLIC KEY-----\n..."

client.emit_intercom(
    HiveMessage(HiveMessageType.BUS,
                Message("speak", {"utterance": "private message"})),
    pubkey=other_node_pubkey,
)
```

---

## Managing trusted peers

Only messages from trusted peers are injected into the internal bus via PROPAGATE and INTERCOM.

```python
from hivemind_bus_client.identity import NodeIdentity

identity = NodeIdentity()

# add a trusted peer
identity.add_trusted_key("home-hub", "-----BEGIN PUBLIC KEY-----\n...")
identity.add_trusted_key("office-relay", "-----BEGIN PUBLIC KEY-----\n...")
identity.save()

# check trust
identity.is_trusted_key("-----BEGIN PUBLIC KEY-----\n...")  # True
identity.get_trusted_alias("-----BEGIN PUBLIC KEY-----\n...")  # "home-hub"

# remove
identity.remove_trusted_key("office-relay")
identity.save()
```

After PING discovery, mark discovered nodes as trusted:

```python
mapper.mark_trusted_nodes(identity.trusted_keys)
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

---

## Receiving INTERCOM messages via a rendezvous server

Nodes in other hives can deposit INTERCOM messages at a shared rendezvous server. Enable polling to receive them asynchronously — no simultaneous connection required.

```python
from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.message import HiveMessage, HiveMessageType

client = HiveMessageBusClient(
    key="my_access_key",
    password="my_password",
    host="ws://127.0.0.1",
    rendezvous_urls=["http://rendezvous.example.com"],
    rendezvous_poll_interval=30.0,
)
client.connect()

# handler fires for both live WebSocket INTERCOM and rendezvous-retrieved ones
client.on(HiveMessageType.INTERCOM, lambda msg: print("INTERCOM:", msg.payload))
```

## Depositing a message at a rendezvous server (sender side)

The sender uses `hivemind-rendezvous` client helpers directly (no WebSocket needed):

```python
import json, time, urllib.request
import base64
from poorman_handshake.asymmetric.utils import sign_RSA, load_RSA_key
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.identity import NodeIdentity

identity = NodeIdentity()
recipient_pubkey = "-----BEGIN PUBLIC KEY-----\n..."   # obtained e.g. via PING

# Build and encrypt an INTERCOM payload
from hivemind_bus_client.encryption import hybrid_encrypt
from ovos_bus_client.message import Message as MycroftMessage

private_key = load_RSA_key(identity.private_key)
inner = MycroftMessage("speak", {"utterance": "hello from the other side"})
envelope = hybrid_encrypt(recipient_pubkey, HiveMessage(HiveMessageType.BUS, inner).serialize(),
                          sign_key=private_key)
msg = HiveMessage(HiveMessageType.INTERCOM, payload=envelope)

body = json.dumps({
    "payload": msg.serialize(),
    "target_pubkey": recipient_pubkey,
}).encode()
req = urllib.request.Request(
    "http://rendezvous.example.com/deposit",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req) as resp:
    print(json.loads(resp.read()))   # {"status": "ok", "deposit_id": "..."}
```
