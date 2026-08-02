# Client API Guide

The `hivemind-websocket-client` library (package `hivemind-bus-client`) provides two primary classes for interacting with a HiveMind.

## 1. `HiveMessageBusClient`
Use this for real-time, bidirectional communication over WebSockets.
- **Source**: `hivemind_bus_client.client.HiveMessageBusClient`

### Basic Connection
The client handles the encrypted handshake (via `poorman_handshake`) and the session cipher (AES-GCM or ChaCha20-Poly1305, via `hivemind_bus_client.encryption`).

```python
from hivemind_bus_client.client import HiveMessageBusClient

# Uses identity from ~/.config/hivemind/_identity.json by default
client = HiveMessageBusClient(host="ws://192.168.1.10", port=5678)
client.connect() # Executes poorman_handshake.PasswordHandShake
```

### Handling AI Events
Listen for events using `on_mycroft` (inherited from `ovos_bus_client.client.MessageBusClient` but wrapped to handle encrypted HiveMessages).

```python
def handle_speak(message):
    print(f"AI says: {message.data['utterance']}")

client.on_mycroft("speak", handle_speak)
```

### Sending Utterances
To send a command, wrap an OVOS `Message` in a `HiveMessage` and use `emit`.

```python
from ovos_bus_client.message import Message
from hivemind_bus_client.message import HiveMessage, HiveMessageType

utt = "What time is it?"
msg = HiveMessage(HiveMessageType.BUS, 
                  Message("recognizer_loop:utterance", {"utterances": [utt]}))
client.emit(msg) # Encrypts and sends via the WebSocket
```

## 2. `HiveMindHTTPClient`
Use this for scenarios where a persistent WebSocket is not desired or possible.
- **Source**: `hivemind_bus_client.http_client.HiveMindHTTPClient`

```python
from hivemind_bus_client.http_client import HiveMindHTTPClient

client = HiveMindHTTPClient(host="http://192.168.1.10", port=5679)
client.connect() # Performs the encrypted handshake via HTTP POST
```

## 3. Decorators
`hivemind_bus_client.decorators` registers a function as a handler for one message type.
Each decorator takes the payload type and the bus.

```python
from hivemind_bus_client.decorators import on_mycroft_message

@on_mycroft_message("speak", bus=client)
def on_speak(msg):
    print(msg.data["utterance"])
```

See the [API Reference](api.md) for the full decorator list.

---
[← API Reference](api.md) · [Home](index.md) · [Async Client →](async_client.md)
