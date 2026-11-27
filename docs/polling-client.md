# HTTP client
<!-- agent-hint
covers: HiveMindHTTPClient, the client for a hub that runs the HTTP network protocol
source: hivemind_bus_client/http_client.py:HiveMindHTTPClient
generated: no
verify: python -c "import hivemind_bus_client.http_client as h, inspect; assert (h.HTTP_TIMEOUT, h.DEFAULT_HANDSHAKE_MAX_RETRIES) == (30, 5); assert inspect.signature(h.HiveMindHTTPClient).parameters['useragent'].default == 'HiveMindHTTPClientV1.0'"
see: troubleshooting.md
-->

`HiveMindHTTPClient` talks to a hub over HTTP requests in place of a WebSocket. Use it where a WebSocket cannot stay open. It runs the same handshake and the same Noise session as the WebSocket client.

## Example

The hub runs the `hivemind-http-plugin` network protocol on port 15679. The identity and the responder are the ones from [Install and connect](install-and-connect.md).

```python
import threading

from ovos_bus_client.message import Message
from ovos_utils.log import LOG
from hivemind_bus_client.http_client import HiveMindHTTPClient
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType

LOG.set_level("ERROR")

answered = threading.Event()
client = HiveMindHTTPClient(host="http://127.0.0.1", port=15679,
                            identity=NodeIdentity(app_name="docs-sat"))
client.on_mycroft("speak", lambda m: (print("speak", m.data), answered.set()))
client.connect()
client.emit(HiveMessage(HiveMessageType.BUS,
                        Message("recognizer_loop:utterance",
                                {"utterances": ["hello over http"]})))
answered.wait(10)
client.disconnect()
client.shutdown()
```

```text
speak {'utterance': 'you said hello over http'}
```

## Steps

1. On the hub, install the HTTP protocol and enable it next to the WebSocket protocol:

   ```bash
   uv pip install --prerelease=allow hivemind-http-protocol
   ```

   In `server.json`, add `"hivemind-http-plugin": {"host": "127.0.0.1", "port": 15679}` under `network_protocol`, then restart `hivemind-core listen`.

2. Build the client with `host` and `port`. The constructor starts a polling thread at once.
3. Call `connect()`. It posts to `/connect` and waits for the handshake. An HTTP error or an `error` field in the answer raises `ConnectionRefusedError`.
4. Send with `emit()`, and listen with `on()` and `on_mycroft()`.
5. Call `disconnect()` to end the session, and `shutdown()` to stop the polling thread. A thread that `shutdown()` stopped does not start again, so build a new client after it.

## How it works

The polling thread waits for a live session. Then, once a second, it gets `/get_messages` and `/get_binary_messages` and dispatches each message. A server error ends the session. A network error leaves the session in place, and the next poll tries again.

Each request carries `authorization=base64(useragent:key)` as a query parameter. The host accepts `ws://`, `wss://`, `http://` or `https://`. The client changes `ws://` to `http://` and `wss://` to `https://`.

## Reference

| Argument | Default | Effect |
| :--- | :--- | :--- |
| `key`, `password`, `host`, `port` | `None` | Credentials. Each falls back to the identity. |
| `identity` | `None` | A `NodeIdentity`. Without it the client uses the shared file and logs a warning. |
| `useragent` | `"HiveMindHTTPClientV1.0"` | Name sent with the access key |
| `http_timeout` | `30` (`HTTP_TIMEOUT`) | Seconds for each HTTP request |
| `max_protocol_version` | `3` | Set `2` to force the legacy handshake |
| `compress`, `binarize`, `share_bus`, `internal_bus`, `bin_callbacks` | as the WebSocket client | See [Install and connect](install-and-connect.md#reference) |

`connect(bus=None, protocol=None, site_id=None, handshake_max_retries=5)` raises `ConnectionRefusedError` after 5 handshake retries by default, where the WebSocket client retries forever.

| Endpoint | Method | Use |
| :--- | :--- | :--- |
| `/connect` | POST | Opens a session |
| `/disconnect` | POST | Ends the session |
| `/send_message` | POST | Sends one frame in the `message` form field. A Noise frame is base64, with `binary=1`. |
| `/get_messages` | GET | Text frames waiting for this client |
| `/get_binary_messages` | GET | Binary frames, base64 in `b64_messages` |

---
[← Security](security.md) · [Home](index.md) · [Troubleshooting →](troubleshooting.md)
