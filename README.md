# HiveMind Bus Client
<!-- agent-hint
covers: what the library does, how to install it, one round trip, and the links into docs/
source: pyproject.toml, hivemind_bus_client/client.py, hivemind_bus_client/scripts.py
generated: no
verify: diff <(ls docs/*.md | xargs -n1 basename | sort) <(grep -o '(docs/[a-z0-9-]*\.md)' README.md | sed 's|(docs/||;s|)||' | sort -u)
see: docs/index.md
-->

`hivemind-bus-client` connects a Python program to a [hivemind-core](https://github.com/JarbasHiveMind/HiveMind-core) hub. It extends the OVOS bus client with the HiveMind wire protocol: a Noise handshake, encrypted messages, and the HiveMind routing types. Every HiveMind satellite builds on it.

## Install

```bash
uv pip install --prerelease=allow "hivemind-bus-client[async]"
```

The `async` extra adds `websockets` for `AsyncHiveMessageBusClient`. The sync client needs no extra.

## Quickstart

On the hub, register the client. On the satellite, store the credentials under an application name, then send an utterance:

```bash
hivemind-core add-client --name docs-sat --access-key docs-key-0123 \
    --password "correct-horse-battery-staple-docs" --allow recognizer_loop:utterance
hivemind-client --app docs-sat set-identity --key docs-key-0123 \
    --password "correct-horse-battery-staple-docs" --host 127.0.0.1 --port 5678
```

```python
from ovos_bus_client.message import Message
from hivemind_bus_client import HiveMessageBusClient
from hivemind_bus_client.identity import NodeIdentity

client = HiveMessageBusClient(identity=NodeIdentity(app_name="docs-sat"))
client.connect(handshake_max_retries=3)
client.emit_mycroft(Message("recognizer_loop:utterance",
                            {"utterances": ["hello hive"]},
                            {"destination": "skills"}))
reply = client.wait_for_mycroft("speak", timeout=5)
print(reply.msg_type, reply.payload.msg_type, reply.payload.data)
client.close()
```

```text
bus speak {'utterance': 'you said hello hive'}
```

The answer comes from a test responder on the hub's OVOS bus. [Install and connect](docs/install-and-connect.md) shows the full setup.

## Documentation

| Page | What you get there |
| :--- | :--- |
| [Docs index](docs/index.md) | The reading order and the wire size of each encoding |
| [Install and connect](docs/install-and-connect.md) | A sync and an async round trip against a local hub |
| [Identity](docs/identity.md) | Where credentials and keys live, and the shared-file refusal |
| [CLI reference](docs/cli.md) | Every `hivemind-client` command and option |
| [Messages](docs/messages.md) | Message types, payload rules and serialization |
| [Security](docs/security.md) | Noise XXpsk2 and KKpsk0, key pinning and the PSK cache |
| [HTTP client](docs/polling-client.md) | `HiveMindHTTPClient` for hubs that serve HTTP |
| [Troubleshooting](docs/troubleshooting.md) | Each error message, its cause and the fix |
| [Contributing](docs/contributing.md) | Setup, tests and the rules for a change |

## License

Apache-2.0. See [LICENSE.md](LICENSE.md).
