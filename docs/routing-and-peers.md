# Routing and peers
<!-- agent-hint
covers: peer-to-peer INTERCOM, the trusted keys, QUERY first-match requests, CASCADE collection with cascade_select_callback, and the PING map with HiveMapper and NodeInfo
source: hivemind_bus_client/client.py:emit_intercom, hivemind_bus_client/protocol.py:handle_intercom, hivemind_bus_client/protocol.py:handle_query, hivemind_bus_client/protocol.py:handle_cascade, hivemind_bus_client/protocol.py:CascadeAggregator, hivemind_bus_client/identity.py:add_trusted_key, hivemind_bus_client/hive_map.py
generated: no
verify: python -c "from hivemind_bus_client.protocol import HiveMindSlaveProtocol as P; f=P.__dataclass_fields__; assert (f['cascade_timeout'].default, f['query_timeout'].default, f['cascade_select_callback'].default) == (5.0, 30.0, None); from hivemind_bus_client.hive_map import NodeInfo; assert list(NodeInfo.__dataclass_fields__) == ['peer','site_id','timestamp','received_at','public_key','lang','trusted']; from hivemind_bus_client.identity import NodeIdentity as N; assert all(hasattr(N, a) for a in ('add_trusted_key','remove_trusted_key','is_trusted_key','get_trusted_alias'))"
see: messages.md
-->

A node can send a message to one peer, ask the hive a question, collect answers from many nodes, and map the nodes that it can reach. This page shows each of these operations against a local hub.

## Before you start

Do steps 1 to 7 of [Install and connect](install-and-connect.md#steps). The responder of step 7 must run. Then register a second client, `docs-peer`, and store its identity:

```bash
hivemind-core add-client --name docs-peer --access-key docs-peer-key-0123 \
    --password "correct-horse-battery-staple-docs-peer" \
    --allow speak --allow recognizer_loop:utterance
hivemind-client --app docs-peer set-identity --key docs-peer-key-0123 \
    --password "correct-horse-battery-staple-docs-peer" \
    --host 127.0.0.1 --port 15678 --siteid peer
```

`set-identity` also makes the RSA key pair of the node. INTERCOM and the PING map use this key.

## INTERCOM

INTERCOM sends one message to one peer, end to end. `emit_intercom(message, pubkey)` encrypts the message with a random AES-256 key, encrypts that key with the RSA public key of the receiver, and signs the ciphertext with the private key of the sender. The client sends the result inside a `PROPAGATE`, so every node forwards it. Only the receiver can decrypt it.

The receiver delivers the message to its bus only when the signature verifies against a key in its `trusted_keys`, or against the key of the hub that it is connected to. The example trusts the sender, sends one message, removes the trust and sends again:

```python
import time

from ovos_bus_client.message import Message
from ovos_utils.fakebus import FakeBus
from ovos_utils.log import LOG
from hivemind_bus_client import HiveMessageBusClient
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType

LOG.set_level("ERROR")

sat_id = NodeIdentity(app_name="docs-sat")
peer_id = NodeIdentity(app_name="docs-peer")

# the receiver accepts INTERCOM only from a key it trusts
peer_id.add_trusted_key("docs-sat", sat_id.public_key)
print("trusted:", peer_id.is_trusted_key(sat_id.public_key),
      peer_id.get_trusted_alias(sat_id.public_key))

peer_bus = FakeBus()
peer_bus.on("speak", lambda m: print("peer got:", m.data["utterance"]))

peer = HiveMessageBusClient(identity=peer_id)
peer.connect(bus=peer_bus, handshake_max_retries=3)
sat = HiveMessageBusClient(identity=sat_id)
sat.connect(handshake_max_retries=3)

secret = HiveMessage(HiveMessageType.BUS, Message("speak", {"utterance": "for your eyes only"}))
sat.emit_intercom(secret, peer_id.public_key)
time.sleep(2)

print("removed:", peer_id.remove_trusted_key("docs-sat"))
sat.emit_intercom(secret, peer_id.public_key)
time.sleep(2)
print("done")

sat.close()
peer.close()
```

```text
trusted: True docs-sat
peer got: for your eyes only
removed: True
done
```

The second message does not arrive: the receiver logs `dropping INTERCOM whose signature matches no trusted key` and drops it.

## Trusted keys

`NodeIdentity` keeps the trusted peers as a map from an alias to a public key:

| Call | Result |
| :--- | :--- |
| `add_trusted_key(alias, pubkey)` | `True`, or `False` when the alias is already in the map |
| `remove_trusted_key(alias)` | `True`, or `False` when the alias is not in the map |
| `is_trusted_key(pubkey)` | `True` when the key is in the map |
| `get_trusted_alias(pubkey)` | The alias of the key, or `None` |
| `trusted_keys` | The full map. Set it to replace the map |

These calls change the identity in memory only. Call `identity.save()` to write the map to `_identity.json`. The trusted keys control which INTERCOM messages, and which `PROPAGATE` messages with a `BUS` payload, reach the bus of the node.

## QUERY

A `QUERY` asks the hive one question and takes the first node that answers. The hub gives the utterance to its agent. When the agent answers, the hub sends each answer chunk back as a `QUERY` response, then a `QUERY` that holds `hive.query.complete`. When the agent has no answer, the hub sends the `QUERY` to its own master. A hub with no master answers `hive.query.timeout`.

```python
from ovos_bus_client.message import Message
from ovos_utils.fakebus import FakeBus
from ovos_utils.log import LOG
from hivemind_bus_client import HiveMessageBusClient
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType

LOG.set_level("ERROR")

bus = FakeBus()
bus.on("speak", lambda m: print("bus speak:", m.data["utterance"]))

client = HiveMessageBusClient(identity=NodeIdentity(app_name="docs-sat"))
client.connect(bus=bus, handshake_max_retries=3)

query = HiveMessage(HiveMessageType.QUERY,
                    HiveMessage(HiveMessageType.BUS,
                                Message("recognizer_loop:utterance",
                                        {"utterances": ["what time is it"]})))
answer = client.wait_for_response(query, reply_type=HiveMessageType.QUERY, timeout=10)
print(answer.msg_type, answer.payload.payload.msg_type, answer.payload.payload.data["utterance"])
print(sorted(answer.metadata))
client.close()
```

```text
bus speak: you said what time is it
query speak you said what time is it
['is_response', 'originator_peer', 'query_id', 'responder_peer']
```

The client also puts each answer chunk on the bus that you give to `connect(bus=...)`. The sync `emit()` of a `QUERY` starts a timer of `client.protocol.query_timeout` seconds (default 30). Each answer chunk starts the timer again, and `hive.query.complete` stops it. When the timer runs out, the client puts `hive.query.timeout` with `"error": "no_answer"` on its bus. Set `query_timeout` to `0` to wait with no limit.

## CASCADE

A `CASCADE` asks the hive one question and collects the answers of all the nodes that answer. The client keeps the answers for `client.protocol.cascade_timeout` seconds (default 5) after the first one. Then it gives the list to `client.protocol.cascade_select_callback`, and puts the answer that the callback returns on its bus. The client stops to wait before the timeout when the number of answers is equal to the number of nodes in `client.protocol.hive_mapper`. With an empty map, the first answer stops the wait. Without a callback, the client picks one answer at random. When the callback returns `None`, nothing goes on the bus.

```python
import time

from ovos_bus_client.message import Message
from ovos_utils.fakebus import FakeBus
from ovos_utils.log import LOG
from hivemind_bus_client import HiveMessageBusClient
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType

LOG.set_level("ERROR")


def pick_longest(responses):
    print("responses:", len(responses))
    return max(responses, key=lambda r: len(r.payload.payload.data["utterance"]))


bus = FakeBus()
bus.on("speak", lambda m: print("selected:", m.data["utterance"]))

client = HiveMessageBusClient(identity=NodeIdentity(app_name="docs-sat"))
client.connect(bus=bus, handshake_max_retries=3)
client.protocol.cascade_select_callback = pick_longest
client.protocol.cascade_timeout = 2

client.emit(HiveMessage(HiveMessageType.CASCADE,
                        HiveMessage(HiveMessageType.BUS,
                                    Message("recognizer_loop:utterance",
                                            {"utterances": ["tell me a joke"]}))))
time.sleep(4)
client.close()
```

```text
responses: 1
selected: you said tell me a joke
```

The demo hub is the only node with an agent, so the list holds one answer. Each element of the list is a `CASCADE` `HiveMessage` whose `payload` is the `BUS` answer. The `hive.query.complete` message of each node is not in the list.

## The hive map

A `PING` inside a `PROPAGATE` travels to every node. Each node answers with its own `PING` that has the same `flood_id`. `HiveMapper` collects these answers into `NodeInfo` records. `hivemind-client ping` does this from the command line ([CLI reference](cli.md#ping)). The same in Python:

```python
import time
import uuid

from ovos_utils.log import LOG
from hivemind_bus_client import HiveMessageBusClient
from hivemind_bus_client.hive_map import HiveMapper
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType

LOG.set_level("ERROR")

peer = HiveMessageBusClient(identity=NodeIdentity(app_name="docs-peer"))
peer.connect(handshake_max_retries=3)
sat = HiveMessageBusClient(identity=NodeIdentity(app_name="docs-sat"))
sat.connect(handshake_max_retries=3)

mapper = HiveMapper()
flood_id = str(uuid.uuid4())
mapper.start_ping(flood_id)


def on_propagate(outer):
    inner = outer.payload
    if inner.msg_type == HiveMessageType.PING and inner.payload.get("flood_id") == flood_id:
        inner.replace_route(outer.route)
        mapper.on_ping(inner, received_at=time.time())


sat.on(HiveMessageType.PROPAGATE, on_propagate)
sat.emit(HiveMessage(HiveMessageType.PROPAGATE,
                     HiveMessage(HiveMessageType.PING,
                                 {"flood_id": flood_id, "timestamp": time.time(),
                                  "peer": "docs-sat", "site_id": "sat"})))
time.sleep(3)

mapper.mark_trusted_nodes({"docs-peer": NodeIdentity(app_name="docs-peer").public_key})
for info in sorted(mapper.nodes.values(), key=lambda n: n.site_id or ""):
    print(info.site_id or "(no site)", "trusted" if info.trusted else "untrusted")

sat.close()
peer.close()
```

```text
(no site) untrusted
peer trusted
```

`NodeInfo` has these fields:

| Field | Content |
| :--- | :--- |
| `peer` | The label of the node. A hub uses its public key, a satellite uses `<name>::<session_id>` |
| `site_id` | The site that the node announced, or `None`. A hub that has no site in its identity file announces none |
| `timestamp` | The clock of the node when it sent the `PING` |
| `received_at` | The local clock when the `PING` arrived |
| `public_key` | The RSA public key of the node |
| `lang` | The language that the node announced |
| `trusted` | `True` after `mark_trusted_nodes()` finds `public_key` in the given map |

`latency_ms` is `received_at` minus `timestamp`, in milliseconds. It compares two different clocks, so it can be wrong or negative. `mapper.to_ascii()` draws the map as a tree, and `mapper.to_json()` gives it as JSON.

---
[← Messages](messages.md) · [Home](index.md) · [Wire format →](wire-format.md)
