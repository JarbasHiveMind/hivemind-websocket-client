# Identity & Credentials

A HiveMind node has **one identity**: one keypair and one Noise static key,
used in both directions — serving its own clients and dialling its master.
The identity is persisted in:

```
~/.config/hivemind/_identity.json
```

Credentials (`access_key`, `password`), `useragent` and `site_id` are not
part of the identity. They say how to reach one particular master, and a
node that both serves clients and connects upstream has its own access key
and password as well as its master's. The client reads them from the
identity file only as a fallback, and never writes them back — see
[One identity, many masters](#one-identity-many-masters) below.

## Fields

| Field | Description |
|---|---|
| `name` | Human-readable node label (not required to be unique). Read as the client's `useragent` fallback |
| `access_key` | Access key issued by `hivemind-core add-client`. Read as a fallback when the client is not given one directly |
| `password` | Password used to derive the AES session key during handshake. Read as a fallback when the client is not given one directly |
| `default_master` | Default hub URL (e.g. `ws://192.168.1.10`) |
| `default_port` | Default hub port (e.g. `5678`) |
| `site_id` | Location identifier injected into every OVOS message context. Read as a fallback when the client is not given one directly |
| `public_key` | RSA public key for this node |
| `secret_key` | Path to the RSA private key PEM file |
| `trusted_keys` | Dict of alias → public key for trusted peers (see below) |

## One identity, many masters

A node's identity is its keypair. Credentials are not stored *in* the
identity in the sense of being owned by it — they are read from the
identity file as a fallback, and a client given its own `key`/`password`
(directly, or via `set-identity`) uses those instead.

`connect()` resolves credentials this way:

```python
self._access_key = self._access_key or self.identity.access_key
self._password   = self._password   or self.identity.password
self._site_id    = site_id or self._site_id or self.identity.site_id
```

Nothing here is ever written back to the identity file. That distinction
matters for a node that both serves its own downstream clients and connects
to a master above it: it has its own access key and password, and its
master's. Earlier, the client copied whatever credentials it was handed
onto `self.identity` and the first successful Noise handshake persisted
them (pinning a peer key writes the whole identity to disk) — so the node's
own access key, password, and name were silently overwritten by its
master's on first connect. Every downstream client of that node then failed
its own handshake with "invalid api key" against credentials the node no
longer had, and the node reported itself under the default useragent
instead of its own name.

## Trusted Keys

Peers whose public key is in `trusted_keys` are allowed to inject BUS
messages via PROPAGATE and INTERCOM.  Untrusted peers are silently dropped.

```python
from hivemind_bus_client.identity import NodeIdentity

identity = NodeIdentity()
identity.add_trusted_key("living-room-hub", "<RSA_PUBLIC_KEY>")
identity.save()

# Check trust
identity.is_trusted_key("<RSA_PUBLIC_KEY>")  # True
identity.get_trusted_alias("<RSA_PUBLIC_KEY>")  # "living-room-hub"

# Remove
identity.remove_trusted_key("living-room-hub")
identity.save()
```

Source: `NodeIdentity.trusted_keys`, `identity.py`

## Setting identity from the CLI

```bash
hivemind-client set-identity \
  --key  "42caf3d2405075fb9e7a4e1ff44e4c4f" \
  --password "5ae486f7f1c26bd4645bd052e4af3ea3" \
  --siteid "living-room"
```

This writes the values to `~/.config/hivemind/_identity.json`. You can also set `default_master` / `default_port` so you don't need to pass `--host` / `--port` on every invocation.

## Using NodeIdentity in Python

```python
from hivemind_bus_client.identity import NodeIdentity

identity = NodeIdentity()

# Read persisted values
print(identity.access_key)
print(identity.password)
print(identity.default_master)
print(identity.site_id)

# Override values programmatically
identity.access_key = "my-key"
identity.password   = "my-password"
identity.default_master = "ws://192.168.1.10"
identity.default_port   = 5678
identity.save()
```

## RSA key pair

NodeIdentity stores an RSA key pair used for the HiveMind handshake and `INTERCOM` (peer-to-peer encrypted) messages.

```python
identity.create_keys()  # generates and saves a new RSA key pair
print(identity.public_key)  # PEM-encoded public key string
print(identity.private_key) # path to the private key .pem file
```

Keys are auto-created on first use if they do not exist.

## Passing credentials directly (without identity file)

Credentials can be passed directly to the client constructor instead of relying on the identity file:

```python
from hivemind_bus_client.client import HiveMessageBusClient

client = HiveMessageBusClient(
    host="ws://192.168.1.10",
    port=5678,
    key="42caf3d2405075fb9e7a4e1ff44e4c4f",
    password="5ae486f7f1c26bd4645bd052e4af3ea3",
)
client.connect()
```

Both `key` and `password` are required. If either is missing and not present in the identity file, a `RuntimeError` is raised.

---
[← Binary Handlers](binary_handlers.md) · [Home](index.md) · [CLI Reference →](cli.md)
