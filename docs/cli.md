# CLI Reference

The `hivemind-client` command provides utilities for managing identity and sending test messages.

```
hivemind-client [COMMAND] [OPTIONS]
```

---

## `set-identity`

Persist node credentials to the identity file (`~/.config/hivemind/_identity.json`).

```bash
hivemind-client set-identity [OPTIONS]
```

| Option | Description |
|---|---|
| `--key TEXT` | HiveMind access key |
| `--password TEXT` | HiveMind password |
| `--host TEXT` | Default hub URL, `ws://` or `wss://` |
| `--port INTEGER` | Default hub port |
| `--siteid TEXT` | Location identifier injected into `message.context` |

**Example:**

```bash
hivemind-client set-identity \
  --key "42caf3d2405075fb9e7a4e1ff44e4c4f" \
  --password "5ae486f7f1c26bd4645bd052e4af3ea3" \
  --siteid "living-room"
```

---

## `terminal`

Interactive text terminal. Type utterances and see spoken responses.

```bash
hivemind-client terminal [OPTIONS]
```

| Option | Description |
|---|---|
| `--key TEXT` | HiveMind access key (overrides identity file) |
| `--password TEXT` | HiveMind password (overrides identity file) |
| `--host TEXT` | HiveMind host URL |
| `--port INTEGER` | HiveMind port (default 5678) |
| `--siteid TEXT` | Location identifier (overrides identity file) |

**Example:**

```bash
hivemind-client terminal --host ws://192.168.1.10 --port 5678
> what time is it
It is 3:45 PM.
```

---

## `send-mycroft`

Send a single OVOS/Mycroft bus message to the hub.

```bash
hivemind-client send-mycroft [OPTIONS]
```

| Option | Description |
|---|---|
| `--key TEXT` | HiveMind access key |
| `--password TEXT` | HiveMind password |
| `--host TEXT` | HiveMind host |
| `--port INTEGER` | HiveMind port (default 5678) |
| `--siteid TEXT` | Location identifier |
| `--msg TEXT` | OVOS message type to inject |
| `--payload TEXT` | OVOS message data as a JSON string |

The hub must have the message type in this client's whitelist. If it does not, the hub
answers `hive.policy.denied`. Grant it with `hivemind-core allow-msg <msg_type> <node_id>`.

**Example:**

```bash
hivemind-client send-mycroft \
  --msg "recognizer_loop:utterance" \
  --payload '{"utterances": ["turn off the lights"]}'
```

---

## `escalate`

Send a single OVOS message wrapped in a `HiveMessageType.ESCALATE` envelope. The message is forwarded upstream through the hub hierarchy. It takes the same options as `send-mycroft`.

```bash
hivemind-client escalate [OPTIONS]
```

---

## `propagate`

Send a single OVOS message wrapped in a `HiveMessageType.PROPAGATE` envelope. The message is forwarded to all peers and upstream hubs. It takes the same options as `send-mycroft`.

```bash
hivemind-client propagate [OPTIONS]
```

---

## `ping`

Send a PING flood and print the reachable hive topology as an ASCII tree.

```bash
hivemind-client ping [OPTIONS]
```

| Option | Description |
|---|---|
| `--key TEXT` | HiveMind access key |
| `--password TEXT` | HiveMind password |
| `--host TEXT` | HiveMind host |
| `--port INTEGER` | HiveMind port (default 5678) |
| `--siteid TEXT` | Location identifier |
| `--timeout FLOAT` | Seconds to collect answering PINGs (default 5.0) |
| `--json` | Print the raw JSON topology instead of the tree |

See the [CLI Guide](cli_guide.md) for sample output.

---

## `test-identity`

Open a connection with the saved identity and report whether the handshake completes.

```bash
hivemind-client test-identity
```

---

## `reset-pgp`

Generate a new RSA key pair for this node. Peers that trust the old public key must be
updated.

```bash
hivemind-client reset-pgp
```

---
[← Identity & Credentials](identity.md) · [Home](index.md) · [CLI Guide →](cli_guide.md)

