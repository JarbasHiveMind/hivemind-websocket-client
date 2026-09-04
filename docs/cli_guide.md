
The `hivemind-client` command-line tool provides utility functions for managing your satellite identity and interacting with a Mind.
- **Source**: `hivemind_bus_client.scripts`

## Identity Management

Before connecting, you must set your client credentials. This is handled by `hivemind_bus_client.identity.NodeIdentity`.

```bash
hivemind-client set-identity --key "MY_ACCESS_KEY" --password "MY_PASSWORD"
```
- **Source**: `hivemind_bus_client.scripts.set_identity`
- **Storage**: `~/.config/hivemind/_identity.json` (managed by `NodeIdentity`).

## Terminal Interface

The `terminal` command launches a simple interactive CLI where you can type utterances and see the AI's response. It uses a specialized `HiveMessageBusClient` instance.

```bash
hivemind-client terminal --host "ws://192.168.1.10" --port 5678
```
- **Source**: `hivemind_bus_client.scripts.terminal`

## Sending One-Off Messages

You can use `send-mycroft` to inject a single `HiveMessageType.BUS` message into the HiveMind bus.

```bash
hivemind-client send-mycroft --msg "speak" --payload '{"utterance": "Hello from the CLI"}'
```
- **Source**: `hivemind_bus_client.scripts.send_mycroft`

## Propagation and Escalation

- **`escalate`**: Send a message to a Master Mind (from a Slave Mind). Uses `HiveMessageType.ESCALATE`.
- **`propagate`**: Flood a message to every peer, downstream and upstream alike. Uses `HiveMessageType.PROPAGATE`.

```bash
hivemind-client escalate --msg "recognizer_loop:utterance" --payload '{"utterances": ["help"]}'
```
- **Source**: `hivemind_bus_client.scripts.escalate` and `hivemind_bus_client.scripts.propagate`.

## Network Discovery: `ping`

The `ping` command sends a `PING` flood through the hive and collects responsive PINGs (same `flood_id`). After the
collection window closes it renders the reachable topology as an ASCII tree (or raw JSON).

```bash
hivemind-client ping
```

**Options:**

```bash
$ hivemind-client ping --help
Usage: hivemind-client ping [OPTIONS]

  Send a PING and display the reachable hive map.

Options:
  --key TEXT       HiveMind access key (default read from identity file)
  --password TEXT  HiveMind password (default read from identity file)
  --host TEXT      HiveMind host (default read from identity file)
  --port INTEGER   HiveMind port number (default: 5678)
  --siteid TEXT    location identifier (default read from identity file)
  --timeout FLOAT  Seconds to wait for responsive PINGs (default: 5.0)
  --json           Output raw JSON topology instead of ASCII tree
  --help           Show this message and exit.
```

**Example output (ASCII tree):**

```
[self] my-laptop::abc123
├── living-room-hub::def456   site=living-room  latency=12ms
│   ├── kitchen-speaker::ghi  site=kitchen      latency=34ms
│   └── bedroom-sat::jkl      site=bedroom      latency=28ms
└── garage-pi::mno012         site=garage       latency=67ms
```

`latency` is the receiver clock minus the sender clock, not a round trip. On nodes with
unsynchronized clocks it can read negative.

**Example output (JSON):**

```json
{
  "nodes": [
    { "peer": "living-room-hub::def456", "site_id": "living-room",
      "timestamp": 1741478412.034, "latency_ms": 12.0,
      "public_key": null, "lang": "en-us", "trusted": false },
    { "peer": "kitchen-speaker::ghi", "site_id": "kitchen",
      "timestamp": 1741478412.056, "latency_ms": 34.0,
      "public_key": null, "lang": "en-us", "trusted": false }
  ],
  "edges": [
    { "source": "my-laptop::abc123",       "target": "living-room-hub::def456" },
    { "source": "living-room-hub::def456", "target": "kitchen-speaker::ghi" }
  ]
}
```

> **Warning**: Any node, including masters, MAY choose not to respond to a PING. The map reflects only
> the nodes that replied within the timeout window. Nodes further up the chain may be configured
> to act as a discovery boundary and will simply not appear in the output.

- **Source**: `hivemind_bus_client.scripts.ping`
- **Backend**: `hivemind_bus_client.hive_map.HiveMapper`

---
[← CLI Reference](cli.md) · [Home](index.md) · [Examples →](examples.md)
