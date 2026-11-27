# CLI reference
<!-- agent-hint
covers: every hivemind-client command, its options, and its real output
source: hivemind_bus_client/scripts.py, pyproject.toml:[project.scripts]
generated: no
verify: diff <(hivemind-client --help 2>/dev/null | sed -n '/^Commands:/,$p') <(awk '/^Commands:/{f=1} f&&/^```/{exit} f' docs/cli.md)
see: messages.md
-->

`hivemind-client` stores a node identity and sends single messages to a hub from the shell. This page lists each command with its options and the output of a real run.

## Example

```bash
hivemind-client --app docs-sat test-identity
```

```text
== Identity successfully connected to HiveMind!
```

## Steps

1. Choose the identity with a group option before the subcommand: `--app <name>` for the application's own file, or `--shared` for the shared file. With neither, the CLI reads an existing shared file and refuses to create one. [Identity](identity.md) explains the three cases.
2. Store the credentials once with `set-identity`.
3. Run the other commands. Each one reads the key, password, host, port and site from the identity. An option on the command line takes precedence over the identity.

## Group options

```text
Usage: hivemind-client [OPTIONS] COMMAND [ARGS]...

Options:
  --app TEXT  application name: use the identity in ~/.config/hivemind/<app>/
              instead of the shared ~/.config/hivemind/_identity.json
  --shared    use the shared ~/.config/hivemind/_identity.json, and create it
              if it does not exist. Sharing one identity across applications
              is a provisioning choice a deployer makes explicitly (HIVEMIND-
              CRYPTO-1 §2); without this flag and without --app, an existing
              shared file is read but a new one is never created
  --help      Show this message and exit.

Commands:
  escalate       escalate a single mycroft message
  forget-server  forget the pinned encryption key of a hivemind-core
  ping           Send a PING and display the reachable hive map.
  propagate      propagate a single mycroft message
  reset-pgp      recreate the private RSA key for inter-node communication
  send-mycroft   send a single mycroft message
  set-identity   persist node identity / credentials
  terminal       simple cli interface to inject utterances and print speech
  test-identity  test if Identity file can connect to HiveMind
```

When you give both `--app` and `--shared`, `--app` wins.

## set-identity

Writes the credentials to the identity file. It needs at least one option. The first run makes an RSA key pair and prints the public key.

| Option | Effect |
| :--- | :--- |
| `--key TEXT` | Access key |
| `--password TEXT` | Password. A changed password also clears the Noise PSK cache. |
| `--host TEXT` | Hub host. `ws://` is added when the scheme is missing. |
| `--port INTEGER` | Hub port. Without it, the stored port, then 5678. |
| `--siteid TEXT` | Site identifier |

```bash
hivemind-client --app docs-sat set-identity --key docs-key-0123 \
    --password "correct-horse-battery-staple-docs" \
    --host 127.0.0.1 --port 15678 --siteid kitchen
```

```text
PUBKEY: -----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
identity saved: /home/user/hm-demo/config/hivemind/docs-sat/_identity.json
```

With `--app`, the write always goes to the application's own file, also when the application reads the shared file as a fallback.

## test-identity

Connects with the stored identity and reports the result. `--timeout FLOAT` (default 30) bounds the wait. The command retries the handshake `max(1, timeout // 5)` times.

```text
== Identity successfully connected to HiveMind!
```

A refused access key exits with an error that names the fix:

```text
Error: HiveMind refused this identity: invalid api key
Check the access key and password with 'hivemind-client set-identity', and confirm the client is registered on the server with 'hivemind-core list-clients'.
```

[Troubleshooting](troubleshooting.md) lists the other failures.

## send-mycroft

Connects, sends one OVOS message in a `BUS` envelope, and disconnects. `--msg` is the message type and `--payload` is the `message.data` as JSON. Both are needed.

```bash
hivemind-client --app docs-sat send-mycroft --msg recognizer_loop:utterance \
    --payload '{"utterances": ["hi"]}'
```

```text
== connected to HiveMind
```

## escalate and propagate

Each sends one OVOS message, wrapped as `ESCALATE(BUS(message))` or `PROPAGATE(BUS(message))`. They take the same options as `send-mycroft`. `--siteid` sets `target_site_id` on the outer envelope. A node delivers the inner `BUS` message to its bus only when its site matches, so pass the site of the target. The hub must allow the client to send these types (`hivemind-core allow-escalate`, `hivemind-core allow-propagate`).

## ping

Sends a `PING` flood inside a `PROPAGATE` envelope, collects the answers for `--timeout` seconds (default 5), and prints the hive map. `--json` prints the map as JSON.

```bash
hivemind-client --app docs-sat ping --timeout 3
```

```text
== connected to HiveMind, sending PING (timeout=3.0s)
  PING from -----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----  site=hub

== Hive Map ==
[self] unnamed-node::fbb8b36d
└── key:3c5bff6b9445  site=hub  latency=0ms
```

## terminal

Opens an interactive prompt. Each line you type goes to the hub as `recognizer_loop:utterance`, and each `speak` answer prints with `> `. Press Ctrl+C to stop. It takes the connection options of `send-mycroft` without `--msg` and `--payload`.

## forget-server

Drops the pinned Noise key of a hub, so that the next connection trusts the key it sees. `--host` and `--port` default to the identity. [Security](security.md#forget-a-server-key) tells you when to use it.

```bash
hivemind-client --app docs-sat forget-server
```

```text
forgot pinned key for 127.0.0.1:15678
the next connection will trust and pin the key it sees
```

When no pin exists for that host and port, it lists the pins that do exist:

```text
no pinned key for 127.0.0.1:15678
pinned servers: -----BEGIN PUBLIC KEY-----
...
```

## reset-pgp

Makes a new RSA key pair, prints the public key and saves the identity. With `--app`, the key goes to the application's own folder. Peers that trust the old public key for INTERCOM must get the new one.

## Connection options

`terminal`, `send-mycroft`, `escalate`, `propagate` and `ping` share these options:

| Option | Default |
| :--- | :--- |
| `--key TEXT` | `access_key` of the identity |
| `--password TEXT` | `password` of the identity |
| `--host TEXT` | `default_master` of the identity |
| `--port INTEGER` | `default_port` of the identity, then 5678 |
| `--siteid TEXT` | `site_id` of the identity, then `unknown` |

Without a key, a password or a host, these commands raise `RuntimeError: NodeIdentity not set, please pass key/password/host or call 'hivemind-client set-identity'`.

---
[← Identity](identity.md) · [Home](index.md) · [Messages →](messages.md)
