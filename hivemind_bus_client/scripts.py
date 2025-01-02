import json

import click
from ovos_bus_client import Message
from ovos_utils.log import LOG
from ovos_utils.fakebus import FakeBus

from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.identity import NodeIdentity
LOG.set_level("DEBUG")


@click.group()
def hmclient_cmds():
    pass


@hmclient_cmds.command(help="persist node identity / credentials", name="set-identity")
@click.option("--key", help="HiveMind access key", type=str, default="")
@click.option("--password", help="HiveMind password", type=str, default="")
@click.option("--host", help="default host for hivemind-core", type=str, default="")
@click.option("--port", help="default port for hivemind-core", type=int, required=False)
@click.option("--siteid", help="location identifier for message.context", type=str, default="")
def identity_set(key: str, password: str, host: str, port: int, siteid: str):
    if not key and not password and not siteid:
        raise ValueError("please set at least one of key/password/siteid/host")
    identity = NodeIdentity()
    identity.password = password or identity.password
    identity.access_key = key or identity.access_key
    identity.site_id = siteid or identity.site_id
    identity.default_port = port or identity.default_port or 5678
    host = host or identity.default_master
    if not host.startswith("ws://") and not host.startswith("wss://"):
        host = "ws://" + host
    identity.default_master = host
    if not identity.public_key:
        identity.create_keys()
        print("PUBKEY:", identity.public_key)
    identity.save()
    print(f"identity saved: {identity.IDENTITY_FILE.path}")


@hmclient_cmds.command(help="simple cli interface to inject utterances and print speech", name="terminal")
@click.option("--key", help="HiveMind access key (default read from identity file)", type=str, default="")
@click.option("--password", help="HiveMind password (default read from identity file)", type=str, default="")
@click.option("--host", help="HiveMind host (default read from identity file)", type=str, default="")
@click.option("--port", help="HiveMind port number (default: 5678)", type=int, required=False)
@click.option("--siteid", help="location identifier for message.context  (default read from identity file)", type=str, default="")
def terminal(key: str, password: str, host: str, port: int, siteid: str):
    identity = NodeIdentity()
    password = password or identity.password
    key = key or identity.access_key
    host = host or identity.default_master
    siteid = siteid or identity.site_id or "unknown"
    port = port or identity.default_port or 5678

    if not host.startswith("ws://") and not host.startswith("wss://"):
        host = "ws://" + host

    if not key or not password or not host:
        raise RuntimeError("NodeIdentity not set, please pass key/password/host or "
                           "call 'hivemind-client set-identity'")

    node = HiveMessageBusClient(key, host=host, port=port, password=password)
    node.connect(FakeBus(), site_id=siteid)

    # node.connected_event.wait()
    print("== connected to HiveMind")

    def handle_speak(message: Message):
        utt = message.data["utterance"]
        print("> ", utt)

    node.on_mycroft("speak", handle_speak)

    while True:
        try:
            utt = input("Utterance:")
            node.emit_mycroft(
                Message("recognizer_loop:utterance",
                        {"utterances": [utt]},
                        {"destination": "skills"})
            )
        except KeyboardInterrupt:
            break
        except Exception:
            LOG.exception("error")
            break

    node.close()


@hmclient_cmds.command(help="send a single mycroft message",
                       name="send-mycroft")
@click.option("--key", help="HiveMind access key (default read from identity file)", type=str, default="")
@click.option("--password", help="HiveMind password (default read from identity file)", type=str, default="")
@click.option("--host", help="HiveMind host (default read from identity file)", type=str, default="")
@click.option("--port", help="HiveMind port number (default: 5678)", type=int, required=False)
@click.option("--siteid", help="location identifier for message.context  (default read from identity file)", type=str, default="")
@click.option("--msg", help="ovos message type to inject", type=str)
@click.option("--payload", help="ovos message.data json", type=str)
def send_mycroft(key: str, password: str, host: str, port: int, siteid: str, msg: str, payload: str):
    node = HiveMessageBusClient(key, host=host, port=port, password=password)
    node.connect(FakeBus(), site_id=siteid)

    node.connected_event.wait()
    print("== connected to HiveMind")

    node.emit_mycroft(Message(msg, json.loads(payload)))

    node.close()


@hmclient_cmds.command(help="escalate a single mycroft message",
                       name="escalate")
@click.option("--key", help="HiveMind access key (default read from identity file)", type=str, default="")
@click.option("--password", help="HiveMind password (default read from identity file)", type=str, default="")
@click.option("--host", help="HiveMind host (default read from identity file)", type=str, default="")
@click.option("--port", help="HiveMind port number (default: 5678)", type=int, required=False)
@click.option("--siteid", help="location identifier for message.context  (default read from identity file)", type=str, default="")
@click.option("--msg", help="ovos message type to inject", type=str)
@click.option("--payload", help="ovos message.data json", type=str)
def escalate(key: str, password: str, host: str, port: int, siteid: str, msg: str, payload: str):
    identity = NodeIdentity()
    password = password or identity.password
    key = key or identity.access_key
    host = host or identity.default_master
    siteid = siteid or identity.site_id or "unknown"
    port = port or identity.default_port or 5678

    if not host.startswith("ws://") and not host.startswith("wss://"):
        host = "ws://" + host

    if not key or not password or not host:
        raise RuntimeError("NodeIdentity not set, please pass key/password/host or "
                           "call 'hivemind-client set-identity'")

    node = HiveMessageBusClient(key, host=host, port=port, password=password)
    node.connect(FakeBus(), site_id=siteid)

    node.connected_event.wait()
    print("== connected to HiveMind")

    hm = HiveMessage(HiveMessageType.ESCALATE,
                     Message(msg, json.loads(payload)))
    node.emit(hm)

    node.close()


@hmclient_cmds.command(help="propagate a single mycroft message",
                       name="propagate")
@click.option("--key", help="HiveMind access key (default read from identity file)", type=str, default="")
@click.option("--password", help="HiveMind password (default read from identity file)", type=str, default="")
@click.option("--host", help="HiveMind host (default read from identity file)", type=str, default="")
@click.option("--port", help="HiveMind port number (default: 5678)", type=int, required=False)
@click.option("--siteid", help="location identifier for message.context  (default read from identity file)", type=str, default="")
@click.option("--msg", help="ovos message type to inject", type=str)
@click.option("--payload", help="ovos message.data json", type=str)
def propagate(key: str, password: str, host: str, port: int, siteid: str, msg: str, payload: str):
    identity = NodeIdentity()
    password = password or identity.password
    key = key or identity.access_key
    host = host or identity.default_master
    siteid = siteid or identity.site_id or "unknown"
    port = port or identity.default_port or 5678

    if not host.startswith("ws://") and not host.startswith("wss://"):
        host = "ws://" + host

    if not key or not password or not host:
        raise RuntimeError("NodeIdentity not set, please pass key/password/host or "
                           "call 'hivemind-client set-identity'")

    node = HiveMessageBusClient(key, host=host, port=port, password=password)
    node.connect(FakeBus(), site_id=siteid)

    node.connected_event.wait()
    print("== connected to HiveMind")

    hm = HiveMessage(HiveMessageType.PROPAGATE,
                     Message(msg, json.loads(payload)))
    node.emit(hm)

    node.close()


@hmclient_cmds.command(help="test if Identity file can connect to HiveMind",
                       name="test-identity")
def test_identity():
    node = HiveMessageBusClient()
    node.connect(FakeBus())

    node.connected_event.wait()
    print("== Identity successfully connected to HiveMind!")

    node.close()


@hmclient_cmds.command(help="recreate the private RSA key for inter-node communication", name="reset-pgp")
def reset_keys():
    identity = NodeIdentity()
    identity.create_keys()
    print("PUBKEY:", identity.public_key)
    identity.save()
    print(f"identity saved: {identity.IDENTITY_FILE.path}")


if __name__ == "__main__":
    hmclient_cmds()
