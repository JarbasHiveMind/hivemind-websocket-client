"""Peer-to-peer INTERCOM did not deliver, in three separate ways.

All three were found in a three-layer lab hive (master -> two relays -> leaves)
and none of them is visible from a unit test that stops at "a message was
emitted": each failure happens after the frame is on the wire.
"""
from unittest.mock import MagicMock, patch

import pytest
from ovos_bus_client.message import Message

from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol


@pytest.fixture
def keypair(tmp_path):
    """A real RSA identity — the bug is in how real envelopes are handled."""
    from json_database import JsonStorageXDG
    store = JsonStorageXDG("_identity", subfolder="hivemind")
    store.path = str(tmp_path / "_identity.json")
    identity = NodeIdentity(identity_file=store)
    identity.create_keys()
    identity.save()
    return identity


def _protocol(identity, trust_self=True):
    protocol = HiveMindSlaveProtocol(hm=MagicMock())
    protocol.mpubkey = None
    if trust_self and identity.public_key:
        identity.trusted_keys = {"self": identity.public_key}
    protocol.identity = identity
    protocol.internal_protocol = MagicMock()
    protocol.site_id = "lab"
    return protocol


def _sealed(sender, recipient_pubkey, payload):
    from hivemind_bus_client.encryption import hybrid_encrypt
    from poorman_handshake.asymmetric.utils import load_RSA_key
    inner = HiveMessage(HiveMessageType.BUS, Message("lab.probe", payload))
    envelope = hybrid_encrypt(recipient_pubkey, inner.serialize(),
                              sign_key=load_RSA_key(sender.private_key))
    return HiveMessage(HiveMessageType.INTERCOM, payload=envelope,
                       target_pubkey=recipient_pubkey)


def test_an_encrypted_intercom_does_not_crash_the_handler(keypair):
    """The payload of an encrypted INTERCOM is the envelope dict, which has no
    msg_type. Asserting the decrypted shape before decrypting raised
    AttributeError on every encrypted frame — the only frames that matter."""
    protocol = _protocol(keypair)

    message = _sealed(keypair, keypair.public_key, {"secret": "hi"})

    protocol.handle_intercom(message)  # must not raise

    protocol.internal_protocol.bus.emit.assert_called_once()


def test_the_decrypted_payload_is_what_gets_delivered(keypair):
    """handle_bus asserts its argument is a BUS message. Handing it the outer
    INTERCOM raised AssertionError from inside the handler, after a successful
    decrypt."""
    protocol = _protocol(keypair)

    protocol.handle_intercom(_sealed(keypair, keypair.public_key, {"secret": "hi"}))

    delivered = protocol.internal_protocol.bus.emit.call_args[0][0]
    assert delivered.msg_type == "lab.probe"
    assert delivered.data["secret"] == "hi"


def test_an_intercom_for_someone_else_is_not_delivered(keypair, tmp_path):
    """The guard that must survive the fixes above."""
    from json_database import JsonStorageXDG
    store = JsonStorageXDG("_identity", subfolder="hivemind")
    store.path = str(tmp_path / "other.json")
    other = NodeIdentity(identity_file=store)
    other.create_keys()

    protocol = _protocol(keypair)
    protocol._is_source_trusted = lambda m: False

    protocol.handle_intercom(_sealed(keypair, other.public_key, {"secret": "hi"}))

    protocol.internal_protocol.bus.emit.assert_not_called()


def test_emit_intercom_addresses_and_wraps_the_frame(keypair):
    """A bare INTERCOM is consumed at the first node it reaches: the
    handle_message call site discards handle_intercom_message's "not for me,
    keep relaying" answer. Only the PROPAGATE handler acts on it. And without
    target_pubkey a node has nothing to route on in the first place."""
    from hivemind_bus_client.client import HiveMessageBusClient

    client = HiveMessageBusClient.__new__(HiveMessageBusClient)
    client.identity = keypair
    sent = []
    client.emit = sent.append

    client.emit_intercom(Message("lab.probe", {"x": 1}), keypair.public_key)

    assert len(sent) == 1
    outer = sent[0]
    assert outer.msg_type == HiveMessageType.PROPAGATE, "a bare INTERCOM never travels"
    inner = outer.payload
    assert inner.msg_type == HiveMessageType.INTERCOM
    assert inner.target_public_key == keypair.public_key, "the frame must carry its address"


def test_a_forged_signature_is_not_delivered(keypair, tmp_path):
    """CRYPTO-1 §5: the origin signature must verify. A node's public key is
    its address, published in every PING answer — knowing it must not be
    enough to send as somebody else."""
    from json_database import JsonStorageXDG
    store = JsonStorageXDG("_identity", subfolder="hivemind")
    store.path = str(tmp_path / "attacker.json")
    attacker = NodeIdentity(identity_file=store)
    attacker.create_keys()

    protocol = _protocol(keypair, trust_self=False)
    # a POPULATED store: an empty one would pass even if verification always
    # returned False, so it would prove nothing
    keypair.trusted_keys = {"a-real-peer": keypair.public_key}
    protocol.mpubkey = None

    protocol.handle_intercom(_sealed(attacker, keypair.public_key, {"x": "forged"}))

    protocol.internal_protocol.bus.emit.assert_not_called()


def test_an_unsigned_intercom_is_not_delivered(keypair):
    protocol = _protocol(keypair)
    message = _sealed(keypair, keypair.public_key, {"x": "hi"})
    message.payload.pop("signature", None)

    protocol.handle_intercom(message)

    protocol.internal_protocol.bus.emit.assert_not_called()


def test_a_trusted_signed_intercom_is_delivered(keypair):
    """The control: trust-gating must not disable the feature."""
    protocol = _protocol(keypair)
    keypair.trusted_keys = {"self": keypair.public_key}

    protocol.handle_intercom(_sealed(keypair, keypair.public_key, {"x": "hi"}))

    protocol.internal_protocol.bus.emit.assert_called_once()


def test_the_master_is_an_anchor_without_hand_edited_trust(keypair):
    """A default deployment has an empty trusted_keys and nothing populates
    it, so mail from the node's own master has to work on its own."""
    protocol = _protocol(keypair, trust_self=False)
    keypair.trusted_keys = {}
    protocol.mpubkey = keypair.public_key

    protocol.handle_intercom(_sealed(keypair, keypair.public_key, {"x": "hi"}))

    protocol.internal_protocol.bus.emit.assert_called_once()


def test_one_trusted_peer_cannot_sign_as_another(keypair, tmp_path):
    """Accepting any trusted key lets a trusted peer impersonate another."""
    from json_database import JsonStorageXDG
    store = JsonStorageXDG("_identity", subfolder="hivemind")
    store.path = str(tmp_path / "other.json")
    other = NodeIdentity(identity_file=store)
    other.create_keys()

    protocol = _protocol(keypair, trust_self=False)
    keypair.trusted_keys = {"peer-a": keypair.public_key, "peer-b": other.public_key}
    protocol.mpubkey = None

    message = _sealed(other, keypair.public_key, {"x": "as-peer-a"})
    message.update_source_peer(keypair.public_key)   # claims to be peer-a

    protocol.handle_intercom(message)

    protocol.internal_protocol.bus.emit.assert_not_called()


def test_the_delivered_message_names_the_key_that_signed_it(keypair):
    """The envelope binds no origin, so `source_peer` is whatever the sender
    wrote. Recording the key that actually verified leaves the claim with
    nothing to act on.

    The outer INTERCOM object is discarded once unwrapped — a consumer never
    sees it. What a consumer actually receives is whatever gets handed to
    ``bus.emit``, so that is what must carry the verified origin, not the
    outer frame that is thrown away.
    """
    from hivemind_bus_client.protocol import VERIFIED_SOURCE_PEER_KEY

    protocol = _protocol(keypair)
    message = _sealed(keypair, keypair.public_key, {"x": "hi"})
    message.update_source_peer("somebody-elses-label")

    protocol.handle_intercom(message)

    protocol.internal_protocol.bus.emit.assert_called_once()
    delivered = protocol.internal_protocol.bus.emit.call_args[0][0]
    assert delivered.context.get(VERIFIED_SOURCE_PEER_KEY) == keypair.public_key, \
        "the message a consumer actually receives must name the key that signed it"


async def _emit_intercom_via(client_kind: str, keypair, message):
    """Call ``emit_intercom`` on the given client kind, capturing what it
    hands to ``self.emit`` instead of touching a real socket/HTTP transport.

    Returns the outer HiveMessage that was emitted.
    """
    sent = []
    if client_kind == "sync":
        from hivemind_bus_client.client import HiveMessageBusClient
        client = HiveMessageBusClient.__new__(HiveMessageBusClient)
        client.identity = keypair
        client.emit = sent.append
        client.emit_intercom(message, keypair.public_key)
    elif client_kind == "async":
        from hivemind_bus_client.async_client import AsyncHiveMessageBusClient
        client = AsyncHiveMessageBusClient.__new__(AsyncHiveMessageBusClient)
        client.identity = keypair

        async def _capture(msg):
            sent.append(msg)

        client.emit = _capture
        await client.emit_intercom(message, keypair.public_key)
    elif client_kind == "http":
        from hivemind_bus_client.http_client import HiveMindHTTPClient
        client = HiveMindHTTPClient.__new__(HiveMindHTTPClient)
        client.identity = keypair
        client.emit = sent.append
        client.emit_intercom(message, keypair.public_key)
    else:
        raise ValueError(client_kind)

    assert len(sent) == 1, f"{client_kind} client did not emit exactly one message"
    return sent[0]


@pytest.mark.parametrize("client_kind", ["sync", "async", "http"])
@pytest.mark.asyncio
async def test_all_three_clients_produce_a_deliverable_intercom(client_kind, keypair):
    """``emit_intercom`` was fixed for the sync client (address the frame,
    wrap it in PROPAGATE) but the async and HTTP clients diverged: async sent
    a bare, unaddressed INTERCOM (same two defects the sync client used to
    have), and HTTP built an entirely different, non-hybrid envelope that the
    receiver rejects outright and that could not even be JSON-serialized
    (raw ``bytes`` from ``pybase64.b64encode`` in the payload dict).

    All three clients must now (a) produce a frame that serializes without
    raising, and (b) be accepted end-to-end by the same receiving path.
    """
    message = Message("lab.probe", {"x": 1})

    outer = await _emit_intercom_via(client_kind, keypair, message)

    assert outer.msg_type == HiveMessageType.PROPAGATE, \
        f"{client_kind} client: a bare INTERCOM never travels"
    inner = outer.payload
    assert inner.msg_type == HiveMessageType.INTERCOM
    assert inner.target_public_key == keypair.public_key, \
        f"{client_kind} client: the frame must carry its address"

    # (a) serializes without raising - the HTTP client used to embed raw
    # bytes in the payload dict, which json.dumps rejects.
    wire = outer.serialize()
    assert isinstance(wire, str) and wire

    # (b) accepted end-to-end by the same verification/delivery path real
    # traffic goes through.
    from hivemind_bus_client.protocol import VERIFIED_SOURCE_PEER_KEY

    protocol = _protocol(keypair)
    delivered_ok = protocol.handle_intercom(inner)
    assert delivered_ok is not False, \
        f"{client_kind} client: frame was rejected by the receiving protocol"
    protocol.internal_protocol.bus.emit.assert_called_once()
    delivered = protocol.internal_protocol.bus.emit.call_args[0][0]
    assert delivered.msg_type == "lab.probe"
    assert delivered.data["x"] == 1
    assert delivered.context.get(VERIFIED_SOURCE_PEER_KEY) == keypair.public_key


def test_a_forged_verified_source_context_is_stripped_on_plain_bus(keypair):
    """`handle_bus` is the common sink for every BUS-injection path, not
    just INTERCOM - plain master BUS and PROPAGATE-wrapped BUS reach it too,
    and neither of those paths checks a signature. If a sender-supplied
    VERIFIED_SOURCE_PEER_KEY survived through one of those paths, it would
    forge the exact field the INTERCOM fix introduced for consumers to
    trust: a field that is authoritative on one path and attacker-controlled
    on every other path into the same sink is worse than no field at all.
    """
    from hivemind_bus_client.protocol import VERIFIED_SOURCE_PEER_KEY

    protocol = _protocol(keypair)
    forged = HiveMessage(HiveMessageType.BUS,
                         Message("lab.probe", {"x": 1},
                                 context={VERIFIED_SOURCE_PEER_KEY: "I-AM-TOTALLY-TRUSTED"}))

    protocol.handle_bus(forged)

    protocol.internal_protocol.bus.emit.assert_called_once()
    delivered = protocol.internal_protocol.bus.emit.call_args[0][0]
    assert VERIFIED_SOURCE_PEER_KEY not in delivered.context, \
        "a sender-supplied verified-origin claim must never survive to the consumer"


def test_a_genuinely_verified_intercom_still_carries_the_real_signer(keypair):
    """The control for the strip above: stripping every inbound value must
    not also strip the one legitimate case, where THIS node verified the
    signature itself and _deliver_verified passes it explicitly."""
    from hivemind_bus_client.protocol import VERIFIED_SOURCE_PEER_KEY

    protocol = _protocol(keypair)

    protocol.handle_intercom(_sealed(keypair, keypair.public_key, {"x": "hi"}))

    protocol.internal_protocol.bus.emit.assert_called_once()
    delivered = protocol.internal_protocol.bus.emit.call_args[0][0]
    assert delivered.context.get(VERIFIED_SOURCE_PEER_KEY) == keypair.public_key
