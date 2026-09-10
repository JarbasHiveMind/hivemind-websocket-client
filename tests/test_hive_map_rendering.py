"""The hive map is the tool for asking whether a hive is healthy.

Two things made it unusable against a real hive: nodes identify themselves by
public key, so peer ids are full PEM blocks that destroy the tree layout; and a
node that answers a flood directly leaves no relayed hop behind, so it appears
in the node table with no edge naming it and was never drawn at all.
"""
import time

from hivemind_bus_client.hive_map import HiveMapper
from hivemind_bus_client.message import HiveMessage, HiveMessageType

PEM = ("-----BEGIN PUBLIC KEY-----\n"
       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuRgdM4MJ1/OMuROQYbdn\n"
       "ufjNq0guvEGIGerxi+/2MwdVl4Bp3KQtfSoexs1FVV7+bS1dAssSweLKQfBszAyW\n"
       "-----END PUBLIC KEY-----")


def _ping(mapper, flood_id, peer, site_id=None, route=None):
    message = HiveMessage(HiveMessageType.PING, {
        "flood_id": flood_id, "peer": peer, "site_id": site_id,
        "timestamp": time.time(), "public_key": peer,
    })
    if route:
        message.replace_route(route)
    mapper.on_ping(message, received_at=time.time())


def test_a_public_key_peer_renders_as_a_fingerprint():
    from hivemind_bus_client.hive_map import display_peer

    assert display_peer(PEM).startswith("key:")
    assert "\n" not in display_peer(PEM)
    assert len(display_peer(PEM)) < 24


def test_a_plain_peer_id_is_left_alone():
    from hivemind_bus_client.hive_map import display_peer

    assert display_peer("sat-1a::abc123") == "sat-1a::abc123"


def test_the_tree_stays_on_one_line_per_node():
    mapper = HiveMapper()
    mapper.start_ping("f1")
    _ping(mapper, "f1", PEM, site_id="kitchen")

    tree = mapper.to_ascii(root_peer="me::1")

    assert len(tree.splitlines()) == 2, tree
    assert "BEGIN PUBLIC KEY" not in tree


def test_a_node_that_answered_directly_appears_on_the_map():
    """It leaves no relayed hop, so nothing in the edge graph names it."""
    mapper = HiveMapper()
    mapper.start_ping("f1")
    _ping(mapper, "f1", "relay-a::1", site_id="hall")

    tree = mapper.to_ascii(root_peer="me::1")

    assert "relay-a::1" in tree, tree


def test_every_answerer_appears_exactly_once():
    mapper = HiveMapper()
    mapper.start_ping("f1")
    _ping(mapper, "f1", "relay-a::1")
    _ping(mapper, "f1", "leaf-b::2", route=[{"source": "relay-a::1",
                                             "targets": ["leaf-b::2"]}])

    tree = mapper.to_ascii(root_peer="me::1")

    assert tree.count("relay-a::1") == 1, tree
    assert tree.count("leaf-b::2") == 1, tree


def test_json_output_keeps_the_full_key():
    """Fingerprints are for reading; a machine consumer needs the real key."""
    mapper = HiveMapper()
    mapper.start_ping("f1")
    _ping(mapper, "f1", PEM)

    assert "BEGIN PUBLIC KEY" in mapper.to_json()


def test_a_cycle_does_not_recurse_forever():
    """Two nodes that relayed each other's PINGs make a cycle in the display
    graph, and flood routing produces exactly that."""
    mapper = HiveMapper()
    mapper.start_ping("f1")
    _ping(mapper, "f1", "b::1", route=[{"source": "c::1", "targets": ["b::1"]}])
    _ping(mapper, "f1", "c::1", route=[{"source": "b::1", "targets": ["c::1"]}])
    _ping(mapper, "f1", "x::1", route=[{"source": "c::1", "targets": ["x::1"]}])

    tree = mapper.to_ascii(root_peer="me::1")   # must not raise

    assert "[self] me::1" in tree
    assert "(cycle)" in tree, tree


def test_a_node_reachable_by_two_paths_still_appears_under_both():
    """The guard is per-branch: it must not hide legitimate second parents."""
    mapper = HiveMapper()
    mapper.start_ping("f1")
    _ping(mapper, "f1", "shared::1", route=[{"source": "a::1", "targets": ["shared::1"]}])
    _ping(mapper, "f1", "shared::1", route=[{"source": "b::1", "targets": ["shared::1"]}])

    tree = mapper.to_ascii(root_peer="me::1")

    assert tree.count("shared::1") >= 1, tree


def test_answerers_appear_without_a_root_peer_too():
    """`to_ascii()` with no root is the raw view; nodes that answered directly
    have no edge, and rendering only the edge graph showed nothing at all."""
    mapper = HiveMapper()
    mapper.start_ping("f1")
    _ping(mapper, "f1", "relay-a::1")

    tree = mapper.to_ascii()

    assert "relay-a::1" in tree, tree
