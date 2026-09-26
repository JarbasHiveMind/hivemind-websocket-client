"""One PING flood cache per node — HIVEMIND-MSG-1 §4, HIVEMIND-NODE-1 §4.

A node that has an upstream runs two protocol objects at once: a
``HiveMindListenerProtocol`` (hivemind-core) serving its downstream clients,
and the ``HiveMindSlaveProtocol`` here, connected to its upstream. They are
two halves of one node.

With a flood cache each, both halves answer the same PING flood, and they
answer under different identities — the slave as its connection peer, the
listener as its public key. The originator then maps one node as two.

``FloodIdCache`` is the shared store that stops it, and
``HiveMindSlaveProtocol.bind_flood_cache`` is how the listener hands its
cache over.
"""
import threading
from unittest.mock import MagicMock

import pytest

from hivemind_bus_client.hive_map import FloodIdCache, HiveMapper
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol


class TestFloodIdCache:
    def test_behaves_as_a_set(self):
        """Existing callers treat the cache as a plain set of flood ids."""
        cache = FloodIdCache()
        cache.add("f1")
        assert "f1" in cache
        assert "f2" not in cache
        assert len(cache) == 1
        assert list(cache) == ["f1"]

    def test_adding_twice_keeps_one_entry(self):
        cache = FloodIdCache()
        cache.add("f1")
        cache.add("f1")
        assert len(cache) == 1

    def test_check_is_false_first_then_true(self):
        cache = FloodIdCache()
        assert cache.check("f1") is False, "first sighting must be handled"
        assert cache.check("f1") is True, "second sighting must be dropped"

    def test_empty_flood_id_always_reads_as_seen(self):
        """A malformed PING carries no flood_id and must never be answered."""
        assert FloodIdCache().check("") is True

    def test_eviction_is_fifo_and_bounded(self):
        cache = FloodIdCache(max_size=3)
        for i in range(5):
            cache.add(f"f{i}")
        assert len(cache) == 3
        assert "f0" not in cache and "f1" not in cache
        assert "f2" in cache and "f3" in cache and "f4" in cache

    def test_discard_and_clear(self):
        cache = FloodIdCache()
        cache.add("f1")
        cache.discard("f1")
        assert "f1" not in cache
        cache.add("f2")
        cache.clear()
        assert len(cache) == 0

    def test_check_is_atomic_across_threads(self):
        """The two halves of a node race on one cache from two threads.

        Only one of them may answer a given flood, so exactly one caller
        gets ``False`` no matter how many threads ask at once.
        """
        cache = FloodIdCache()
        winners = []
        start = threading.Barrier(16)

        def contend():
            start.wait()
            if not cache.check("contended-flood"):
                winners.append(threading.current_thread().name)

        threads = [threading.Thread(target=contend) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(winners) == 1

    def test_concurrent_adds_keep_the_cache_bounded(self):
        """Eviction under contention must not corrupt the ordered store."""
        cache = FloodIdCache(max_size=50)
        start = threading.Barrier(8)

        def fill(offset):
            start.wait()
            for i in range(200):
                cache.check(f"f-{offset}-{i}")

        threads = [threading.Thread(target=fill, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(cache) == 50


class TestHiveMapperUsesTheCache:
    def test_check_flood_id_still_dedups(self):
        mapper = HiveMapper()
        assert mapper.check_flood_id("f1") is False
        assert mapper.check_flood_id("f1") is True

    def test_check_flood_id_rejects_empty(self):
        assert HiveMapper().check_flood_id("") is True

    def test_check_flood_id_honours_max_size(self):
        mapper = HiveMapper()
        for i in range(5):
            mapper.check_flood_id(f"f{i}", max_size=3)
        assert len(mapper._seen_flood_ids) == 3

    def test_mapper_cache_is_a_flood_id_cache(self):
        """The store must be the shareable type, not a private dict."""
        assert isinstance(HiveMapper()._seen_flood_ids, FloodIdCache)


def _slave(cache=None) -> HiveMindSlaveProtocol:
    """A slave protocol wired just enough to answer a PING."""
    slave = object.__new__(HiveMindSlaveProtocol)
    slave.hm = MagicMock(session_id="sess-1")
    slave.identity = MagicMock(name_="node-a", public_key="PUBKEY-A")
    slave.identity.name = "node-a"
    slave.site_id = "site-a"
    slave.hive_mapper = HiveMapper()
    slave.cascade_aggregator = None
    if cache is not None:
        slave.bind_flood_cache(cache)
    return slave


def _ping(flood_id: str) -> HiveMessage:
    return HiveMessage(HiveMessageType.PING,
                       {"flood_id": flood_id, "peer": "origin",
                        "site_id": "site-z", "timestamp": 1.0})


class TestSlaveAnswersOncePerNode:
    def test_answers_a_new_flood(self):
        """A node with no shared cache still answers exactly once."""
        slave = _slave()
        sent = []
        slave._emit = sent.append

        slave.handle_ping(_ping("f1"))
        assert len(sent) == 1, "a node must answer a flood it has not seen"

        slave.handle_ping(_ping("f1"))
        assert len(sent) == 1, "a node must not answer the same flood twice"

    def test_shared_cache_suppresses_the_second_half_of_the_node(self):
        """The listener half already answered, so the slave half must not."""
        cache = FloodIdCache()
        cache.add("f1")  # the co-located listener answered this flood

        slave = _slave(cache=cache)
        sent = []
        slave._emit = sent.append

        slave.handle_ping(_ping("f1"))
        assert sent == [], (
            "the node already took part in this flood through its listener "
            "half; answering again maps one node as two (NODE-1 §4)")

    def test_slave_answer_is_visible_to_the_listener_half(self):
        """Suppression works in the other direction too."""
        cache = FloodIdCache()
        slave = _slave(cache=cache)
        slave._emit = MagicMock()

        slave.handle_ping(_ping("f1"))

        assert "f1" in cache, (
            "the slave's answer must be recorded in the shared cache so the "
            "listener half suppresses its own duplicate answer")

    def test_bind_flood_cache_creates_a_mapper_when_absent(self):
        slave = object.__new__(HiveMindSlaveProtocol)
        slave.hive_mapper = None
        cache = FloodIdCache()
        slave.bind_flood_cache(cache)
        assert slave.hive_mapper is not None
        assert slave.hive_mapper._seen_flood_ids is cache

    def test_unbound_slaves_do_not_share_a_cache(self):
        """Two separate nodes must each answer the flood — no cross-talk."""
        a, b = _slave(), _slave()
        sent_a, sent_b = [], []
        a._emit, b._emit = sent_a.append, sent_b.append

        a.handle_ping(_ping("f1"))
        b.handle_ping(_ping("f1"))

        assert len(sent_a) == 1 and len(sent_b) == 1


class TestResponsivePingIdentity:
    def test_carries_both_the_connection_peer_and_the_stable_key(self):
        """``peer`` labels the connection; ``public_key`` identifies the node.

        The listener half of a node announces its public key, so the stable
        identity has to travel on every responsive PING for a consumer to
        recognise the two as one node.
        """
        slave = _slave()
        sent = []
        slave._emit = sent.append

        slave.handle_ping(_ping("f1"))

        payload = sent[0].payload.payload
        assert payload["peer"] == "node-a::sess-1"
        assert payload["public_key"] == "PUBKEY-A"
        assert payload["flood_id"] == "f1"
