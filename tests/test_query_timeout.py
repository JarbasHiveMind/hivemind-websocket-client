"""Originator-side QUERY liveness bound (HIVEMIND-NODE-1 §5.5, AGENT-1 §5).

NODE-1 §5.5 requires the originator of a QUERY to treat it as failed when no
chunk, no ``hive.query.complete`` and no ``hive.query.timeout`` arrives within
a configured interval. CASCADE has always had such a window
(``cascade_timeout``); QUERY had none, so a vanished intermediate node stranded
the originator forever.

The failure is reported as ``hive.query.timeout`` with
``error="originator_timeout"`` — deliberately distinct from the mesh's own
``error="no_answer"``, which means the query *was* resolved and nothing had an
answer.
"""

import time
from unittest.mock import MagicMock

from ovos_bus_client.message import Message

from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import (HiveMindSlaveInternalProtocol,
                                          HiveMindSlaveProtocol,
                                          QueryTimeoutGuard,
                                          QUERY_STREAM_END, QUERY_TIMEOUT)


def _make_protocol(query_timeout=0.05):
    hm = MagicMock()
    hm.session_id = "test-session"
    identity = MagicMock(spec=NodeIdentity)
    identity.name = "test-node"
    proto = HiveMindSlaveProtocol(hm=hm, identity=identity,
                                  query_timeout=query_timeout)
    proto.internal_protocol = MagicMock()
    proto.internal_protocol.bus = MagicMock()
    return proto


def _query(payload_type, query_id="q-1"):
    inner = HiveMessage(HiveMessageType.BUS,
                        {"type": payload_type, "data": {}, "context": {}})
    return HiveMessage(HiveMessageType.QUERY, payload=inner,
                       metadata={"query_id": query_id})


def _emitted(proto):
    return [c[0][0] for c in proto.internal_protocol.bus.emit.call_args_list
            if isinstance(c[0][0], Message)]


def _originator_timeouts(proto):
    return [m for m in _emitted(proto)
            if m.msg_type == QUERY_TIMEOUT
            and m.data.get("error") == "originator_timeout"]


class TestQueryTimeoutGuard:
    """NODE-1 §5.5: the window exists, expires, and is cancellable."""

    def test_window_expires_when_nothing_arrives(self):
        fired = []
        guard = QueryTimeoutGuard(timeout=0.05, emit_callback=fired.append)
        guard.start()
        assert fired == []
        time.sleep(0.15)
        assert fired == [""]

    def test_keepalive_extends_the_window(self):
        fired = []
        guard = QueryTimeoutGuard(timeout=0.15, emit_callback=fired.append)
        guard.start()
        for _ in range(3):
            time.sleep(0.08)
            guard.keepalive("q-1")
        assert fired == []
        time.sleep(0.25)
        assert fired == ["q-1"]

    def test_cancel_prevents_expiry(self):
        fired = []
        guard = QueryTimeoutGuard(timeout=0.05, emit_callback=fired.append)
        guard.start()
        guard.cancel()
        time.sleep(0.15)
        assert fired == []


class TestOriginatorQueryTimeout:
    """NODE-1 §5.5 end to end on HiveMindSlaveProtocol."""

    def test_silence_after_sending_a_query_is_reported_as_a_failure(self):
        proto = _make_protocol()
        proto.arm_query_timeout()
        time.sleep(0.2)
        msgs = _emitted(proto)
        assert [m.msg_type for m in msgs] == [QUERY_TIMEOUT]
        assert msgs[0].data["error"] == "originator_timeout"
        assert msgs[0].data["query_id"] == ""

    def test_a_timeout_is_distinguishable_from_answered_with_nothing(self):
        # the mesh's own verdict uses error="no_answer" and must not be
        # confused with the originator giving up
        proto = _make_protocol()
        proto.arm_query_timeout()
        assert proto.internal_protocol.bus.emit.call_count == 0
        time.sleep(0.2)
        assert _emitted(proto)[0].data["error"] != "no_answer"

    def test_an_answer_chunk_keeps_the_query_alive(self):
        proto = _make_protocol(query_timeout=0.2)
        proto.arm_query_timeout()
        for _ in range(3):
            time.sleep(0.1)
            proto.handle_query(_query("speak"))
        assert _originator_timeouts(proto) == []

    def test_stream_completion_closes_the_window(self):
        proto = _make_protocol()
        proto.arm_query_timeout()
        proto.handle_query(_query(QUERY_STREAM_END))
        time.sleep(0.2)
        assert _originator_timeouts(proto) == []

    def test_a_mesh_timeout_verdict_closes_the_window(self):
        proto = _make_protocol()
        proto.arm_query_timeout()
        proto.handle_query(_query(QUERY_TIMEOUT))
        time.sleep(0.2)
        # the mesh verdict is relayed to the app, and the originator does not
        # pile its own failure on top of it
        assert [m.msg_type for m in _emitted(proto)] == [QUERY_TIMEOUT]
        assert _originator_timeouts(proto) == []

    def test_sending_a_query_upstream_arms_the_window(self):
        proto = _make_protocol()
        internal = HiveMindSlaveInternalProtocol(hm_bus=MagicMock(), bus=MagicMock(),
                                                 slave_protocol=proto)
        internal.handle_send(Message("hive.send.upstream",
                                     {"msg_type": HiveMessageType.QUERY,
                                      "payload": {"type": "recognizer_loop:utterance"}}))
        assert proto.query_guard is not None
        proto.query_guard.cancel()
