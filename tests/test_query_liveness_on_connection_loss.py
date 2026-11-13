"""A QUERY waiting when the socket dies must not be left hanging.

``QueryLivenessTimer`` exists because intermediate nodes decline a QUERY
silently: only the clock tells the originator the answer is lost. The socket
closing says the same thing sooner, and says it with certainty — whatever was
in flight died with the connection, and the replacement socket carries a new
session in which the old query id means nothing.

Before this, ``reset_connection_state()`` left the timer armed. The waiter got
its answer late, on a daemon timer belonging to a connection that no longer
existed; after ``close()`` it fired into a bus nobody was reading.
"""
from unittest.mock import MagicMock, patch

from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.protocol import (HiveMindSlaveProtocol,
                                          QueryLivenessTimer)


def _reset(proto: HiveMindSlaveProtocol) -> None:
    """Run reset_connection_state with the RSA handshake stubbed.

    ``reset_connection_state`` rebuilds the legacy handshake from a real key
    file, which a mocked identity has no business owning; every other test of
    this method stubs it the same way.
    """
    proto._noise_established = True  # skip the KK pin-drop branch
    with patch("hivemind_bus_client.protocol.HandShake"):
        proto.reset_connection_state()


def _make_protocol(stopping: bool = False) -> HiveMindSlaveProtocol:
    hm = MagicMock()
    hm.session_id = "test-session"
    hm.password = "test-node-horse-battery-staple-92"
    hm.stopping = stopping
    identity = MagicMock(spec=NodeIdentity)
    identity.name = "test-node"
    return HiveMindSlaveProtocol(hm=hm, identity=identity, site_id="living-room")


class TestExpireNow:
    def test_it_reports_the_remembered_query_id_once(self):
        seen = []
        timer = QueryLivenessTimer(60.0, seen.append)
        timer.arm("query-7")
        assert timer.expire_now() is True
        assert seen == ["query-7"]

    def test_a_second_call_reports_nothing(self):
        seen = []
        timer = QueryLivenessTimer(60.0, seen.append)
        timer.arm("query-7")
        timer.expire_now()
        assert timer.expire_now() is False
        assert seen == ["query-7"]

    def test_nothing_in_flight_reports_nothing(self):
        seen = []
        timer = QueryLivenessTimer(60.0, seen.append)
        assert timer.expire_now() is False
        assert seen == []

    def test_it_leaves_no_timer_running(self):
        timer = QueryLivenessTimer(60.0, lambda qid: None)
        timer.arm("query-7")
        armed = timer._timer
        timer.expire_now()
        assert timer._timer is None
        # Timer.cancel() only stops the action; the thread leaves its wait a
        # moment later, so join before asking whether it is gone.
        armed.join(timeout=5)
        assert not armed.is_alive()


class TestReconnect:
    def test_a_lost_query_is_reported_at_once(self):
        proto = _make_protocol(stopping=False)
        seen = []
        proto.query_liveness = QueryLivenessTimer(60.0, seen.append)
        proto.query_liveness.arm("query-7")

        _reset(proto)

        assert seen == ["query-7"], "a query lost with its socket was not reported"
        assert proto.query_liveness._timer is None

    def test_a_reconnect_with_no_query_in_flight_reports_nothing(self):
        proto = _make_protocol(stopping=False)
        seen = []
        proto.query_liveness = QueryLivenessTimer(60.0, seen.append)

        _reset(proto)

        assert seen == []

    def test_a_protocol_that_never_queried_is_untouched(self):
        proto = _make_protocol(stopping=False)
        assert proto.query_liveness is None
        _reset(proto)  # must not raise
        assert proto.query_liveness is None


class TestPermanentClose:
    def test_the_timer_is_cancelled_and_nothing_is_emitted(self):
        """After close() nobody is listening: firing would reach a closed bus."""
        proto = _make_protocol(stopping=True)
        seen = []
        proto.query_liveness = QueryLivenessTimer(60.0, seen.append)
        proto.query_liveness.arm("query-7")
        armed = proto.query_liveness._timer

        _reset(proto)

        assert seen == [], "a closing client still reported a timeout"
        assert proto.query_liveness._timer is None
        armed.join(timeout=5)
        assert not armed.is_alive()
