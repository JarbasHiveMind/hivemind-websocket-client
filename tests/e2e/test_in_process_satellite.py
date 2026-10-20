"""E2E for an in-process satellite driven through ``InProcessHiveShim``.

Every other e2e test in this suite connects a real
:class:`HiveMessageBusClient` over a loopback WebSocket. None of them reaches
``hivescope.node.InProcessHiveShim``, so none of them needs the ``hivescope``
floor that ``pyproject.toml`` names.

This test does. ``TopologyBuilder.add_satellite`` wires a satellite to a master
in-process, and the handshake runs
:class:`hivemind_bus_client.protocol.HiveMindSlaveProtocol` against the shim
instead of against a client. That path reads ``self.hm.key`` for the Noise PSK
cache scope (``protocol.py``, ``cache_scope=self.hm.key`` and
``forget_cached_psk``). ``InProcessHiveShim.key`` first exists in hivescope
0.8.6a1, so this test raises ``AttributeError`` on 0.8.5a2 and passes from
0.8.6a1 up. That is the floor the ``e2e`` extra states.
"""

import pytest
from hivescope import TopologyBuilder

STRONG_PASSWORD = "correct-horse-battery-staple-92"


def test_in_process_satellite_handshakes_through_the_shim():
    """The shim completes the handshake and reports the access key as scope."""
    b = TopologyBuilder()
    m = b.add_master("M0")
    sat = b.add_satellite("S0", m)
    sat.identity.password = STRONG_PASSWORD
    try:
        b.start_all()

        assert sat.wait_for_handshake(timeout=10), "in-process handshake did not complete"
        assert sat.shim.handshake_event.is_set()

        # The PSK cache scope the slave protocol reads. Without it the
        # handshake above raises AttributeError instead of completing.
        assert sat.shim.key == sat.identity.access_key
        assert sat.shim.key, "the shim reports an empty access key"

        # An encrypted session is live. This path negotiates protocol v3, so
        # the slave protocol reports an established Noise session and the
        # pattern it settled on.
        assert sat.slave_protocol._noise_established, "no Noise session"
        assert sat.slave_protocol._noise_pattern, "no Noise pattern recorded"
    finally:
        b.stop_all()


def test_the_shim_exposes_the_key_the_slave_protocol_reads():
    """A named check on the floor, so a hivescope downgrade fails loudly.

    ``key`` is the attribute this repository raised the floor for. On
    hivescope 0.8.5a2 the class has no ``key`` and this test names the
    reason instead of leaving an ``AttributeError`` deep in the handshake.
    """
    from hivescope.node import InProcessHiveShim

    assert isinstance(getattr(InProcessHiveShim, "key", None), property), (
        "InProcessHiveShim has no key property; hivescope>=0.8.6a1 is required"
    )
