"""A handshake retry must not downgrade before the server's offer arrives.

``wait_for_handshake`` waits for ``handshake_event`` and, on timeout, calls
``protocol.start_handshake()`` to resend. Under a burst of satellites against
one listener on one IOLoop, the server's HANDSHAKE offer for one of them is
still in flight when that timer fires.

``start_handshake`` used to read:

    if self._server_handshake_payload and self._should_use_noise(...):
        self.start_noise_handshake(...)
        return
    self._legacy_start_handshake(self._server_handshake_payload or {}, retry=True)

With no offer yet, ``_server_handshake_payload`` is ``None``, so the guarded
branch was skipped and the legacy call ran with ``{}``. That sends a protocol
v2 pubkey handshake decided on NO evidence about the peer, and hivemind-core
5.x refuses it with 1008: HIVEMIND-CRYPTO-1 §3 makes Noise the only key
exchange and gives no legacy fallback.

That is the nightly red in hivemind-test-harness,
``test_listener_releases_every_client_after_a_burst``. Its log names one
``_legacy_start_handshake`` line for fifteen satellites, at
``protocol.py:786``, "hivemind does not support binarization protocol",
followed by a 1008 for that same satellite. The other satellites negotiate v3
normally.

The correction to the original classification: the downgrading client did not
read a server payload that was missing the v3 capability fields. It read no
payload at all. The server offers every satellite the same full payload; this
one had not received it yet.

Waiting is right because every caller of ``start_handshake`` is a bounded
retry loop that re-waits, in ``client.py``, ``async_client.py`` and
``http_client.py``. A peer that truly never offers ends in that loop's own
timeout, which reports the timeout instead of provoking a refusal.
"""
import unittest
from unittest.mock import MagicMock, patch

from hivemind_bus_client.protocol import HiveMindSlaveProtocol

#: a v3-capable server's offer, as ``handle_handshake`` stores it
V3_OFFER = {"max_protocol_version": 3,
            "noise": {"patterns": ["KK"], "suites": ["25519_ChaChaPoly_BLAKE2s"]},
            "binarize": True, "ciphers": ["AES_GCM"], "encodings": ["JSON_HEX"]}

#: a genuinely pre-v3 server's request
V2_REQUEST = {"max_protocol_version": 2, "password": True,
              "ciphers": ["AES_GCM"], "encodings": ["JSON_HEX"],
              "binarize": False}


def _protocol(server_payload):
    """A slave protocol positioned exactly as a retry finds it."""
    protocol = HiveMindSlaveProtocol.__new__(HiveMindSlaveProtocol)
    protocol._noise_established = False
    protocol.noise_handshake = None
    protocol._server_handshake_payload = server_payload
    protocol._server_hello_payload = {}
    protocol.binarize = False
    protocol.pswd_handshake = None
    protocol.handshake = MagicMock(pubkey="PUBKEY")
    protocol.hm = MagicMock(password="a password", max_protocol_version=3)
    protocol.identity = MagicMock()
    protocol.internal_protocol = MagicMock(node_id="node")
    return protocol


class TestTheRetryDoesNotDowngradeOnNoEvidence(unittest.TestCase):

    def _start(self, server_payload, v3_capable=True):
        taken = []
        with patch.object(HiveMindSlaveProtocol, "_legacy_start_handshake",
                          lambda self, *a, **k: taken.append("legacy")), \
             patch.object(HiveMindSlaveProtocol, "start_noise_handshake",
                          lambda self, *a, **k: taken.append("noise")), \
             patch.object(HiveMindSlaveProtocol, "_should_use_noise",
                          lambda self, payload: v3_capable):
            _protocol(server_payload).start_handshake()
        return taken

    def test_no_offer_yet_sends_nothing(self):
        """The burst case. It used to send the legacy handshake."""
        self.assertEqual(self._start(None), [])

    def test_a_v3_offer_starts_noise(self):
        self.assertEqual(self._start(V3_OFFER), ["noise"])

    def test_a_pre_v3_request_still_takes_the_legacy_path(self):
        """The downgrade is kept where there IS evidence for it.

        A real pre-v3 server must still be reachable, so the fix must not
        remove the legacy path, only the case that guesses at it.
        """
        self.assertEqual(self._start(V2_REQUEST, v3_capable=False), ["legacy"])

    def test_the_legacy_path_never_sees_an_empty_payload(self):
        """The defect's signature, read from the argument.

        ``_legacy_start_handshake({})`` is what built the v2 frame that drew
        the 1008, so assert on the payload and not only on which path ran.
        """
        seen = []
        with patch.object(HiveMindSlaveProtocol, "_legacy_start_handshake",
                          lambda self, payload, retry=False: seen.append(payload)), \
             patch.object(HiveMindSlaveProtocol, "_should_use_noise",
                          lambda self, payload: False):
            _protocol(None).start_handshake()
        self.assertEqual(seen, [], "a downgrade was decided on an empty payload")

    def test_an_established_session_still_sends_nothing(self):
        """Unchanged behaviour, kept as a control."""
        protocol = _protocol(V3_OFFER)
        protocol._noise_established = True
        with patch.object(HiveMindSlaveProtocol, "_legacy_start_handshake",
                          lambda self, *a, **k: self.fail("sent a handshake")), \
             patch.object(HiveMindSlaveProtocol, "start_noise_handshake",
                          lambda self, *a, **k: self.fail("sent a handshake")):
            protocol.start_handshake()

    def test_a_handshake_in_flight_still_sends_nothing(self):
        """Unchanged behaviour, kept as a control."""
        protocol = _protocol(V3_OFFER)
        protocol.noise_handshake = MagicMock()
        with patch.object(HiveMindSlaveProtocol, "_legacy_start_handshake",
                          lambda self, *a, **k: self.fail("sent a handshake")), \
             patch.object(HiveMindSlaveProtocol, "start_noise_handshake",
                          lambda self, *a, **k: self.fail("sent a handshake")):
            protocol.start_handshake()


class TestEveryRetryCallerRewaits(unittest.TestCase):
    """Waiting is only safe because no caller treats the send as mandatory.

    If a caller called ``start_handshake`` once and then blocked forever,
    returning without sending would hang instead of timing out.
    """

    def test_start_handshake_is_only_called_inside_a_bounded_loop(self):
        import inspect
        import re

        from hivemind_bus_client import async_client, client, http_client

        for module in (client, async_client, http_client):
            source = inspect.getsource(module)
            for match in re.finditer(r"^(\s*)self\.protocol\.start_handshake\(\)",
                                     source, re.M):
                with self.subTest(module=module.__name__):
                    before = source[:match.start()]
                    # the nearest enclosing block must be a loop that re-tests
                    # the handshake event
                    self.assertRegex(
                        before.split("def ")[-1],
                        r"while not self\.handshake_event\.is_set\(\)",
                        "start_handshake is called outside a re-waiting loop, "
                        "so returning without sending could hang")
