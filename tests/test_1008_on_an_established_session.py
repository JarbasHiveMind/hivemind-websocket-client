"""A 1008 on an established session is not a credential refusal.

The clients latched ``_auth_rejected`` on close code 1008 alone and stopped
reconnecting, logging "HiveMind refused this identity ... Check the access
key and password ... Not reconnecting."

hivemind-core sends 1008 from seven sites, and only some are identity-bound.
Read from ``origin/dev`` and grouped by the function that sends them:

* ``decode()`` sends it for a non-Noise message on a v3 session, an invalid
  Noise transport message, and an unencrypted message when crypto is
  required. All three need an ADMITTED connection to reach, so the
  credentials were accepted before the frame that triggers them.
* ``handle_new_client`` (protocol v3 required), ``_abort_noise_handshake``
  (which is the only caller of ``handle_invalid_key_connected``) and
  ``_finish_noise_handshake`` (pinned-key mismatch) all send it at
  connection or handshake time, before a session exists.

So one malformed or unencrypted message took a CORRECTLY REGISTERED
satellite off the mesh permanently and blamed its access key.

The split is read from the connection state, not from the reason text.
HIVEMIND-TRANSPORT-1 §2.2 makes a retryable refusal machine-readable through
a STABLE reason string (``connection_limit``) precisely so that "a peer that
cannot tell the two apart retries a rejected key forever". The three
``decode()`` reasons are free prose and no peer should parse them.

Moving the non-identity cases to their own close code is the other fix, and
it is a wire change, so it is not taken here.
"""
import unittest
from unittest.mock import MagicMock, patch


def _sync_client():
    """A HiveMessageBusClient with just enough state for on_close."""
    from hivemind_bus_client.client import HiveMessageBusClient

    client = HiveMessageBusClient.__new__(HiveMessageBusClient)
    import threading
    client.handshake_event = threading.Event()
    client.connected_event = threading.Event()
    client._auth_rejected = None
    # This helper stubs _clear_connection_state, which is why it could not
    # see T-5102: the REAL clear wipes handshake_event, and on_error runs it
    # before on_close. The class at the end of this file drives that order
    # with the real one. Left as it is, deliberately.
    client.emitter = MagicMock()
    client._clear_connection_state = MagicMock()
    client.close = MagicMock()
    client._failed_kk_retry_pending = lambda: False
    client.client = type("_Socket", (), {})()
    return client


class TestTheSyncClientOnClose(unittest.TestCase):

    def test_1008_before_the_handshake_still_latches(self):
        """The real credential refusal must keep working."""
        client = _sync_client()  # handshake_event not set
        client.on_close(client.client, 1008, "invalid authorization")
        self.assertEqual(client._auth_rejected, "invalid authorization")
        client.emitter.emit.assert_any_call("auth_rejected",
                                            "invalid authorization")

    def test_1008_on_an_established_session_does_not_latch(self):
        """The defect. This used to unregister a valid satellite."""
        client = _sync_client()
        client.handshake_event.set()
        client.on_close(client.client, 1008,
                        "invalid Noise transport message (tampered, "
                        "replayed or out-of-order)")
        self.assertIsNone(client._auth_rejected)
        emitted = [c.args[0] for c in client.emitter.emit.call_args_list]
        self.assertNotIn("auth_rejected", emitted)
        self.assertIn("close", emitted)

    def test_an_ordinary_close_is_unchanged(self):
        client = _sync_client()
        client.handshake_event.set()
        client.on_close(None, 1000, "goodbye")
        self.assertIsNone(client._auth_rejected)


class TestTheFrameLevelCheck(unittest.TestCase):
    """``_is_auth_rejection`` reads the CLOSE frame before on_close runs."""

    def _frame(self, code, reason=b""):
        from websocket import ABNF
        frame = MagicMock()
        frame.opcode = ABNF.OPCODE_CLOSE
        frame.data = bytes([code >> 8, code & 0xFF]) + reason
        return frame

    def test_1008_before_the_handshake_is_a_rejection(self):
        client = _sync_client()
        self.assertTrue(
            client._is_auth_rejection(self._frame(1008, b"invalid authorization")))
        self.assertEqual(client._auth_rejected, "invalid authorization")

    def test_1008_on_an_established_session_is_not_a_rejection(self):
        client = _sync_client()
        client.handshake_event.set()
        self.assertFalse(
            client._is_auth_rejection(
                self._frame(1008, b"unencrypted message rejected: crypto is "
                                  b"required")))
        self.assertIsNone(client._auth_rejected)

    def test_a_non_1008_close_is_not_a_rejection(self):
        client = _sync_client()
        self.assertFalse(client._is_auth_rejection(self._frame(1000, b"bye")))


# TestEverySiteIsGuarded, which asserted that `inspect.getsource` of each
# latch site CONTAINS the token "handshake_event", was deleted here. It passed
# on broken code: reviewer-d changed the guard to
# `if False and self.handshake_event.is_set():`, which keeps the token and
# loses the behaviour, and the run was 1 failed 9 passed with all three of its
# subtests green.
#
# The comment that first stood here said all three sites it named are covered
# behaviourally. That was FALSE for the async one, and reviewer-d measured it
# per site rather than taking the claim: mutating the sync guard fails five
# rows here, removing the socket mark fails five, but forcing
# async_client._receive_loop's `session_was_established` to False left the
# whole set green. Every async 1008 row set `connected_event` and never
# `handshake_event`, so they covered the never-established branch only.
# tests/test_async_client.py now carries a row that sets the handshake first,
# and it is the one that fails on that mutation.


def _sync_client_with_the_real_clear():
    """A client whose ``_clear_connection_state`` is the REAL one.

    The class above stubs it with a MagicMock, and that is why it could not
    see this: the real clear is what wipes ``handshake_event``, and
    websocket-client delivers a close to ``on_error`` BEFORE ``on_close``.
    """
    from hivemind_bus_client.client import HiveMessageBusClient
    import threading

    client = HiveMessageBusClient.__new__(HiveMessageBusClient)
    client.handshake_event = threading.Event()
    client.connected_event = threading.Event()
    client._auth_rejected = None
    client.crypto_key = None
    client.noise_transport = None
    client.protocol = None
    client.emitter = MagicMock()
    client.close = MagicMock()
    client._failed_kk_retry_pending = lambda: False
    # The established fact is stamped on the SOCKET, so the fixture needs one.
    # A plain object stands in for the WebSocketApp, which is all the code
    # under test reads it as.
    client.client = type("_Socket", (), {})()
    return client


class TestTheCloseArrivesThroughOnErrorFirst(unittest.TestCase):
    """The live stage's finding on #294 (T-5102).

    On a real hub the disconnect reaches ``on_error`` with an exception
    first. That path calls ``_clear_connection_state()``, which clears
    ``handshake_event``; teardown then calls ``on_close(1008)``, where the
    guard read ``handshake_event.is_set()`` as False and latched
    ``_auth_rejected`` on a session whose credentials had been accepted.
    """

    def test_a_protocol_1008_after_on_error_does_not_latch(self):
        from websocket import WebSocketConnectionClosedException

        client = _sync_client_with_the_real_clear()
        client.handshake_event.set()          # the session IS established
        client.connected_event.set()

        # websocket-client's own order: the exception first ...
        client.on_error(None, WebSocketConnectionClosedException("closed"))
        self.assertFalse(client.handshake_event.is_set(),
                         "precondition: on_error clears the handshake event")

        # ... then the close, with the code the hub sent
        client.on_close(client.client, 1008,
                        "non-Noise message received on a protocol v3 session")

        self.assertIsNone(client._auth_rejected,
                          "a protocol error on an established session must "
                          "not be read as a credential refusal")
        client.emitter.emit.assert_any_call("close")
        for call in client.emitter.emit.call_args_list:
            self.assertNotEqual(call.args[0], "auth_rejected")
        client.close.assert_not_called()

    def test_a_credential_1008_after_on_error_still_latches(self):
        """The control. A refusal BEFORE any handshake must still latch, or
        the fix above would simply have disabled the latch."""
        from websocket import WebSocketConnectionClosedException

        client = _sync_client_with_the_real_clear()
        # no handshake_event.set(): the credentials were never accepted
        client.on_error(None, WebSocketConnectionClosedException("closed"))
        client.on_close(client.client, 1008, "invalid authorization")

        self.assertEqual(client._auth_rejected, "invalid authorization")
        client.emitter.emit.assert_any_call("auth_rejected",
                                            "invalid authorization")

    def test_the_flag_does_not_survive_into_the_next_connection(self):
        """A session that WAS established, then a reconnect whose credentials
        are refused. Reading the previous connection here would make a real
        refusal reconnect forever."""
        from websocket import WebSocketConnectionClosedException

        client = _sync_client_with_the_real_clear()
        client.handshake_event.set()
        client.on_error(None, WebSocketConnectionClosedException("closed"))
        client.on_close(client.client, 1008, "non-Noise message")
        self.assertIsNone(client._auth_rejected)

        # The reconnect. run_forever builds a NEW WebSocketApp for each
        # attempt (client.py: `self.client = self.create_client()`), so a
        # fresh socket is what "the next connection" means; on_open alone was
        # the right model only while the fact was a field on the client.
        client.client = type("_Socket", (), {})()
        client.on_error(None, WebSocketConnectionClosedException("closed"))
        client.on_close(client.client, 1008, "invalid authorization")

        self.assertEqual(client._auth_rejected, "invalid authorization")


class TestTheFactSurvivesASecondClear(unittest.TestCase):
    """reviewer-d's finding on the first version of this fix.

    `_clear_connection_state` ASSIGNED the fact to a field on the client, so a
    SECOND clear before `on_close` overwrote it with False and the 1008
    latched again. Two clears is not exotic: `on_error` runs one and the
    reconnect lifecycle runs another before teardown reaches `on_close`.

    Latching the field with `or` fixes that one case and breaks another: a hub
    that refuses the websocket UPGRADE closes with no `on_open` at all, so
    nothing resets a per-client field and a genuinely refused key reconnects
    for ever. The fact therefore lives on the SOCKET — one clear or ten cannot
    downgrade it, and the next connection is a new object.
    """

    def test_two_clears_before_on_close_still_do_not_latch(self):
        from websocket import WebSocketConnectionClosedException

        client = _sync_client_with_the_real_clear()
        client.handshake_event.set()
        client.connected_event.set()

        client.on_error(None, WebSocketConnectionClosedException("closed"))
        client._clear_connection_state()          # the second clear
        client.on_close(client.client, 1008, "non-Noise message")

        self.assertIsNone(client._auth_rejected,
                          "a second clear must not turn an established "
                          "session back into a credential refusal")

    def test_a_refusal_on_a_fresh_socket_still_latches(self):
        """The case an `or`-latched field broke: no `on_open` to reset it."""
        client = _sync_client_with_the_real_clear()
        client.handshake_event.set()
        client.on_error(None, Exception("closed"))
        client.on_close(client.client, 1008, "non-Noise message")
        self.assertIsNone(client._auth_rejected)

        # the reconnect builds a NEW WebSocketApp, and this time the upgrade
        # is refused, so on_open never runs
        client.client = type("_Socket", (), {})()
        client.on_close(client.client, 1008, "invalid authorization")
        self.assertEqual(client._auth_rejected, "invalid authorization")

    def test_the_mark_is_on_the_socket_and_not_on_the_client(self):
        """States where the fact lives, so a field cannot creep back in."""
        client = _sync_client_with_the_real_clear()
        client.handshake_event.set()
        client._clear_connection_state()

        self.assertTrue(getattr(client.client,
                                "_hivemind_session_was_established", False))
        self.assertFalse(getattr(client, "_session_was_established", False),
                         "the fact must not be a field on the client")


class TestTheCloseCallbackIsCalledWithNoSocket(unittest.TestCase):
    """`on_close(None, 1008, ...)` must read the same as `on_close(ws, ...)`.

    The guard took `args[0]` whenever any argument was passed, so a caller
    that passes None as the ws handed it None; the fallback to
    `handshake_event` then read False, because `on_error` had already cleared
    it, and the 1008 latched again. Measured before the fix:

        ws=the socket -> _auth_rejected = None
        ws=None       -> _auth_rejected = 'non-Noise message on a v3 session'

    websocket-client 1.9.2 always passes the app, but it is a transitive
    dependency here and the callback signature is not ours to rely on.
    """

    def test_a_none_websocket_argument_reads_the_current_socket(self):
        from websocket import WebSocketConnectionClosedException

        client = _sync_client_with_the_real_clear()
        client.handshake_event.set()
        client.connected_event.set()
        client.on_error(None, WebSocketConnectionClosedException("closed"))

        client.on_close(None, 1008, "non-Noise message on a v3 session")

        self.assertIsNone(client._auth_rejected,
                          "a close callback with no socket must not turn an "
                          "established session into a credential refusal")

    def test_a_socket_that_invents_attributes_does_not_read_as_established(self):
        """The mark is read with `is True`, not as a truth test.

        A MagicMock — or any proxy that auto-creates attributes — answers a
        getattr for an attribute nobody set with something TRUTHY. Read as a
        boolean, this guard then believed a session had been established when
        it never was, which fails OPEN: a genuinely refused key stops latching
        and retries for ever. Two rows in tests/test_client.py caught exactly
        this.
        """
        client = _sync_client_with_the_real_clear()
        client.client = MagicMock()          # invents any attribute asked for
        # no handshake: the credentials were never accepted on this connection
        client.on_close(client.client, 1008, "invalid authorization")

        self.assertEqual(client._auth_rejected, "invalid authorization")
