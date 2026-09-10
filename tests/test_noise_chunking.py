"""Adversarial unit tests for multi-frame Noise transport chunking.

A single Noise transport message caps at 65535 bytes, so a HiveMessage
larger than that is split, encrypted, sent as several in-order Noise messages
and reassembled by the receiver. These tests exercise the SINGLE fast path
(wire-identical to the pre-chunking behavior), the exact size boundaries, the
multi-megabyte audio-sized round trips, every malformed-sequence error path,
the bounded reassembly cap, and concurrent sends through a shared fake wire.
"""

import threading
import unittest

from poorman_handshake.noise import derive_psk

from hivemind_bus_client.noise import (
    CHUNK_SIZE,
    NOISE_PATTERN_XX,
    NOISE_SUITE_CHACHA,
    NoiseTransport,
    NoiseTransportFailed,
    _FRAME_BINARY,
    _FRAME_JSON,
    build_prologue,
    noise_protocol_name,
    start_noise_handshake,
)


def _pair(max_reassembly_bytes=None):
    prologue = build_prologue(
        {"node_id": "server"}, {"max_protocol_version": 3},
        noise_protocol_name(NOISE_PATTERN_XX, NOISE_SUITE_CHACHA))
    common = dict(pattern=NOISE_PATTERN_XX, suite=NOISE_SUITE_CHACHA,
                  node_id="server")
    alice = start_noise_handshake(initiator=True, password="s3cr3t",
                                  prologue=prologue, **common)
    bob = start_noise_handshake(initiator=False, password="s3cr3t",
                                prologue=prologue, **common)
    m1 = alice.write_message(b"hi")
    bob.read_message(m1)
    m2 = bob.write_message(b"ho")
    alice.read_message(m2)
    m3 = alice.write_message(b"")
    bob.read_message(m3)
    kw = {} if max_reassembly_bytes is None else {
        "max_reassembly_bytes": max_reassembly_bytes}
    return NoiseTransport(alice, **kw), NoiseTransport(bob, **kw)


def _send_recv(sender, receiver, payload):
    """Send payload through sender.send_message into a list, feed every wire
    frame to receiver.decrypt_frame, and return the single reassembled value."""
    wire = []
    sender.send_message(payload, wire.append)
    out = [receiver.decrypt_frame(f) for f in wire]
    completed = [m for m in out if m is not None]
    assert len(completed) == 1, f"expected 1 message, got {len(completed)}"
    return wire, completed[0]


class TestSingleFrameUnchanged(unittest.TestCase):
    def test_small_json_is_one_single_frame(self):
        ta, tb = _pair()
        wire, msg = _send_recv(ta, tb, '{"msg_type": "bus"}')
        self.assertEqual(len(wire), 1)
        self.assertEqual(msg, '{"msg_type": "bus"}')

    def test_small_binary_is_one_single_frame(self):
        ta, tb = _pair()
        wire, msg = _send_recv(ta, tb, b"\x00\x01binary")
        self.assertEqual(len(wire), 1)
        self.assertEqual(msg, b"\x00\x01binary")

    def test_send_message_single_matches_encrypt_frame_marker(self):
        # a message that fits stays wire-identical to encrypt_frame: the
        # decrypted plaintext still begins with the SINGLE marker
        ta, tb = _pair()
        wire = []
        ta.send_message("x", wire.append)
        self.assertEqual(len(wire), 1)
        plain = tb._hs.decrypt(wire[0])
        self.assertEqual(plain[:1], _FRAME_JSON)

    def test_send_message_single_binary_marker(self):
        ta, tb = _pair()
        wire = []
        ta.send_message(b"x", wire.append)
        plain = tb._hs.decrypt(wire[0])
        self.assertEqual(plain[:1], _FRAME_BINARY)


class TestSizeBoundaries(unittest.TestCase):
    def test_payload_exactly_chunk_size_is_single(self):
        ta, tb = _pair()
        payload = "a" * CHUNK_SIZE
        wire, msg = _send_recv(ta, tb, payload)
        self.assertEqual(len(wire), 1)
        self.assertEqual(msg, payload)

    def test_payload_chunk_size_plus_one_splits(self):
        ta, tb = _pair()
        payload = "a" * (CHUNK_SIZE + 1)
        wire, msg = _send_recv(ta, tb, payload)
        self.assertEqual(len(wire), 2)
        self.assertEqual(msg, payload)

    def test_payload_exact_multiple_of_chunk_size(self):
        ta, tb = _pair()
        for n in (2, 3):
            payload = b"b" * (CHUNK_SIZE * n)
            wire, msg = _send_recv(ta, tb, payload)
            self.assertEqual(len(wire), n)
            self.assertEqual(msg, payload)

    def test_payload_multiple_plus_one(self):
        ta, tb = _pair()
        payload = b"c" * (CHUNK_SIZE * 3 + 1)
        wire, msg = _send_recv(ta, tb, payload)
        self.assertEqual(len(wire), 4)
        self.assertEqual(msg, payload)


class TestLargeRoundTrip(unittest.TestCase):
    def test_300kb_json_round_trip(self):
        ta, tb = _pair()
        payload = ("z" * 300_000)
        _, msg = _send_recv(ta, tb, payload)
        self.assertEqual(msg, payload)
        self.assertIsInstance(msg, str)

    def test_5mb_binary_round_trip_byte_identical(self):
        ta, tb = _pair()
        payload = bytes(bytearray((i * 131 + 7) % 256
                                  for i in range(5 * 1024 * 1024 // 1)))[:5_000_000]
        wire, msg = _send_recv(ta, tb, payload)
        self.assertGreater(len(wire), 70)
        self.assertEqual(msg, payload)
        self.assertIsInstance(msg, bytes)

    def test_5mb_json_round_trip(self):
        ta, tb = _pair()
        payload = "".join(chr(0x40 + (i % 26)) for i in range(5_000_000))
        _, msg = _send_recv(ta, tb, payload)
        self.assertEqual(msg, payload)


class TestMalformedSequences(unittest.TestCase):
    def test_more_with_no_open_buffer(self):
        ta, tb = _pair()
        with ta._send_lock:
            more = ta._hs.encrypt(b"\x04payload")
        with self.assertRaises(NoiseTransportFailed) as cm:
            tb.decrypt_frame(more)
        self.assertIn("MORE", str(cm.exception))

    def test_last_with_no_open_buffer(self):
        ta, tb = _pair()
        with ta._send_lock:
            last = ta._hs.encrypt(b"\x05payload")
        with self.assertRaises(NoiseTransportFailed) as cm:
            tb.decrypt_frame(last)
        self.assertIn("LAST", str(cm.exception))

    def test_first_while_buffer_open(self):
        # frames crafted directly so the receive nonces stay contiguous; the
        # second FIRST arrives before the first message's LAST
        ta, tb = _pair()
        with ta._send_lock:
            frame0 = ta._hs.encrypt(b"\x02open")       # FIRST-JSON, opens buffer
            frame1 = ta._hs.encrypt(b"\x02newmsg")     # FIRST again, illegal
        self.assertIsNone(tb.decrypt_frame(frame0))
        with self.assertRaises(NoiseTransportFailed) as cm:
            tb.decrypt_frame(frame1)
        self.assertIn("previous one", str(cm.exception))

    def test_single_while_buffer_open(self):
        ta, tb = _pair()
        with ta._send_lock:
            frame0 = ta._hs.encrypt(b"\x02open")               # FIRST, opens buffer
            frame1 = ta._hs.encrypt(_FRAME_JSON + b"interrupt")  # SINGLE, illegal
        self.assertIsNone(tb.decrypt_frame(frame0))
        with self.assertRaises(NoiseTransportFailed) as cm:
            tb.decrypt_frame(frame1)
        self.assertIn("still buffered", str(cm.exception))

    def test_unknown_marker(self):
        ta, tb = _pair()
        with ta._send_lock:
            bad = ta._hs.encrypt(b"\x7fpayload")
        with self.assertRaises(NoiseTransportFailed) as cm:
            tb.decrypt_frame(bad)
        self.assertIn("unknown", str(cm.exception))


class TestReassemblyCap(unittest.TestCase):
    def test_cap_exceeded_rejects_and_resets(self):
        # a 200 KB cap; a ~400 KB message must be rejected mid-reassembly
        ta, tb = _pair(max_reassembly_bytes=200_000)
        payload = b"d" * 400_000
        wire = []
        ta.send_message(payload, wire.append)
        raised = False
        try:
            for f in wire:
                tb.decrypt_frame(f)
        except NoiseTransportFailed as e:
            raised = True
            self.assertIn("cap", str(e))
        self.assertTrue(raised, "cap was not enforced")
        # buffer was reset: a fresh small message still works if nonces align
        self.assertIsNone(tb._reasm)


class TestConcurrency(unittest.TestCase):
    def test_two_threads_serialize_and_do_not_corrupt(self):
        # one sender, two threads each sending a distinct large payload into a
        # shared thread-safe wire; because send_message holds _send_lock for a
        # whole message, each message's chunks stay contiguous and in order,
        # so the receiver reassembles both intact.
        ta, tb = _pair()
        pa = b"A" * (CHUNK_SIZE * 3 + 5)
        pb = b"B" * (CHUNK_SIZE * 2 + 9)
        wire = []
        wire_lock = threading.Lock()

        def sink(frame):
            with wire_lock:
                wire.append(frame)

        def send(p):
            ta.send_message(p, sink)

        t1 = threading.Thread(target=send, args=(pa,))
        t2 = threading.Thread(target=send, args=(pb,))
        t1.start(); t2.start(); t1.join(); t2.join()

        # decrypt in wire order; two complete messages must come out, each the
        # exact payload (never interleaved bytes)
        results = []
        for f in wire:
            m = tb.decrypt_frame(f)
            if m is not None:
                results.append(m)
        self.assertEqual(len(results), 2)
        self.assertEqual(set(results), {pa, pb})


if __name__ == "__main__":
    unittest.main()
