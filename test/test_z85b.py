import unittest
from hivemind_bus_client.encodings import Z85B
from hivemind_bus_client.exceptions import Z85DecodeError


class TestZ85B(unittest.TestCase):
    def test_encode_empty(self):
        """Test encoding an empty byte sequence."""
        self.assertEqual(Z85B.encode(b''), b'')
        self.assertEqual(Z85B.encode(''), b'')

    def test_decode_empty(self):
        """Test decoding an empty string."""
        self.assertEqual(Z85B.decode(''), b'')
        self.assertEqual(Z85B.decode(b''), b'')

    def test_encode_single_byte(self):
        """Test encoding a single byte."""
        self.assertEqual(b'A', Z85B.decode(Z85B.encode(b'A')))
        self.assertEqual(b'B', Z85B.decode(Z85B.encode('B')))
        self.assertEqual(b'_~', Z85B.decode(Z85B.encode(b'_~')))
        self.assertEqual(b'_~', Z85B.decode(Z85B.encode('_~')))

    def test_encode_short_string(self):
        """Test encoding a short string."""
        self.assertEqual(b'hello', Z85B.decode(Z85B.encode(b'hello')))
        self.assertEqual(b'Hello World', Z85B.decode(Z85B.encode(b'Hello World')))

    def test_encode_decode_round_trip(self):
        """Test encoding and decoding round-trip."""
        data = b'The quick brown fox jumps over the lazy dog.'
        encoded = Z85B.encode(data)
        decoded = Z85B.decode(encoded)
        self.assertEqual(decoded, data)

    def test_encode_unicode_string(self):
        """Test encoding a Unicode string."""
        data = 'こんにちは'  # Japanese for "hello"
        encoded = Z85B.encode(data)
        decoded = Z85B.decode(encoded)
        self.assertEqual(decoded.decode('utf-8'), data)

    def test_decode_invalid_character(self):
        """Test decoding with invalid Base91 characters."""
        with self.assertRaises(Z85DecodeError):
            Z85B.decode('Invalid🎉Chars')

    def test_edge_case_88_threshold(self):
        """Test edge cases around the 88 threshold."""
        data = b'\x00\x00\x00'  # Minimal data
        encoded = Z85B.encode(data)
        self.assertEqual(Z85B.decode(encoded), data)

    def test_encode_large_data(self):
        """Test encoding a large byte sequence."""
        data = b'\xff' * 1000
        encoded = Z85B.encode(data)
        decoded = Z85B.decode(encoded)
        self.assertEqual(decoded, data)


if __name__ == '__main__':
    unittest.main()
