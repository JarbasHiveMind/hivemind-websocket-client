import unittest
from hivemind_bus_client.encodings import B91


class TestB91(unittest.TestCase):
    def test_encode_empty(self):
        """Test encoding an empty byte sequence."""
        self.assertEqual(B91.encode(b''), b'')
        self.assertEqual(B91.encode(''), b'')

    def test_decode_empty(self):
        """Test decoding an empty string."""
        self.assertEqual(B91.decode(''), b'')
        self.assertEqual(B91.decode(b''), b'')

    def test_encode_single_byte(self):
        """Test encoding a single byte."""
        self.assertEqual(b'A', B91.decode(B91.encode(b'A')))
        self.assertEqual(b'B', B91.decode(B91.encode('B')))
        self.assertEqual(b'_~', B91.decode(B91.encode(b'_~')))
        self.assertEqual(b'_~', B91.decode(B91.encode('_~')))

    def test_encode_short_string(self):
        """Test encoding a short string."""
        self.assertEqual(b'hello', B91.decode(B91.encode(b'hello')))
        self.assertEqual(B91.decode('>OwJh>Io0Tv!lE'), b'Hello World')

    def test_encode_decode_round_trip(self):
        """Test encoding and decoding round-trip."""
        data = b'The quick brown fox jumps over the lazy dog.'
        encoded = B91.encode(data)
        decoded = B91.decode(encoded)
        self.assertEqual(decoded, data)

    def test_encode_unicode_string(self):
        """Test encoding a Unicode string."""
        data = 'こんにちは'  # Japanese for "hello"
        encoded = B91.encode(data)
        decoded = B91.decode(encoded)
        self.assertEqual(decoded.decode('utf-8'), data)

    def test_decode_invalid_character(self):
        """Test decoding with invalid Base91 characters."""
        with self.assertRaises(ValueError):
            B91.decode('Invalid🎉Chars')

    def test_3bytes_threshold(self):
        """Test edge cases around the 88 threshold."""
        data = b'\x00\x00\x00'  # Minimal data
        encoded = B91.encode(data)
        self.assertEqual(B91.decode(encoded), data)

    def test_encode_large_data(self):
        """Test encoding a large byte sequence."""
        data = b'\xff' * 1000
        encoded = B91.encode(data)
        decoded = B91.decode(encoded)
        self.assertEqual(decoded, data)


if __name__ == '__main__':
    unittest.main()
