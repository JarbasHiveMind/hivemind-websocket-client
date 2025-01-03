import unittest
from hivemind_bus_client.encodings.z85p import Z85P


class TestZ85P(unittest.TestCase):
    def test_encode_empty(self):
        """Test encoding an empty byte sequence."""
        self.assertEqual(Z85P.encode(b''), b'\x00')
        self.assertEqual(Z85P.encode(''), b'\x00')

    def test_decode_empty(self):
        """Test decoding an empty string."""
        self.assertEqual(Z85P.decode(b'\x00'), b'')
        self.assertEqual(Z85P.decode(''), b'')
        self.assertEqual(Z85P.decode(b''), b'')

    def test_encode_single_byte(self):
        """Test encoding a single byte."""
        self.assertEqual(b'A', Z85P.decode(Z85P.encode(b'A')))
        self.assertEqual(b'B', Z85P.decode(Z85P.encode('B')))
        self.assertEqual(b'_~', Z85P.decode(Z85P.encode(b'_~')))
        self.assertEqual(b'_~', Z85P.decode(Z85P.encode('_~')))

    def test_encode_short_string(self):
        """Test encoding a short string."""
        self.assertEqual(b'hello', Z85P.decode(Z85P.encode(b'hello')))

    def test_encode_decode_round_trip(self):
        """Test encoding and decoding round-trip."""
        data = b'The quick brown fox jumps over the lazy dog.'
        encoded = Z85P.encode(data)
        decoded = Z85P.decode(encoded)
        self.assertEqual(decoded, data)

    def test_encode_unicode_string(self):
        """Test encoding a Unicode string."""
        data = 'こんにちは'  # Japanese for "hello"
        encoded = Z85P.encode(data)
        decoded = Z85P.decode(encoded)
        self.assertEqual(decoded.decode('utf-8'), data)

    def test_decode_invalid_character(self):
        """Test decoding with invalid z85 characters."""
        with self.assertRaises(ValueError):
            Z85P.decode('Invalid🎉Chars')

    def test_encode_large_data(self):
        """Test encoding a large byte sequence."""
        data = b'\xff' * 1000
        encoded = Z85P.encode(data)
        decoded = Z85P.decode(encoded)
        self.assertEqual(decoded, data)

    def test_padding_single_byte(self):
        """Test encoding and decoding with one byte that requires padding."""
        data = b'\x01'  # Single byte, should get padded with 3 \x00 bytes
        encoded = Z85P.encode(data)
        self.assertEqual(encoded[0], 3)  # Check padding byte
        self.assertEqual(Z85P.decode(encoded), data)

    def test_padding_two_bytes(self):
        """Test encoding and decoding with two bytes that require padding."""
        data = b'\x01\x01'  # Two bytes, should get padded with 2 \x00 bytes
        encoded = Z85P.encode(data)
        self.assertEqual(encoded[0], 2)  # Check padding byte
        self.assertEqual(Z85P.decode(encoded), data)

    def test_padding_three_bytes(self):
        """Test encoding and decoding with three bytes that require padding."""
        data = b'\x01\x01\x01'  # Three bytes, should get padded with 1 \x00 byte
        encoded = Z85P.encode(data)
        self.assertEqual(encoded[0], 1)  # Check padding byte
        self.assertEqual(Z85P.decode(encoded), data)

    def test_no_padding_5_bytes(self): # fails
        data = b'\x01\x01\x01\x01\x01'  # 5 bytes
        encoded = Z85P.encode(data)
        self.assertEqual(encoded[0], 3)  # Check padding byte
        self.assertEqual(Z85P.decode(encoded), data)

    def test_no_padding_needed(self):
        """Test encoding and decoding with data that doesn't need padding."""
        data = b'\x01\x01\x01\x01'  # Exactly 4 bytes, no padding
        encoded = Z85P.encode(data)
        self.assertEqual(encoded[0], 0)  # No padding
        self.assertEqual(Z85P.decode(encoded), data)

    def test_round_trip_padding(self):
        """Test round-trip encoding and decoding with padding."""
        data = b'\x01\x01\x01'  # Less than 4 bytes, needs padding
        encoded = Z85P.encode(data)
        decoded = Z85P.decode(encoded)
        self.assertEqual(decoded, data)  # Ensure padding is correctly removed

    def test_padding_removal_after_decoding(self):
        """Test ensuring padding is correctly removed after decoding."""
        data = b'\x01\x01\x01'  # Less than 4 bytes, needs padding
        encoded = Z85P.encode(data)
        self.assertEqual(encoded[0], 1)  # Padding size is 1
        decoded = Z85P.decode(encoded)
        self.assertEqual(decoded, data)  # Padding should be removed

if __name__ == '__main__':
    unittest.main()
