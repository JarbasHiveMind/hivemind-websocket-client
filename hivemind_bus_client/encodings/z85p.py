from typing import Union
import struct

class Z85P:
    """
    Z85 is a class that provides encoding and decoding methods for transforming raw bytes into the Z85 encoding format.
    Z85 encoding represents 32-bit chunks of input bytes into a base85-encoded string with padding applied.
    The padding is added to ensure the encoded data's length is a multiple of 4 characters.
    The first byte of the encoded data indicates how many padding characters were added, which can be removed during decoding.
    """
    Z85CHARS = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
    Z85MAP = {c: idx for idx, c in enumerate(Z85CHARS)}

    _85s = [85 ** i for i in range(5)][::-1]

    @classmethod
    def encode(cls, rawbytes: Union[str, bytes]) -> bytes:
        """
        Encodes raw bytes into Z85 encoding format with padding, and prepends the padding size.

        Args:
            rawbytes (Union[str, bytes]): The input raw bytes to be encoded.

        Returns:
            bytes: The Z85-encoded byte sequence with appropriate padding and padding size indication.

        Notes:
            The padding is applied to ensure the length of the encoded data is a multiple of 5. The first byte in the
            returned byte sequence represents the number of padding characters added.
        """
        if isinstance(rawbytes, str):
            rawbytes = rawbytes.encode("utf-8")

        padding = (4 - len(rawbytes) % 4) % 4  # Padding to make the length a multiple of 4
        rawbytes += b'\x00' * padding

        # The first byte indicates how many padding characters were added
        nvalues = len(rawbytes) // 4
        values = struct.unpack('>%dI' % nvalues, rawbytes)
        encoded = [padding]

        for v in values:
            for offset in cls._85s:
                encoded.append(cls.Z85CHARS[(v // offset) % 85])

        return bytes(encoded)

    @classmethod
    def decode(cls, z85bytes: Union[str, bytes]) -> bytes:
        """
        Decodes a Z85-encoded byte sequence back into raw bytes, removing padding as indicated by the first byte.

        Args:
            z85bytes (Union[str, bytes]): The Z85-encoded byte sequence to be decoded.

        Returns:
            bytes: The decoded raw byte sequence with padding removed.

        Raises:
            ValueError: If the length of the input data is not divisible by 5 or contains invalid Z85 encoding.

        Notes:
            The first byte of the encoded data indicates the padding size, and this padding is removed during decoding.
        """
        if isinstance(z85bytes, str):
            z85bytes = z85bytes.encode("utf-8")

        if len(z85bytes) == 0:
            return z85bytes

        if len(z85bytes) % 5 != 1:
            raise ValueError('Invalid data length, should be divisible by 5 with 1 extra byte for padding indicator.')

        padding = z85bytes[0]  # Read the padding size from the first byte
        if padding < 0 or padding > 4:
            raise ValueError('Padding size must be between 0 and 4.')

        z85bytes = z85bytes[1:]  # Remove the first byte (padding size byte)

        values = []
        for i in range(0, len(z85bytes), 5):
            value = 0
            for j, offset in enumerate(cls._85s):
                value += cls.Z85MAP[z85bytes[i + j]] * offset
            values.append(value)

        decoded = struct.pack('>%dI' % len(values), *values)
        return decoded[:-padding] if padding else decoded  # Remove padding
