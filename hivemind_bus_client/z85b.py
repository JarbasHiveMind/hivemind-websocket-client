"""
Python implementation of Z85b 85-bit encoding.

Z85b is a variation of ZMQ RFC 32 Z85 85-bit encoding with the following differences:
1. Little-endian encoding (to facilitate alignment with lower byte indices).
2. No requirement for a multiple of 4/5 length.
3. `decode_z85b()` eliminates whitespace from the input.
4. `decode_z85b()` raises a clear exception if invalid characters are encountered.

This file is a derivative work of z85.py from pyzmq.

Copyright (c) 2013 Brian Granger, Min Ragan-Kelley
Distributed under the terms of the New BSD License.
"""
import re
import struct
from typing import Union

from hivemind_bus_client.exceptions import Z85DecodeError


class Z85B:
    # Z85CHARS is the base 85 symbol table
    Z85CHARS = bytearray(b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")

    # Z85MAP maps integers in [0, 84] to the appropriate character in Z85CHARS
    Z85MAP = {char: idx for idx, char in enumerate(Z85CHARS)}

    # Powers of 85 for encoding/decoding
    _85s = [85 ** i for i in range(5)]

    # Padding lengths for encoding and decoding
    _E_PADDING = [0, 3, 2, 1]
    _D_PADDING = [0, 4, 3, 2, 1]

    @classmethod
    def encode(cls, rawbytes: Union[str, bytes]) -> bytes:
        """
        Encode raw bytes into Z85b format.

        Args:
            rawbytes (Union[str, bytes]): Input data to encode.

        Returns:
            bytes: Z85b-encoded bytes.
        """
        rawbytes = bytearray(rawbytes) if isinstance(rawbytes, (bytes, str)) else rawbytes
        padding = cls._E_PADDING[len(rawbytes) % 4]
        rawbytes += b'\x00' * padding
        nvalues = len(rawbytes) // 4

        # Pack the raw bytes into little-endian 32-bit integers
        values = struct.unpack(f'<{nvalues}I', rawbytes)
        encoded = bytearray()

        for value in values:
            for offset in cls._85s:
                encoded.append(cls.Z85CHARS[(value // offset) % 85])

        # Remove padding characters from the encoded output
        if padding:
            encoded = encoded[:-padding]
        return bytes(encoded)

    @classmethod
    def decode(cls, z85bytes: Union[str, bytes]) -> bytes:
        """
        Decode Z85b-encoded bytes into raw bytes.

        Args:
            z85bytes (Union[str, bytes]): Z85b-encoded data.

        Returns:
            bytes: Decoded raw bytes.

        Raises:
            Z85DecodeError: If invalid characters are encountered during decoding.
        """
        # Normalize input by removing whitespace
        z85bytes = bytearray(re.sub(rb'\s+', b'', z85bytes if isinstance(z85bytes, bytes) else z85bytes.encode()))
        padding = cls._D_PADDING[len(z85bytes) % 5]
        nvalues = (len(z85bytes) + padding) // 5

        values = []
        for i in range(0, len(z85bytes), 5):
            value = 0
            for j, offset in enumerate(cls._85s):
                try:
                    value += cls.Z85MAP[z85bytes[i + j]] * offset
                except IndexError:
                    break  # End of input reached
                except KeyError as e:
                    raise Z85DecodeError(f"Invalid byte code: {e.args[0]!r}")
            values.append(value)

        # Unpack the values back into raw bytes
        decoded = struct.pack(f'<{nvalues}I', *values)

        # Remove padding from the decoded output
        if padding:
            decoded = decoded[:-padding]
        return decoded
