"""
Python implementation of Z85b 85-bit encoding.

Z85b is a variation of ZMQ RFC 32 Z85 85-bit encoding with the following differences:
1. Little-endian encoding (to facilitate alignment with lower byte indices).
2. No requirement for a multiple of 4/5 length.
3. `decode_z85b()` eliminates whitespace from the input.
4. `decode_z85b()` raises a clear exception if invalid characters are encountered.

This file is a derivative work of https://gist.github.com/minrk/6357188?permalink_comment_id=2366506#gistcomment-2366506

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
    def encode(cls, data: Union[str, bytes], encoding: str = "utf-8") -> bytes:
        """
        Encode raw bytes into Z85b format.

        Args:
            data (Union[str, bytes]): Input data to encode.
            encoding (str): The encoding to use if `data` is provided as a string. Default is 'utf-8'.

        Returns:
            bytes: Z85b-encoded bytes.
        """
        if isinstance(data, str):
            data = data.encode(encoding)
        data = bytearray(data)
        padding = cls._E_PADDING[len(data) % 4]
        data += b'\x00' * padding
        nvalues = len(data) // 4

        # Pack the raw bytes into little-endian 32-bit integers
        values = struct.unpack(f'<{nvalues}I', data)
        encoded = bytearray()

        for value in values:
            for offset in cls._85s:
                encoded.append(cls.Z85CHARS[(value // offset) % 85])

        # Remove padding characters from the encoded output
        if padding:
            encoded = encoded[:-padding]
        return bytes(encoded)

    @classmethod
    def decode(cls, encoded_data: Union[str, bytes], encoding: str = "utf-8") -> bytes:
        """
        Decode Z85b-encoded bytes into raw bytes.

        Args:
            encoded_data (Union[str, bytes]): Z85b-encoded data.
            encoding (str): The encoding to use if `encoded_data` is provided as a string. Default is 'utf-8'.

        Returns:
            bytes: Decoded raw bytes.

        Raises:
            Z85DecodeError: If invalid characters are encountered during decoding.
        """
        # Normalize input by removing whitespace
        encoded_data = bytearray(re.sub(rb'\s+', b'',
                                        encoded_data if isinstance(encoded_data, bytes)
                                        else encoded_data.encode(encoding)))
        padding = cls._D_PADDING[len(encoded_data) % 5]
        nvalues = (len(encoded_data) + padding) // 5

        values = []
        for i in range(0, len(encoded_data), 5):
            value = 0
            for j, offset in enumerate(cls._85s):
                try:
                    value += cls.Z85MAP[encoded_data[i + j]] * offset
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
