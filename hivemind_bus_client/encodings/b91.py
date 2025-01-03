from typing import Union


class B91:
    ALPHABET = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '#', '$',
        '%', '&', '(', ')', '*', '+', ',', '.', '/', ':', ';', '<', '=',
        '>', '?', '@', '[', ']', '^', '_', '`', '{', '|', '}', '~', '"'
    ]

    DECODE_TABLE = {char: idx for idx, char in enumerate(ALPHABET)}

    @classmethod
    def decode(cls, encoded_data: Union[str, bytes], encoding: str = "utf-8") -> bytes:
        """
        Decodes a Base91-encoded string into its original binary form.

        Args:
            encoded_data (Union[str, bytes]): Base91-encoded input data. If `bytes`, it is decoded as UTF-8.
            encoding (str): The encoding to use if `encoded_data` is provided as a string. Default is 'utf-8'.

        Returns:
            bytes: The decoded binary data.

        Raises:
            ValueError: If the input contains invalid Base91 characters.
        """
        if isinstance(encoded_data, bytes):
            encoded_data = encoded_data.decode(encoding)

        v = -1
        b = 0
        n = 0
        out = bytearray()

        for char in encoded_data:
            if char not in cls.DECODE_TABLE:
                raise ValueError(f"Invalid Base91 character: {char}")
            c = cls.DECODE_TABLE[char]
            if v < 0:
                v = c
            else:
                v += c * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n >= 8:
                    out.append(b & 255)
                    b >>= 8
                    n -= 8
                v = -1

        if v >= 0:
            out.append((b | v << n) & 255)

        return bytes(out)

    @classmethod
    def encode(cls, data: Union[bytes, str], encoding: str = "utf-8") -> bytes:
        """
        Encodes binary data into a Base91-encoded string.

        Args:
            data (Union[bytes, str]): Input binary data to encode. If `str`, it is encoded as UTF-8.
            encoding (str): The encoding to use if `data` is provided as a string. Default is 'utf-8'.

        Returns:
            str: The Base91-encoded string.
        """
        if isinstance(data, str):
            data = data.encode(encoding)

        b = 0
        n = 0
        out = []

        for byte in data:
            b |= byte << n
            n += 8
            if n > 13:
                v = b & 8191
                if v > 88:
                    b >>= 13
                    n -= 13
                else:
                    v = b & 16383
                    b >>= 14
                    n -= 14
                out.append(cls.ALPHABET[v % 91])
                out.append(cls.ALPHABET[v // 91])

        if n:
            out.append(cls.ALPHABET[b % 91])
            if n > 7 or b > 90:
                out.append(cls.ALPHABET[b // 91])

        return ''.join(out).encode(encoding)
