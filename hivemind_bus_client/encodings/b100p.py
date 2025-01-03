from typing import Union


class B100P:
    """
    B100P is a class that provides encoding and decoding methods for transforming text into an emoji-based representation
    with a custom padding mechanism. The first byte of the encoded data indicates how many padding bytes were added
    during encoding, which is then removed during decoding.

    The padding is added to make the data length a multiple of 4, and the padding size is included as part of the encoded data.
    When decoding, the padding size is read from the first byte and used to strip the padding from the decoded data.
    """

    @classmethod
    def encode(cls, data: Union[str, bytes], encoding: str = "utf-8") -> bytes:
        """
        Encodes text into an emoji representation with padding, and prepends the padding size.

        Args:
            data (Union[str, bytes]): The input text to be encoded. This can either be a string (plaintext) or bytes.
            encoding (str): The encoding to use if `data` is provided as a string. Default is 'utf-8'.

        Returns:
            bytes: The emoji-encoded byte sequence with appropriate padding and padding size indication.

        Notes:
            The padding is applied to ensure the length of the encoded data is a multiple of 4. The first byte in the
            returned byte sequence represents the number of padding bytes added. This allows for proper decoding with
            padding removal.
        """
        if isinstance(data, str):
            data = data.encode(encoding)

        padding = (4 - len(data) % 4) % 4  # Padding to make the length a multiple of 4
        data += b'\x00' * padding

        # The first byte indicates how many padding bytes were added
        encoded_data = [padding] + [240, 159, 0, 0] * len(data)

        for i, b in enumerate(data):
            encoded_data[4 * i + 3] = (b + 55) // 64 + 143
            encoded_data[4 * i + 4] = (b + 55) % 64 + 128

        return bytes(encoded_data)

    @classmethod
    def decode(cls, encoded_data: Union[str, bytes], encoding: str = "utf-8") -> bytes:
        """
        Decodes an emoji representation back into text, removing padding as indicated by the first byte.

        Args:
            encoded_data (Union[str, bytes]): The emoji-encoded byte sequence or string to be decoded.
            encoding (str): The encoding to use if `encoded_data` is provided as a string. Default is 'utf-8'.

        Returns:
            bytes: The decoded byte sequence of text with padding removed.

        Raises:
            ValueError: If the length of the input data is not divisible by 4 or contains invalid emoji encoding.

        Notes:
            The first byte of the encoded data indicates the padding size, and this padding is removed during decoding.
        """
        if isinstance(encoded_data, str):
            encoded_data = encoded_data.encode(encoding)

        if len(encoded_data) == 0:
            return encoded_data

        # Ensure the length of data is divisible by 4 (with 1 extra byte for padding size)
        if len(encoded_data) % 4 != 1:
            raise ValueError('Invalid data length, should be divisible by 4 with 1 extra byte for padding indicator.')

        padding = encoded_data[0]  # Read the padding size from the first byte
        if padding < 0 or padding > 3:
            raise ValueError('Padding size must be between 0 and 3.')

        # Extract the actual encoded data (excluding the padding size byte)
        encoded_data = encoded_data[1:]

        tmp = 0
        out = [None] * (len(encoded_data) // 4)

        for i, b in enumerate(encoded_data):
            if i % 4 == 2:
                tmp = ((b - 143) * 64) % 256
            elif i % 4 == 3:
                out[i // 4] = (b - 128 + tmp - 55) & 0xff

        # Return decoded bytes, removing the indicated padding
        decoded = bytes(out)
        return decoded[:-padding] if padding else decoded  # Remove the padding
