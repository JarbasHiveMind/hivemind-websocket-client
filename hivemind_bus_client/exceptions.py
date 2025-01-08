
class UnsupportedProtocolVersion(ValueError):
    """ Specified protocol version is not supported """


class HiveMindException(Exception):
    """ An Exception inside the HiveMind"""


class UnauthorizedKeyError(HiveMindException):
    """ Invalid Key provided """


class InvalidCipher(HiveMindException):
    """unknown encryption scheme requested"""


class InvalidEncoding(HiveMindException):
    """unknown encoding scheme requested"""


class InvalidKeySize(HiveMindException):
    """ Encryption Key size does not obey specification"""


class WrongEncryptionKey(HiveMindException):
    """ Wrong Encryption Key"""


class DecryptionKeyError(WrongEncryptionKey):
    """ Could not decrypt payload """


class EncryptionKeyError(WrongEncryptionKey):
    """ Could not encrypt payload """


class HiveMindConnectionError(ConnectionError, HiveMindException):
    """ Could not connect to the HiveMind"""


class SecureConnectionFailed(HiveMindConnectionError):
    """ Could not connect by SSL """


class HiveMindEntryPointNotFound(HiveMindConnectionError):
    """ can not connect to provided address """


class DecodingError(HiveMindException):
    """Exception raised for errors in decoding"""


class Z85DecodeError(DecodingError):
    """Exception raised for errors in decoding Z85b."""

