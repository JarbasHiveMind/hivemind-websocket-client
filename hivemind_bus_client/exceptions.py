
class UnsupportedProtocolVersion(ValueError):
    """ Specified protocol version is not supported """


class MetadataTooLarge(ValueError):
    """ Metadata block does not fit the 8-bit length field of a binary frame """


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


class MalformedBinaryFrame(DecodingError, ValueError):
    """A WIRE-1 §4 binary frame that cannot be decoded: truncated, a
    metadata length past the end of the frame, an unassigned message-type
    code, or a metadata or payload block that is not what the header says."""


class Z85DecodeError(DecodingError):
    """Exception raised for errors in decoding Z85b."""



class IdentityFileCorrupted(HiveMindException):
    """ The identity file exists but could not be read """
