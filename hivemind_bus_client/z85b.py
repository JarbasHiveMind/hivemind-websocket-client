import warnings

from hivemind_bus_client.encodings.z85b import Z85B

# Deprecation warning
warnings.warn(
    "Importing Z85B from hivemind_bus_client.z85b is deprecated and will be removed in a future release. "
    "Please update your code to use the new import path 'from hivemind_bus_client.encodings.z85b'.",
    DeprecationWarning,
    stacklevel=2,
)