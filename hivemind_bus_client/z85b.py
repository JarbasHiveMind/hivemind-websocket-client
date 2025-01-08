import warnings

from z85base91 import Z85B

# Deprecation warning
warnings.warn(
    "Importing Z85B from hivemind_bus_client.z85b is deprecated and will be removed in a future release. "
    "Please update your code to use the new package 'z85base91'",
    DeprecationWarning,
    stacklevel=2,
)