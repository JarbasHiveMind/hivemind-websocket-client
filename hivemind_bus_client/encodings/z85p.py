from z85base91 import Z85P
import warnings

# Deprecation warning
warnings.warn(
    "Importing from hivemind_bus_client.encodings is deprecated and will be removed in a future release. "
    "Please update your code to use the new package 'z85base91'",
    DeprecationWarning,
    stacklevel=2,
)