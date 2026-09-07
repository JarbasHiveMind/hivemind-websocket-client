"""The HTTP client must advertise protocol v3 like the websocket client.

HiveMindSlaveProtocol._should_use_noise() reads the ceiling off the client:

    if getattr(self.hm, "max_protocol_version", 2) < PROTOCOL_V3:
        return False

HiveMindHTTPClient never set the attribute, so that getattr fell back to 2
and every HTTP client silently declined the Noise handshake. Against a
HiveMind-core 5.x server -- where v3 Noise is the only transport crypto and
there is no legacy fallback -- the connection can never complete: the
handshake offer arrives carrying "noise", the client ignores it, and the
session hangs until it times out.
"""

import inspect

from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.http_client import HiveMindHTTPClient


def test_http_client_accepts_max_protocol_version():
    assert "max_protocol_version" in inspect.signature(
        HiveMindHTTPClient.__init__
    ).parameters


def test_http_and_websocket_clients_default_to_the_same_ceiling():
    http = inspect.signature(HiveMindHTTPClient.__init__).parameters[
        "max_protocol_version"
    ].default
    ws = inspect.signature(HiveMessageBusClient.__init__).parameters[
        "max_protocol_version"
    ].default
    assert http == ws == 3


def test_getattr_fallback_no_longer_caps_the_http_client_at_v2():
    """The exact read _should_use_noise() performs."""
    client = HiveMindHTTPClient.__new__(HiveMindHTTPClient)
    client.max_protocol_version = inspect.signature(
        HiveMindHTTPClient.__init__
    ).parameters["max_protocol_version"].default
    assert getattr(client, "max_protocol_version", 2) >= 3


def test_the_ceiling_is_still_lowerable_for_legacy_servers():
    assert (
        inspect.signature(HiveMindHTTPClient.__init__)
        .parameters["max_protocol_version"]
        .kind
        is not inspect.Parameter.POSITIONAL_ONLY
    )
