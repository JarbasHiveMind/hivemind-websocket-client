"""The access key must not cross an untrusted network in the clear.

Every request this client makes carries the access key in the query string,
where Noise does not reach: Noise protects the frame body, not the URL.
"""
import socket
from unittest.mock import patch

import pytest

from hivemind_bus_client.http_client import HiveMindHTTPClient


def _resolves_to(*addresses):
    """Patch name resolution to answer with exactly these addresses."""
    return patch.object(
        socket, "getaddrinfo",
        lambda host, *a, **k: [(None, None, None, "", (addr, 0)) for addr in addresses],
    )


def _client(host, port=5678, **kwargs):
    client = HiveMindHTTPClient.__new__(HiveMindHTTPClient)
    client._host = host
    client._port = port
    client.allow_insecure_http = kwargs.get("allow_insecure_http", False)
    return client


@pytest.mark.parametrize("host", [
    "wss://hive.example.com",       # TLS to anywhere is fine
    "ws://127.0.0.1",               # loopback never leaves the machine
    "ws://[::1]",
    "ws://192.168.1.40",            # the LAN satellite case this protocol exists for
    "ws://10.0.0.5",
    "ws://172.16.3.9",
    "ws://169.254.10.10",           # link-local
])
def test_ip_literals_and_tls_need_no_resolution(host):
    # a literal answers for itself; resolving one would be a lie waiting to happen
    with patch.object(socket, "getaddrinfo", side_effect=AssertionError("resolved a literal")):
        assert _client(host).base_url.startswith(("http://", "https://"))


@pytest.mark.parametrize("host", ["ws://hub.local", "ws://hub.lan", "ws://hub.internal"])
def test_a_local_looking_name_is_allowed_only_if_it_resolves_locally(host):
    with _resolves_to("192.168.1.40"):
        assert _client(host).base_url.startswith("http://")


@pytest.mark.parametrize("host", ["ws://hub.local", "ws://hub.lan", "ws://hub.internal"])
def test_a_local_looking_name_that_resolves_remotely_is_refused(host):
    """The finding: a name is not evidence of where it points."""
    with _resolves_to("93.184.216.34"):
        with pytest.raises(ValueError, match="cleartext"):
            _ = _client(host).base_url


def test_one_public_answer_among_local_ones_is_enough_to_refuse():
    """That is the address the connection may actually use."""
    with _resolves_to("192.168.1.40", "93.184.216.34"):
        with pytest.raises(ValueError, match="cleartext"):
            _ = _client("ws://hub.lan").base_url


def test_a_name_that_cannot_be_resolved_is_refused():
    """An unanswered question about where the key goes is not a yes."""
    with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("nope")):
        with pytest.raises(ValueError, match="cleartext"):
            _ = _client("ws://hub.lan").base_url


@pytest.mark.parametrize("host", ["ws://8.8.8.8", "ws://1.1.1.1"])
def test_cleartext_to_a_public_address_is_refused(host):
    with pytest.raises(ValueError, match="cleartext"):
        _ = _client(host).base_url


def test_cleartext_to_a_public_name_is_refused():
    with _resolves_to("93.184.216.34"):
        with pytest.raises(ValueError, match="cleartext"):
            _ = _client("ws://hive.example.com").base_url


@pytest.mark.parametrize("host", ["ws://hive.example.com", "ws://8.8.8.8"])
def test_the_risk_can_be_accepted_deliberately(host):
    client = _client(host, allow_insecure_http=True)
    assert client.base_url.startswith("http://")


def test_the_guard_sees_the_port_not_a_hostname():
    """The port must not be mistaken for part of the host when deciding."""
    assert _client("ws://192.168.1.40", port=8080).base_url == "http://192.168.1.40:8080"
    with pytest.raises(ValueError, match="cleartext"):
        _ = _client("ws://hive.example.com", port=8080).base_url


def test_no_credential_bearing_request_follows_a_redirect():
    """A hub answering HTTPS with an HTTP Location would move the key onto
    cleartext after the transport check had already passed."""
    import pathlib
    source = pathlib.Path(
        HiveMindHTTPClient.__module__.replace(".", "/") + ".py"
    )
    if not source.exists():
        import hivemind_bus_client.http_client as module
        source = pathlib.Path(module.__file__)
    lines = source.read_text().splitlines()
    uncovered = [
        index + 1
        for index, line in enumerate(lines)
        if 'params={"authorization": self.auth}' in line
        and "allow_redirects=False" not in "\n".join(lines[max(0, index - 3):index + 4])
    ]
    assert not uncovered, f"credential-bearing requests follow redirects at lines {uncovered}"
