"""A named application on a box provisioned with the shared identity file.

HIVEMIND-CRYPTO-1 §2 wants one identity per application. Every deployment
so far was provisioned with ``hivemind-client set-identity``, which writes
the shared ``~/.config/hivemind/_identity.json``. When an application starts
to name itself, that box has no file for the name, and without a fallback
the application starts as ``unnamed-node`` with no password and no server.

So a named application whose own file does not exist reads the shared file
when that one exists, and logs a warning that says how to move. A write with
``--app`` never lands in the shared file, and the shared file is never
created by a named application.
"""
from os.path import join, isfile
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from hivemind_bus_client.identity import NodeIdentity


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _shared_store():
    """The shared file addressed explicitly, as a deployer now must.

    ``NodeIdentity()`` no longer creates it: HIVEMIND-CRYPTO-1 §2 forbids
    defaulting to a location shared by every application of the user, so
    provisioning it is a deliberate act. This is the route
    ``hivemind-client set-identity --shared`` takes.
    """
    from json_database import JsonConfigXDG
    from ovos_utils.xdg_utils import xdg_config_home
    return JsonConfigXDG("_identity", subfolder="hivemind",
                         xdg_folder=str(xdg_config_home()))


def _provision_shared():
    shared = NodeIdentity(identity_file=_shared_store())
    shared.name = "old-sat"
    shared.password = "hunter2"
    shared.access_key = "key"
    shared.save()
    return shared


def test_a_named_app_without_its_own_file_reads_the_shared_one(home):
    shared = _provision_shared()
    with patch("hivemind_bus_client.identity.LOG.warning") as warning:
        named = NodeIdentity(app_name="voice-sat")
    assert named.IDENTITY_FILE.path == shared.IDENTITY_FILE.path
    assert named.uses_shared_fallback is True
    assert (named.name, named.password, named.access_key) == ("old-sat", "hunter2", "key")
    message = warning.call_args.args[0]
    assert "voice-sat" in message and "CRYPTO-1" in message
    assert "hivemind-client --app voice-sat set-identity" in message


def test_a_named_app_with_its_own_file_ignores_the_shared_one(home):
    _provision_shared()
    own = NodeIdentity(app_name="voice-sat", shared_fallback=False)
    own.name = "new-sat"
    own.save()
    with patch("hivemind_bus_client.identity.LOG.warning") as warning:
        named = NodeIdentity(app_name="voice-sat")
    assert named.IDENTITY_FILE.path.endswith(join("hivemind", "voice-sat", "_identity.json"))
    assert named.uses_shared_fallback is False
    assert named.name == "new-sat"
    warning.assert_not_called()


def test_without_a_shared_file_a_named_app_gets_its_own_path_and_creates_no_shared_file(home):
    with patch("hivemind_bus_client.identity.LOG.warning") as warning:
        named = NodeIdentity(app_name="voice-sat")
    assert named.IDENTITY_FILE.path.endswith(join("hivemind", "voice-sat", "_identity.json"))
    assert named.uses_shared_fallback is False
    warning.assert_not_called()
    named.name = "sat"
    named.save()
    assert not isfile(NodeIdentity().IDENTITY_FILE.path)


def test_shared_fallback_false_keeps_the_application_path(home):
    _provision_shared()
    named = NodeIdentity(app_name="voice-sat", shared_fallback=False)
    assert named.IDENTITY_FILE.path.endswith(join("hivemind", "voice-sat", "_identity.json"))
    assert named.uses_shared_fallback is False
    assert named.password is None


def test_without_an_app_name_the_shared_file_is_read_and_warned_about(home):
    """Stage 3 changed this: the read stays, the silence does not.

    An existing shared file is still read, because a deployer provisioning
    one is the explicit choice HIVEMIND-CRYPTO-1 §2 allows. What is new is
    that it says so, and names the fix.
    """
    shared = _provision_shared()
    with patch("hivemind_bus_client.identity.LOG.warning") as warning:
        plain = NodeIdentity()
    assert plain.IDENTITY_FILE.path == shared.IDENTITY_FILE.path
    assert plain.uses_shared_fallback is False
    # reading an existing shared file is allowed, so nothing is refused
    assert plain.refuses_to_create_shared is False
    warning.assert_called_once()
    said = warning.call_args[0][0]
    assert "HIVEMIND-CRYPTO-1 §2" in said
    assert "app_name" in said


@pytest.mark.parametrize("command", [
    ["set-identity", "--password", "new-pw", "--host", "hub.local"],
    ["reset-pgp"],
])
def test_a_cli_write_with_app_lands_in_the_application_file(home, command):
    from hivemind_bus_client.scripts import hmclient_cmds
    shared = _provision_shared()
    before = dict(shared.IDENTITY_FILE)
    result = CliRunner().invoke(hmclient_cmds, ["--app", "voice-sat"] + command)
    assert result.exit_code == 0, result.output
    own = join("hivemind", "voice-sat", "_identity.json")
    assert own in result.output
    assert isfile(NodeIdentity(app_name="voice-sat", shared_fallback=False).IDENTITY_FILE.path)
    assert dict(NodeIdentity().IDENTITY_FILE) == before


def test_forget_server_under_the_fallback_says_the_pin_is_shared(home):
    from hivemind_bus_client.scripts import hmclient_cmds
    shared = _provision_shared()
    shared.pin_noise_key("hub.local:5678", "aa" * 32)
    shared.save()
    result = CliRunner().invoke(hmclient_cmds, ["--app", "voice-sat", "forget-server",
                                                "--host", "hub.local", "--port", "5678"])
    assert result.exit_code == 0, result.output
    assert "voice-sat has no identity file of its own" in result.output
    assert "checked by every application on this box" in result.output
    assert "forgot pinned key for hub.local:5678" in result.output
    # the pin is gone from the shared file: that is the shared state, said out loud
    assert NodeIdentity().pinned_noise_keys == {}


def test_forget_server_with_an_own_file_prints_no_shared_line(home):
    from hivemind_bus_client.scripts import hmclient_cmds
    _provision_shared()
    own = NodeIdentity(app_name="voice-sat", shared_fallback=False)
    own.pin_noise_key("hub.local:5678", "bb" * 32)
    own.save()
    result = CliRunner().invoke(hmclient_cmds, ["--app", "voice-sat", "forget-server",
                                                "--host", "hub.local", "--port", "5678"])
    assert result.exit_code == 0, result.output
    assert "shared" not in result.output


def test_a_cli_read_with_app_uses_the_fallback(home):
    from hivemind_bus_client.scripts import hmclient_cmds
    _provision_shared()
    with patch("hivemind_bus_client.scripts.NodeIdentity", wraps=NodeIdentity) as ctor:
        CliRunner().invoke(hmclient_cmds, ["--app", "voice-sat", "forget-server", "--host", "x"])
    ctor.assert_called_once_with(app_name="voice-sat", shared_fallback=True)
