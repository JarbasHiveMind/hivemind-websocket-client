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


def _provision_shared():
    shared = NodeIdentity()
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


def test_without_an_app_name_nothing_changes(home):
    shared = _provision_shared()
    with patch("hivemind_bus_client.identity.LOG.warning") as warning:
        plain = NodeIdentity()
    assert plain.IDENTITY_FILE.path == shared.IDENTITY_FILE.path
    assert plain.uses_shared_fallback is False
    warning.assert_not_called()


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


def test_a_cli_read_with_app_uses_the_fallback(home):
    from hivemind_bus_client.scripts import hmclient_cmds
    _provision_shared()
    with patch("hivemind_bus_client.scripts.NodeIdentity", wraps=NodeIdentity) as ctor:
        CliRunner().invoke(hmclient_cmds, ["--app", "voice-sat", "forget-server", "--host", "x"])
    ctor.assert_called_once_with(app_name="voice-sat", shared_fallback=True)
