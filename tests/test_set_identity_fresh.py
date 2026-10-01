"""`hivemind-client set-identity` on an identity that has no master yet.

A first `set-identity --key K --password P` with no `--host` raised
`AttributeError: 'NoneType' object has no attribute 'startswith'`: the
command normalised `host or identity.default_master`, and a fresh identity
has neither. The credentials were never saved.
"""
import os
import tempfile
from unittest.mock import patch

from click.testing import CliRunner
from json_database import JsonStorage

from hivemind_bus_client import scripts
from hivemind_bus_client.identity import NodeIdentity


def _fresh(tmpdir):
    store = JsonStorage(os.path.join(tmpdir, "identity.json"), disable_lock=True)
    return NodeIdentity(identity_file=store)


def _run(identity, args):
    with patch.object(scripts, "NodeIdentity", return_value=identity), \
         patch.object(scripts, "clear_cached_psks"):
        return CliRunner().invoke(scripts.hmclient_cmds, ["set-identity"] + args)


def test_credentials_without_a_host_are_saved_on_a_fresh_identity():
    with tempfile.TemporaryDirectory() as tmpdir:
        identity = _fresh(tmpdir)
        result = _run(identity, ["--key", "k", "--password", "correct-horse-battery-staple"])
        assert result.exit_code == 0, result.output
        saved = NodeIdentity(identity_file=JsonStorage(identity.IDENTITY_FILE.path, disable_lock=True))
        assert saved.access_key == "k"
        assert saved.password == "correct-horse-battery-staple"
        assert saved.default_master is None
        assert saved.default_port == 5678


def test_a_host_alone_is_enough_and_gets_a_scheme():
    with tempfile.TemporaryDirectory() as tmpdir:
        identity = _fresh(tmpdir)
        result = _run(identity, ["--host", "hub.local"])
        assert result.exit_code == 0, result.output
        assert identity.default_master == "ws://hub.local"


def test_a_stored_host_survives_a_credentials_update():
    with tempfile.TemporaryDirectory() as tmpdir:
        identity = _fresh(tmpdir)
        identity.default_master = "wss://hub.local"
        identity.save()
        result = _run(identity, ["--key", "k2"])
        assert result.exit_code == 0, result.output
        assert identity.default_master == "wss://hub.local"
        assert identity.access_key == "k2"


def test_nothing_to_set_is_still_refused():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _run(_fresh(tmpdir), [])
        assert result.exit_code != 0
        assert isinstance(result.exception, ValueError)
