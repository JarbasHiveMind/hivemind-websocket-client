"""NodeIdentity(app_name=...): one identity per application (HIVEMIND-CRYPTO-1 §2).

§2: an implementation that stores identities for its caller MUST locate them
per application by default, keyed on a name the application supplies. Before
this change NodeIdentity took no application name, so every application of a
user shared ~/.config/hivemind/_identity.json and presented one identifier and
one static key.

This step only adds the name. NodeIdentity() without one still uses the shared
file; the default changes after the consumers pass their names.
"""
from os.path import dirname, join
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from hivemind_bus_client.identity import NodeIdentity


@pytest.fixture(autouse=True)
def _own_config_home(tmp_path, monkeypatch):
    # the box running the tests may hold a shared identity file, and a named
    # application with no file of its own reads it (see
    # test_identity_shared_fallback.py); these tests are about the paths
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("HOME", str(tmp_path))


def test_an_app_name_gives_the_application_its_own_identity_file():
    a = NodeIdentity(app_name="voice-sat")
    b = NodeIdentity(app_name="deltachat-bridge")
    assert a.IDENTITY_FILE.path.endswith(join("hivemind", "voice-sat", "_identity.json"))
    assert b.IDENTITY_FILE.path.endswith(join("hivemind", "deltachat-bridge", "_identity.json"))
    assert a.app_name == "voice-sat"


def test_keys_of_an_application_are_kept_next_to_its_own_identity_file():
    identity = NodeIdentity(app_name="voice-sat")
    folder = dirname(identity.IDENTITY_FILE.path)
    assert dirname(identity.private_key) == folder
    assert dirname(identity.noise_key) == folder


def test_without_an_app_name_the_shared_file_is_still_used():
    identity = NodeIdentity()
    assert identity.IDENTITY_FILE.path.endswith(join("hivemind", "_identity.json"))
    assert identity.app_name is None


@pytest.mark.parametrize("bad", ["", ".", "..", "../voice-sat", "a/b", "a\\b",
                                 "-lead", "x" * 65, "sat\n"])
def test_an_app_name_that_is_not_one_plain_path_segment_is_refused(bad):
    with pytest.raises(ValueError):
        NodeIdentity(app_name=bad)


def test_an_identity_file_and_an_app_name_together_are_refused(tmp_path):
    from json_database import JsonStorage
    with pytest.raises(ValueError):
        NodeIdentity(identity_file=JsonStorage(str(tmp_path / "id.json")), app_name="voice-sat")


@pytest.mark.parametrize("args, expected", [
    (["--app", "voice-sat", "forget-server", "--host", "hub"],
     {"app_name": "voice-sat", "shared_fallback": True}),
    (["forget-server", "--host", "hub"], {}),      # no --app: the call is unchanged
])
def test_the_cli_app_option_selects_the_application_identity(args, expected):
    from hivemind_bus_client import scripts
    with patch.object(scripts, "NodeIdentity") as node_identity:
        node_identity.return_value.forget_noise_key.return_value = False
        node_identity.return_value.pinned_noise_keys = {}
        result = CliRunner().invoke(scripts.hmclient_cmds, args)
    assert result.exit_code == 0, result.output
    node_identity.assert_called_once_with(**expected)


@pytest.mark.parametrize("command, extra", [
    ("terminal", []),
    ("escalate", ["--msg", "speak", "--payload", "{}"]),
    ("propagate", ["--msg", "speak", "--payload", "{}"]),
    ("ping", []),
])
def test_connecting_commands_hand_the_application_identity_to_the_client(command, extra):
    """The client must present the application's own Noise key and pin store.

    The four commands read key, password and host from the --app identity.
    Without ``identity=`` the client fell back to NodeIdentity(), the shared
    file, and presented the shared static key under the application's access
    key (HIVEMIND-CRYPTO-1 §2 forbids one key under two access keys).
    """
    from hivemind_bus_client import scripts
    with patch.object(scripts, "NodeIdentity") as node_identity, \
         patch.object(scripts, "HiveMessageBusClient") as client:
        identity = node_identity.return_value
        identity.access_key = "sat-key"
        identity.password = "correct-horse-battery-staple-92"
        identity.default_master = "ws://hub"
        identity.default_port = 5678
        identity.site_id = "site"
        identity.name = "voice-sat"
        client.return_value.connected_event.wait.return_value = False
        client.return_value.handshake_event.wait.return_value = False
        result = CliRunner().invoke(scripts.hmclient_cmds,
                                    ["--app", "voice-sat", command] + extra)
    node_identity.assert_called_once_with(app_name="voice-sat", shared_fallback=True)
    assert client.called, result.output
    assert client.call_args.kwargs.get("identity") is identity, (
        f"{command} built the client without the application identity: "
        f"{client.call_args}")
