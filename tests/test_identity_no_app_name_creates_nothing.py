"""``NodeIdentity()`` with no app_name never creates the shared file.

HIVEMIND-CRYPTO-1 §2, from JarbasHiveMind/architecture:

    An implementation that stores identities for its caller MUST locate them
    per application by default, keyed on a name the application supplies, and
    MUST NOT default to a location shared by every application of the same
    user. Sharing one identity across applications is a provisioning choice a
    deployer makes explicitly, never a default.

Stage 3 of T-1832, Miro's ruling A. The shared
``~/.config/hivemind/_identity.json`` is still READ when it exists, because a
deployer who provisioned one made exactly the explicit choice §2 allows. What
stops is the library creating one on first run.

Three behaviours, and the middle one is the whole point:

* shared file exists, no app_name -> read it, warn, saving to it still works
* shared file absent, no app_name -> warn, and ``save()`` REFUSES rather
  than creating it
* app_name given -> the application's own file, and the shared path is left
  alone

``save()`` raises rather than doing nothing. A silent no-op would let
``set-identity`` report success while storing no credentials, which is worse
than the error: the operator would find out at the next handshake.
"""
import json
import os
from os.path import isfile, join
from unittest.mock import patch

import pytest

from hivemind_bus_client.identity import NodeIdentity


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _shared_path(home):
    return join(str(home), "config", "hivemind", "_identity.json")


def _provision_shared(home, **values):
    """Write the shared file the way a deployer does, without the library."""
    path = _shared_path(home)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(values or {"password": "deployer-set"}, f)
    return path


class TestNoAppNameAndNoSharedFile:

    def test_save_refuses_instead_of_creating_it(self, home):
        identity = NodeIdentity()
        assert identity.refuses_to_create_shared is True
        identity.password = "pw"
        with pytest.raises(ValueError) as caught:
            identity.save()
        assert "refusing to create" in str(caught.value)
        assert not isfile(_shared_path(home)), "the shared file was created"

    def test_the_refusal_names_the_clause_and_both_fixes(self, home):
        """An operator hitting this must learn what to do, not just that it failed."""
        identity = NodeIdentity()
        with pytest.raises(ValueError) as caught:
            identity.save()
        said = str(caught.value)
        assert "HIVEMIND-CRYPTO-1 §2" in said
        assert "app_name" in said       # the per-application fix
        assert "--shared" in said       # the deliberate-sharing fix

    def test_the_warning_names_the_clause_and_app_name(self, home):
        with patch("hivemind_bus_client.identity.LOG.warning") as warning:
            NodeIdentity()
        warning.assert_called_once()
        said = warning.call_args[0][0]
        assert "HIVEMIND-CRYPTO-1 §2" in said
        assert "app_name" in said

    def test_create_keys_refuses_before_writing_the_private_key(self, home):
        """Found by the security audit on this change, not by the tests.

        create_keys() exports a private key PEM into the identity file's
        directory BEFORE anything is stored. Guarding only save() left
        HiveMindComs.pem, and the directory it made, sitting in the shared
        path that the refused save then declined to use: orphan key material
        in exactly the location §2 says not to default to.
        """
        identity = NodeIdentity()
        with pytest.raises(ValueError) as caught:
            identity.create_keys()
        assert "private key" in str(caught.value)
        shared_dir = join(str(home), "config", "hivemind")
        leftovers = os.listdir(shared_dir) if os.path.isdir(shared_dir) else []
        assert leftovers == [], f"left behind in the shared path: {leftovers}"

    def test_reading_still_works_and_creates_nothing(self, home):
        """Construction must not fail, only the write.

        Every client falls back to NodeIdentity(), so raising in the
        constructor would take down callers that never save.
        """
        identity = NodeIdentity()
        assert identity.name == "unnamed-node"
        assert identity.password is None
        assert not isfile(_shared_path(home))


class TestNoAppNameWithAProvisionedSharedFile:

    def test_it_is_read(self, home):
        _provision_shared(home, password="deployer-set")
        assert NodeIdentity().password == "deployer-set"

    def test_saving_to_it_still_works(self, home):
        """The deployer's provisioning choice must keep working.

        This is the documented `hivemind-client set-identity` flow. Refusing
        the write as well would break every existing deployment, which ruling
        A explicitly did not want.
        """
        _provision_shared(home)
        identity = NodeIdentity()
        assert identity.refuses_to_create_shared is False
        identity.site_id = "site-1"
        identity.save()
        with open(_shared_path(home), encoding="utf-8") as f:
            assert json.load(f)["site_id"] == "site-1"


class TestANamedApplication:

    def test_it_gets_its_own_file_and_leaves_the_shared_path_alone(self, home):
        identity = NodeIdentity(app_name="voice-sat")
        identity.password = "pw"
        identity.save()
        own = join(str(home), "config", "hivemind", "voice-sat", "_identity.json")
        assert isfile(own)
        assert not isfile(_shared_path(home)), "a named app created the shared file"

    def test_it_does_not_refuse(self, home):
        assert NodeIdentity(app_name="voice-sat").refuses_to_create_shared is False


class TestTheFlagDefaultsSafely:
    """The flag makes ``save()`` raise, so its default must be the safe one."""

    def test_an_instance_built_without_init_does_not_refuse(self):
        """Hand-built instances exist in this suite and in callers.

        Without a class-level default, ``save()`` raised AttributeError on
        one, which is a worse failure than the one the flag exists to cause.
        """
        identity = NodeIdentity.__new__(NodeIdentity)
        assert identity.refuses_to_create_shared is False
