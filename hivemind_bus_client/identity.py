from os.path import basename, dirname

from json_database import JsonConfigXDG


class NodeIdentity:

    def __init__(self, identity_file=None):
        self.IDENTITY_FILE = identity_file or JsonConfigXDG("_identity", subfolder="hivemind")

    @property
    def name(self):
        """human readable label, not guaranteed unique
        can describe functionality, brand, capabilities or something else...
        """
        if not self.IDENTITY_FILE.get("name") and self.IDENTITY_FILE.get("key"):
            self.IDENTITY_FILE["name"] = basename(self.IDENTITY_FILE["key"])
        return self.IDENTITY_FILE.get("name") or "unnamed-node"

    @name.setter
    def name(self, val):
        self.IDENTITY_FILE["name"] = val

    @property
    def private_key(self):
        """path to PRIVATE .asc PGP key, this cryptographic key
        uniquely identifies this device across the hive and proves it's identity"""
        return self.IDENTITY_FILE.get("key") or \
            f"{dirname(self.IDENTITY_FILE.path)}/{self.name}.asc"

    @private_key.setter
    def private_key(self, val):
        self.IDENTITY_FILE["key"] = val

    @property
    def password(self):
        """password is used to generate a session aes key on handshake.
        It should be used instead of users manually setting an encryption key.
        This password can be thought as identifying a sub-hive where all devices
        can connect to each other (access keys still need to be valid)"""
        return self.IDENTITY_FILE.get("password")

    @password.setter
    def password(self, val):
        self.IDENTITY_FILE["password"] = val

    @property
    def access_key(self):
        return self.IDENTITY_FILE.get("access_key")

    @access_key.setter
    def access_key(self, val):
        self.IDENTITY_FILE["access_key"] = val

    @property
    def site_id(self):
        return self.IDENTITY_FILE.get("site_id")

    @site_id.setter
    def site_id(self, val):
        self.IDENTITY_FILE["site_id"] = val

    @property
    def default_master(self):
        return self.IDENTITY_FILE.get("default_master")

    @default_master.setter
    def default_master(self, val):
        self.IDENTITY_FILE["default_master"] = val

    @property
    def default_port(self):
        return self.IDENTITY_FILE.get("default_port")

    @default_port.setter
    def default_port(self, val):
        self.IDENTITY_FILE["default_port"] = val

    def save(self):
        self.IDENTITY_FILE.store()

    def reload(self):
        self.IDENTITY_FILE.reload()
