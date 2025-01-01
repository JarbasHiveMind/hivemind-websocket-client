from os.path import basename, dirname
from poorman_handshake.asymmetric.utils import export_RSA_key, create_RSA_key
from json_database import JsonConfigXDG
from typing import Optional


class NodeIdentity:
    """
    A class representing a node's identity within a HiveMind network.

    Attributes:
        IDENTITY_FILE (JsonConfigXDG): A configuration file containing the node's identity information.
    """

    def __init__(self, identity_file: Optional[str] = None):
        """
        Initialize the NodeIdentity instance with an optional identity file.

        Args:
            identity_file (Optional[str]): Path to a custom identity file (default: None, uses default configuration).
        """
        self.IDENTITY_FILE = identity_file or JsonConfigXDG("_identity", subfolder="hivemind")

    @property
    def name(self) -> str:
        """
        Get or set the human-readable label for the node.

        The name is not guaranteed to be unique and can describe functionality, brand, capabilities, or other attributes.

        Returns:
            str: The name of the node, defaulting to "unnamed-node" if not set.
        """
        if not self.IDENTITY_FILE.get("name") and self.IDENTITY_FILE.get("key"):
            self.IDENTITY_FILE["name"] = basename(self.IDENTITY_FILE["key"])
        return self.IDENTITY_FILE.get("name") or "unnamed-node"

    @name.setter
    def name(self, val: str):
        """Set the name of the node."""
        self.IDENTITY_FILE["name"] = val

    @property
    def public_key(self) -> Optional[str]:
        """
        Get or set the public RSA key for the node.

        Returns:
            Optional[str]: The public RSA key, if available.
        """
        return self.IDENTITY_FILE.get("public_key")

    @public_key.setter
    def public_key(self, val: str):
        """Set the public RSA key for the node."""
        self.IDENTITY_FILE["public_key"] = val

    @property
    def private_key(self) -> str:
        """
        Get or set the path to the private RSA PEM file for the node.

        The private key is used to uniquely identify the device and prove its identity within the HiveMind network.

        Returns:
            str: The path to the private key file.
        """
        return self.IDENTITY_FILE.get("secret_key") or \
            f"{dirname(self.IDENTITY_FILE.path)}/{self.name}.pem"

    @private_key.setter
    def private_key(self, val: str):
        """Set the path to the private RSA PEM file for the node."""
        self.IDENTITY_FILE["secret_key"] = val

    @property
    def password(self) -> Optional[str]:
        """
        Get or set the password for the node.

        The password is used to generate a session AES key during the non-RSA handshake process.

        Returns:
            Optional[str]: The password used for session encryption.
        """
        return self.IDENTITY_FILE.get("password")

    @password.setter
    def password(self, val: str):
        """Set the password for the node."""
        self.IDENTITY_FILE["password"] = val

    @property
    def access_key(self) -> Optional[str]:
        """
        Get or set the access key for the node.

        Returns:
            Optional[str]: The access key for the node.
        """
        return self.IDENTITY_FILE.get("access_key")

    @access_key.setter
    def access_key(self, val: str):
        """Set the access key for the node."""
        self.IDENTITY_FILE["access_key"] = val

    @property
    def site_id(self) -> Optional[str]:
        """
        Get or set the site ID for the node.

        Returns:
            Optional[str]: The site ID for the node.
        """
        return self.IDENTITY_FILE.get("site_id")

    @site_id.setter
    def site_id(self, val: str):
        """Set the site ID for the node."""
        self.IDENTITY_FILE["site_id"] = val

    @property
    def default_master(self) -> Optional[str]:
        """
        Get or set the host for default master of the node.

        Returns:
            Optional[str]: The default master for the node.
        """
        return self.IDENTITY_FILE.get("default_master")

    @default_master.setter
    def default_master(self, val: str):
        """Set the host for the default master of the node."""
        self.IDENTITY_FILE["default_master"] = val

    @property
    def default_port(self) -> Optional[int]:
        """
        Get or set the default port for the node.

        Returns:
            Optional[int]: The default port for the node.
        """
        return self.IDENTITY_FILE.get("default_port")

    @default_port.setter
    def default_port(self, val: int):
        """Set the default port for the node."""
        self.IDENTITY_FILE["default_port"] = val

    def save(self) -> None:
        """
        Save the current node identity to the identity file.
        """
        self.IDENTITY_FILE.store()

    def reload(self) -> None:
        """
        Reload the node identity from the identity file.
        """
        self.IDENTITY_FILE.reload()

    def create_keys(self) -> None:
        """
        Generate a new RSA key pair (public and private) and store them in the identity file.

        This method generates a new private key, stores it in a PEM file, and updates the node's public and private keys
        in the identity file.
        """
        pub, secret = create_RSA_key()
        priv = f"{dirname(self.IDENTITY_FILE.path)}/HiveMindComs.pem"
        export_RSA_key(secret, priv)
        self.private_key = priv
        self.public_key = pub
