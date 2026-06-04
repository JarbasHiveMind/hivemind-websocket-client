from .client import HiveMessageBusClient
from .message import HiveMessage, HiveMessageType


def __getattr__(name):
    # Lazy-import async surface so bare installs (no `websockets`) keep working.
    if name in ("AsyncHiveMessageBusClient",
                "AsyncHiveMessageWaiter",
                "AsyncHivePayloadWaiter"):
        from . import async_client
        return getattr(async_client, name)
    # Lazy-import MQTT client so bare installs (no `paho-mqtt`) keep working.
    if name == "HiveMindMQTTClient":
        from .mqtt_client import HiveMindMQTTClient
        return HiveMindMQTTClient
    raise AttributeError(f"module 'hivemind_bus_client' has no attribute {name!r}")
