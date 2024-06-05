import json
from enum import Enum

from ovos_bus_client import Message
from ovos_utils.json_helper import merge_dict
from typing import Union, List, Optional


class HiveMessageType(str, Enum):
    HANDSHAKE = "shake"  # negotiate initial connection
    BUS = "bus"  # request meant for internal mycroft-bus in master
    SHARED_BUS = "shared_bus"  # passive sharing of message
    # from mycroft-bus in slave

    INTERCOM = "intercom"  # from satellite to satellite

    BROADCAST = "broadcast"  # forward message to all slaves
    PROPAGATE = "propagate"  # forward message to all slaves and masters
    ESCALATE = "escalate"  # forward message up the authority chain to all
    # masters
    HELLO = "hello"  # like escalate, used to announce the device
    QUERY = "query"  # like escalate, but stops once one of the nodes can
    # send a response
    CASCADE = "cascade"  # like propagate, but expects a response back from
    # all nodes in the hive (responses optional)
    PING = "ping"  # like cascade, but used to map the network
    RENDEZVOUS = "rendezvous"  # reserved for rendezvous-nodes
    THIRDPRTY = "3rdparty"  # user land message, do whatever you want
    BINARY = "bin"  # binary data container, payload for something else


class HiveMessage:
    def __init__(self, msg_type: Union[HiveMessageType, str],
                 payload: Optional[Union[Message, 'HiveMessage', str, dict]] =None,
                 node: Optional[str]=None,
                 source_peer: Optional[str]=None,
                 route: Optional[List[str]]=None,
                 target_peers: Optional[List[str]]=None,
                 target_site_id: Optional[str] =None,
                 target_pubkey: Optional[str] =None):
        #  except for the hivemind node classes receiving the message and
        #  creating the object nothing should be able to change these values
        #  node classes might change them a runtime by the private attribute
        #  but end-users should consider them read_only


        if msg_type not in [m.value for m in HiveMessageType]:
            raise ValueError("Unknown HiveMessage.msg_type")
        self._msg_type = msg_type

        # the payload is more or less a free for all
        # the msg_type determines what happens to the message, but the
        # payload can simply be ignored by the receiving module
        # we store things in dict/json format, json is always used at the
        # transport layer before converting into any of the other formats
        if isinstance(payload, Message):
            payload = {"type": payload.msg_type,
                       "data": payload.data,
                       "context": payload.context}
        elif isinstance(payload, str):
            payload = json.loads(payload)
        self._payload = payload or {}

        self._site_id = target_site_id
        self._target_pubkey = target_pubkey
        self._node = node  # node semi-unique identifier
        self._source_peer = source_peer  # peer_id
        self._route = route or []  # where did this message come from
        self._targets = target_peers or []  # where will it be sent

    @property
    def target_site_id(self) -> str:
        return self._site_id

    @property
    def target_public_key(self) -> str:
        return self._target_pubkey

    @property
    def msg_type(self) -> str:
        return self._msg_type

    @property
    def node_id(self) -> str:
        return self._node

    @property
    def source_peer(self) -> str:
        return self._source_peer

    @property
    def target_peers(self) -> List[str]:
        if self.source_peer:
            return self._targets or [self._source_peer]
        return self._targets

    @property
    def route(self) -> List[str]:
        return [r for r in self._route if r.get("targets") and r.get("source")]

    @property
    def payload(self) -> Union['HiveMessage', Message, dict]:
        if self.msg_type in [HiveMessageType.BUS, HiveMessageType.SHARED_BUS]:
            return Message(self._payload["type"],
                           data=self._payload.get("data"),
                           context=self._payload.get("context"))
        if self.msg_type in [HiveMessageType.BROADCAST,
                             HiveMessageType.PROPAGATE,
                             HiveMessageType.CASCADE,
                             HiveMessageType.ESCALATE]:
            return HiveMessage(**self._payload)
        return self._payload

    @property
    def as_dict(self) -> dict:
        pload = self._payload
        if isinstance(pload, HiveMessage):
            pload = pload.as_dict
        elif isinstance(pload, Message):
            pload = pload.serialize()
        if isinstance(pload, str):
            pload = json.loads(pload)

        assert isinstance(pload, dict)

        return {"msg_type": self.msg_type,
                "payload": pload,
                "route": self.route,
                "node": self.node_id,
                "target_site_id": self.target_site_id,
                "target_pubkey": self.target_public_key,
                "source_peer": self.source_peer}

    @property
    def as_json(self) -> str:
        return json.dumps(self.as_dict)

    def serialize(self) -> str:
        return self.as_json

    @staticmethod
    def deserialize(payload: Union[str, dict]) -> 'HiveMessage':
        if isinstance(payload, str):
            payload = json.loads(payload)

        if "msg_type" in payload:
            try:
                return HiveMessage(payload["msg_type"], payload["payload"],
                                   target_site_id=payload.get("target_site_id"),
                                   target_pubkey=payload.get("target_pubkey"))
            except:
                pass  # not a hivemind message

        if "type" in payload:
            try:
                # NOTE: technically could also be SHARED_BUS or THIRDPRTY
                return HiveMessage(HiveMessageType.BUS,
                                   Message.deserialize(payload),
                                   target_site_id=payload.get("target_site_id"),
                                   target_pubkey=payload.get("target_pubkey"))
            except:
                pass  # not a mycroft message

        return HiveMessage(HiveMessageType.THIRDPRTY, payload,
                           target_site_id=payload.get("target_site_id"),
                           target_pubkey=payload.get("target_pubkey"))

    def __getitem__(self, item):
        return self._payload.get(item)

    def __setitem__(self, key, value):
        self._payload[key] = value

    def __str__(self):
        return self.as_json

    def update_hop_data(self, data=None, **kwargs):
        if not self._route or self._route[-1]["source"] != self.source_peer:
            self._route += [{"source": self.source_peer,
                             "targets": self.target_peers}]
        if self._route and data:
            self._route[-1] = merge_dict(self._route[-1], data, **kwargs)

    def replace_route(self, route):
        self._route = route

    def update_source_peer(self, peer):
        self._source_peer = peer
        return self

    def add_target_peer(self, peer):
        self._targets.append(peer)

    def remove_target_peer(self, peer):
        if peer in self._targets:
            self._targets.pop(peer)
