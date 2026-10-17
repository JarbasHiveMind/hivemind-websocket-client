import json
from enum import Enum, IntEnum

from ovos_bus_client import Message
from ovos_utils.json_helper import merge_dict
from typing import Union, List, Optional, Dict, Any


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
    BINARY = "bin"  # binary data container, payload for something else


class HiveMindBinaryPayloadType(IntEnum):
    """ Pseudo extension type for binary payloads
    it doesnt describe the payload but rather provides instruction to hivemind about how to handle it"""
    UNDEFINED = 0  # no info provided about binary contents
    RAW_AUDIO = 1  # uncompressed PCM, HIVEMIND-AUDIO-1 §2: signed 16-bit little-endian, 16 kHz, mono unless metadata overrides
    NUMPY_IMAGE = 2  # binary content is an image as a numpy array, eg. webcam picture
    FILE = 3  # binary is a file to be saved, additional metadata provided elsewhere
    STT_AUDIO_TRANSCRIBE = 4  # full audio sentence to perform STT and return transcripts
    STT_AUDIO_HANDLE = 5  # full audio sentence to perform STT and handle transcription immediately
    TTS_AUDIO = 6  # synthesized TTS audio to be played


#: The wire types whose payload HIVEMIND-MSG-1 §4 makes a nested envelope:
#: "For ``BROADCAST``, ``PROPAGATE``, ``ESCALATE``, ``QUERY``, and
#: ``CASCADE``, the payload is **itself a HiveMessage** (a nested envelope)
#: whose ``msg_type`` is typically ``BUS``." ``BUS`` and ``SHARED_BUS`` are
#: NOT here: §4 carries their payload OPAQUELY.
#:
#: This answers "may a Layer-1 ``Message`` be the payload", asked in the
#: constructor. It is NOT the emptiness question, which ``_ENVELOPE_PAYLOAD``
#: below answers over a wider set. Keep the two apart: one refuses a wrong
#: TYPE from an originator, the other refuses an EMPTY object off the wire.
_ROUTING_TYPES = frozenset(
    [HiveMessageType.BROADCAST, HiveMessageType.PROPAGATE,
     HiveMessageType.ESCALATE, HiveMessageType.QUERY,
     HiveMessageType.CASCADE]
    + [HiveMessageType.BROADCAST.value, HiveMessageType.PROPAGATE.value,
       HiveMessageType.ESCALATE.value, HiveMessageType.QUERY.value,
       HiveMessageType.CASCADE.value])


#: The wire types whose payload CARRIES AN ENVELOPE, so an empty object is
#: malformed rather than a legal degenerate. The routing types plus ``BUS``
#: and ``SHARED_BUS``, whose payload §4 makes "a single Layer-1 bus message".
#:
#: §4 AT ``7eabe88`` STATES THIS RULE, so this list enforces a merged clause
#: and no longer a reading of one: "The empty object ``{}`` is not an envelope
#: of either kind: it carries nothing at all, so it is neither a Layer-1 bus
#: message nor a HiveMessage. So a ``BUS``, ``SHARED_BUS``, ``BROADCAST``,
#: ``PROPAGATE``, ``ESCALATE``, ``QUERY`` or ``CASCADE`` whose payload is
#: ``{}`` is **malformed**, and a receiver **MUST** reject it as it rejects an
#: absent payload." The clause names the same seven types as this tuple, and
#: it adds the sentence this library needs most: a receiver "**MUST NOT**
#: admit an empty payload on one of the seven types above and leave the
#: failure to a later reader of the inner message".
#:
#: Before ``7eabe88`` no clause said it in those words, and this comment
#: carried the library's own derivation instead: §4's "is" plus §2's required
#: ``msg_type``. The derivation reached the same seven types.
#:
#: Emptiness stays legal exactly where §4 grants it, HANDSHAKE, HELLO and PING,
#: and those are not here. Nor are BINARY, whose payload is bytes, or INTERCOM
#: and RENDEZVOUS, whose inner form belongs to another specification (see
#: ``_PAYLOAD_REQUIRED``).
#:
#: Before this, all seven were ADMITTED with ``{}`` and raised only when
#: something read ``.payload``: KeyError for the bus types, TypeError for the
#: routing types.
_ENVELOPE_PAYLOAD = tuple(
    form
    for _type in (HiveMessageType.BUS, HiveMessageType.SHARED_BUS,
                  HiveMessageType.BROADCAST, HiveMessageType.PROPAGATE,
                  HiveMessageType.ESCALATE, HiveMessageType.QUERY,
                  HiveMessageType.CASCADE)
    for form in (_type, _type.value)
)


#: The wire types whose payload MUST be present on the wire, refused at
#: ``from_wire`` when the key is absent. Both the enum and its ``.value`` are
#: listed, because a frame off the wire carries the string.
#:
#: HIVEMIND-MSG-1 §4 gives each of these a payload that cannot be absent: a
#: Layer-1 bus message for ``BUS`` and ``SHARED_BUS``, a nested HiveMessage for
#: ``BROADCAST``, ``PROPAGATE``, ``ESCALATE``, ``QUERY`` and ``CASCADE``, "an
#: opaque byte string" for ``BINARY``, and the control fields their types
#: require for ``HANDSHAKE`` and ``HELLO``. §2's envelope table now marks
#: ``payload`` Required "yes, except ``PING``" (``7eabe88``), so requiring it
#: for all ten reads the table straight.
#:
#: Settled by architecture under T-4702, and this list is the answer. Before
#: it, only HELLO and HANDSHAKE were here. Measured on the other eleven with a
#: frame of ``{"msg_type": t}`` and no payload key: seven were ADMITTED and
#: raised only when something read ``.payload``, ``BUS`` and ``SHARED_BUS``
#: with ``KeyError`` and the five routing types with ``TypeError``, so a
#: payload-less PROPAGATE blew up frames later in whatever read it. A refusal
#: that happens by crash cannot be logged as a malformed frame, cannot name
#: the field, and a caller cannot tell it from a bug. ``BINARY`` was refused
#: incidentally, by the constructor's bytes check, citing no clause and
#: raising a bare ``ValueError`` that no transport guard caught; that check
#: now raises ``MalformedWirePayload`` and cites §4's "opaque byte string".
#:
#: THREE TYPES ARE LEFT OUT, and they are named here so the gap is not read
#: as an oversight. ``PING`` may omit the key: §2's table excepts it and §4
#: says a receiver reads an absent key as ``{}``. ``INTERCOM`` and
#: ``RENDEZVOUS`` ARE MISSING BY SEQUENCING, NOT BY §2'S SILENCE: presence is
#: §2's rule, and its table has required a payload for every type but ``PING``
#: all along, so this list is two names short of what §2 asks. #297 adds both
#: with the tests that hold them, and this paragraph goes when it lands.
#: Shape is §4's separate question, and §4 at ``7eabe88`` answers that too --
#: each "a JSON object", INTERCOM's "never absent and never the empty object"
#: -- but presence needs no shape to enforce.
_PAYLOAD_REQUIRED = tuple(
    form
    for _type in (HiveMessageType.HANDSHAKE, HiveMessageType.HELLO,
                  HiveMessageType.BUS, HiveMessageType.SHARED_BUS,
                  HiveMessageType.BROADCAST, HiveMessageType.PROPAGATE,
                  HiveMessageType.ESCALATE, HiveMessageType.QUERY,
                  HiveMessageType.CASCADE, HiveMessageType.BINARY)
    for form in (_type, _type.value)
)


class MalformedWirePayload(ValueError):
    """A wire frame whose payload this library refuses.

    The object requirement is THIS LIBRARY'S, not the specification's.
    HIVEMIND-MSG-1 §4 gives a form per ``msg_type`` -- a Layer-1 bus message
    for BUS and SHARED_BUS, a nested HiveMessage for the routing types, "an
    opaque byte string" for BINARY, and a "JSON object" for INTERCOM,
    RENDEZVOUS, HANDSHAKE, HELLO and PING, the last three carrying "only the
    control fields those types require". So §4 names an object for five types
    of thirteen and never states one blanket object rule. What it does carry,
    and what every refusal below rests on, is its closing sentence: a node "MUST
    NOT inspect or rewrite the inner payload of a wrapped routing message
    except where another HiveMind specification explicitly permits it".
    Parsing a string into an object is exactly that rewrite.

    A ValueError, so the callers that already treat a bad frame as a
    ValueError keep working."""


class _Unset:
    """Sentinel telling forward() apart from an explicit None.

    ``forward(target_site_id=None)`` must be able to DROP the site id, so
    ``None`` cannot double as "not given"."""

    def __repr__(self):
        return "<unset>"


_UNSET = _Unset()


class HiveMessage:
    def __init__(self, msg_type: Union[HiveMessageType, str],
                 payload: Optional[Union[Message, 'HiveMessage', str, dict, bytes]] =None,
                 node: Optional[str]=None,
                 source_peer: Optional[str]=None,
                 route: Optional[List[str]]=None,
                 target_peers: Optional[List[str]]=None,
                 target_site_id: Optional[str] =None,
                 target_pubkey: Optional[str] =None,
                 bin_type: HiveMindBinaryPayloadType = HiveMindBinaryPayloadType.UNDEFINED,
                 metadata: Optional[Dict[str, Any]] = None):
        #  except for the hivemind node classes receiving the message and
        #  creating the object nothing should be able to change these values
        #  node classes might change them a runtime by the private attribute
        #  but end-users should consider them read_only.
        #  To send this message on to the next hop, use forward() - it derives
        #  a new envelope and keeps the fields you did not name.
        if msg_type not in [m.value for m in HiveMessageType]:
            raise ValueError("Unknown HiveMessage.msg_type")
        if msg_type != HiveMessageType.BINARY and bin_type != HiveMindBinaryPayloadType.UNDEFINED:
            raise ValueError("bin_type can only be set for BINARY message type")

        self._msg_type = msg_type
        self._bin_type = bin_type
        self._meta = metadata or {}

        # the payload is more or less a free for all
        # the msg_type determines what happens to the message, but the
        # payload can simply be ignored by the receiving module
        # we store things in dict/json format, json is always used at the
        # transport layer before converting into any of the other formats
        if not isinstance(payload, bytes) and msg_type == HiveMessageType.BINARY:
            # HIVEMIND-MSG-1 §4: "For `BINARY`, the payload is an opaque byte
            # string with an associated handling instruction". A MalformedWire-
            # Payload, not a bare ValueError, because from_wire reaches this
            # check for a BINARY frame whose payload is an object, and a caller
            # that guards the door catches MalformedWirePayload. A bare
            # ValueError there escaped the guard in every transport and reached
            # on_error, which clears the connection state: §3 says a node
            # "MUST NOT reject the connection over it, and it MUST NOT stop its
            # own handler over it". MalformedWirePayload IS a ValueError, so an
            # API caller that already catches ValueError keeps working.
            raise MalformedWirePayload(
                f"expected 'bytes' payload for HiveMessageType.BINARY, got "
                f"{type(payload)}. HIVEMIND-MSG-1 §4 makes a BINARY payload "
                f"\"an opaque byte string\"")
        elif isinstance(payload, Message):
            # HIVEMIND-MSG-1 §4: a routing payload "is itself a HiveMessage
            # (a nested envelope)". This conversion writes
            # {"type", "data", "context"} and no `msg_type`, so a Layer-1
            # message put straight into a routing type is NOT an envelope:
            # the far end raises TypeError the moment it reads `.payload`,
            # and the sender is told nothing. The refusal is the invariant of
            # this conversion, so it stands beside it.
            #
            # The key is SPEC-REQUIRED, by composition, and the refusal
            # says so. §4 makes the payload "itself a HiveMessage (a nested
            # envelope)", and §2 makes `msg_type` a required field of a
            # HiveMessage -- "msg_type | yes" in the three-field table, and
            # "`msg_type` is the **only** field a receiver may rely on to
            # decide how to handle a message". So a nested envelope with no
            # `msg_type` is not a HiveMessage and the frame is not what §4
            # requires. An earlier version of this comment said §4 "names the
            # shape and no field" and cited the library for the key. That was
            # wrong, and wrong in the cautious direction: there is no silence
            # here to read as permission.
            #
            # A `Message` OBJECT, and nothing wider. A payload that is
            # already a dict with no `msg_type` is the same shape on the
            # wire, but it is also what every wire door hands this
            # constructor -- `from_wire`, `deserialize`, `decode_bitstring`,
            # the inner view the `payload` property rebuilds, and
            # hivemind-core's own door at protocol.py:584. Refusing it here
            # would be the receive-side twin T-5170 ruled out, and §4 forbids
            # an admitting node to inspect the inner payload of a wrapped
            # routing message. A `Message` object never arrives from a wire,
            # so this branch can only ever refuse an originator.
            if msg_type in _ROUTING_TYPES:
                raise ValueError(
                    f"a {msg_type} payload must be a nested HiveMessage with "
                    f"a 'msg_type' (HIVEMIND-MSG-1 §4 with §2), got a "
                    f"Layer-1 Message. Wrap it: "
                    f"HiveMessage({msg_type}, "
                    f"HiveMessage(HiveMessageType.BUS, payload=<Message>)).")
            payload = {"type": payload.msg_type,
                       "data": payload.data,
                       "context": payload.context}
        elif isinstance(payload, HiveMessage):
            payload = payload.as_dict
        elif isinstance(payload, str):
            # A string is NOT parsed into an object here. `from_wire` is the
            # one door for a wire value, and this constructor is what builds
            # the INNER view of a wrapped routing message
            # (`HiveMessage(**self._payload)`, see the payload property). So
            # a repair here reapplied, one level down, exactly the repair
            # `from_wire` refuses: a PROPAGATE carrying a PING whose payload
            # was the string '{"flood_id": "forged"}' had it parsed and
            # `handle_ping` read the forged id off it. HIVEMIND-MSG-1 §4 also
            # forbids a node to rewrite the inner payload of a wrapped
            # routing message.
            raise MalformedWirePayload(
                f"{msg_type} payload arrived as str and is not parsed here: "
                f"that would rewrite a wrapped inner payload, which "
                f"HIVEMIND-MSG-1 §4 forbids. Parse the frame with "
                f"HiveMessage.from_wire() instead.")
        self._payload = payload if payload is not None else {}
        # BUS/wrapper payloads are rebuilt into Message/HiveMessage objects on
        # access; without this cache every read returned a different object and
        # mutating one of them was silently lost. See the payload property.
        self._payload_view = None

        self._site_id = target_site_id
        self._target_pubkey = target_pubkey
        self._node = node  # node semi-unique identifier
        self._source_peer = source_peer  # peer_id
        self._route = route or []  # where did this message come from
        self._targets = target_peers or []  # where will it be sent

    @property
    def metadata(self) -> Dict[str, Any]:
        return self._meta

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
        # HIVEMIND-MSG-1 §5: a hop records AT LEAST the forwarding node in
        # `source`. `targets` is optional provenance that no consumer reads,
        # so requiring it here silently dropped spec-minimal hops -- and
        # because relaying copies this filtered view back over the route,
        # dropped hops were erased from the message for every later node.
        return [r for r in self._route if isinstance(r, dict) and r.get("source")]

    @property
    def payload(self) -> Union['HiveMessage', Message, dict, bytes]:
        """
        Return the public payload converted to the most appropriate message representation for this HiveMessage.
        
        Depending on this message's msg_type, the payload is returned as a reconstructed `Message`, a reconstructed `HiveMessage`, or the raw stored payload.

        The reconstructed object is built once and reused, so reading the
        payload twice gives you the SAME object and a mutation made through it
        is still there on the next read. It is invalidated when the payload is
        replaced or an item is assigned.

        Returns:
            Union[HiveMessage, Message, dict, bytes]: A `Message` when msg_type is BUS or SHARED_BUS; a `HiveMessage` when msg_type is BROADCAST, PROPAGATE, CASCADE, ESCALATE, or QUERY; otherwise the raw payload (typically a `dict` or `bytes`).
        """
        if self._payload_view is not None:
            return self._payload_view

        if self.msg_type in [HiveMessageType.BUS, HiveMessageType.SHARED_BUS]:
            self._payload_view = Message(self._payload["type"],
                                         data=self._payload.get("data"),
                                         context=self._payload.get("context"))
        elif self.msg_type in [HiveMessageType.BROADCAST,
                               HiveMessageType.PROPAGATE,
                               HiveMessageType.CASCADE,
                               HiveMessageType.ESCALATE,
                               HiveMessageType.QUERY]:
            self._payload_view = HiveMessage(**self._payload)
        else:
            return self._payload
        return self._payload_view

    @payload.setter
    def payload(self, payload: Union['HiveMessage', Message, dict, bytes]):
        """
        Set the message payload, normalizing Message or HiveMessage inputs to their dictionary representations.
        
        Parameters:
            payload (HiveMessage | Message | dict | bytes): New payload to assign. If a `Message` or `HiveMessage` is provided, its dict representation is stored; otherwise the value is stored as given.
        """
        if isinstance(payload, Message):
            self._payload = payload.as_dict
        elif isinstance(payload, HiveMessage):
            self._payload = payload.as_dict
        else:
            self._payload = payload
        self._payload_view = None

    @property
    def bin_type(self) -> HiveMindBinaryPayloadType:
        """
        Get the binary payload type for this message.
        
        Returns:
            HiveMindBinaryPayloadType: Indicator of how the message's binary payload should be interpreted.
        """
        return self._bin_type

    @property
    def as_dict(self) -> dict:
        pload = self._payload
        if self.msg_type == HiveMessageType.BINARY:
            raise ValueError("messages with type HiveMessageType.BINARY can not be cast to dict")
        if isinstance(pload, HiveMessage):
            pload = pload.as_dict
        elif isinstance(pload, Message):
            pload = pload.serialize()
        # A string payload is NOT parsed back into an object here. Doing so
        # repaired a wire value that HIVEMIND-MSG-1 §4 refuses, and it let a
        # HELLO whose payload was the string '{"site_id": "x"}' set a site
        # id. `from_wire` rejects that shape before it reaches this.
        #
        # This raises rather than asserting: `python -O` compiles an assert
        # out, and the guard would then be gone in exactly the deployment
        # that runs with it. protocol.py:1150 carries the same note about an
        # assert this project already lost that way. The public payload
        # setter is the way a string still reaches here.
        if not isinstance(pload, dict):
            raise MalformedWirePayload(
                f"{self.msg_type} payload must be an object on the wire, got "
                f"{type(pload).__name__}. Parsing it here would rewrite a "
                f"wrapped inner payload, which HIVEMIND-MSG-1 §4 forbids")

        return {"msg_type": self.msg_type,
                "payload": pload,
                "metadata": self.metadata,
                "route": self.route,
                "node": self.node_id,
                "target_site_id": self.target_site_id,
                "target_pubkey": self.target_public_key,
                # NOTE: target_peers is deliberately NOT here, and no new key
                # may be added without measuring. hivemind-core encrypts an
                # INTERCOM inner body with raw RSA (PKCS1-OAEP), so a
                # serialized envelope must fit one RSA block - about 214 bytes
                # with 2048-bit keys. The smallest possible BUS envelope is
                # already 207 bytes, so the whole format has ~7 bytes of
                # headroom. Adding "target_peers": [] costs 20 and breaks real
                # INTERCOM traffic. Next-hop targets travel via forward(),
                # which is in-process and free.
                # See tests/test_message.py::TestWireSizeCeiling.
                "source_peer": self.source_peer}

    def forward(self,
                payload=_UNSET,
                msg_type=_UNSET,
                metadata=_UNSET,
                route=_UNSET,
                source_peer=_UNSET,
                target_peers=_UNSET,
                target_site_id=_UNSET,
                target_pubkey=_UNSET,
                node=_UNSET,
                bin_type=_UNSET) -> 'HiveMessage':
        """Derive the envelope to send on to the next hop.

        Every field of this message is carried over unless you name it here,
        including the ones that only the constructor can set (metadata,
        target_site_id, target_pubkey, node, bin_type). Relays that rebuild
        envelopes by hand keep forgetting one of those, and the message then
        arrives stripped with nothing to show what was lost: a flood that dies
        after one hop, a site-targeted message that no longer knows its site.
        Preserving is the default; dropping a field is an explicit
        ``forward(target_site_id=None)``.
        """
        def kept(given, current):
            return current if given is _UNSET else given

        return HiveMessage(
            msg_type=kept(msg_type, self._msg_type),
            payload=kept(payload, self._payload),
            node=kept(node, self._node),
            source_peer=kept(source_peer, self._source_peer),
            route=kept(route, list(self._route)),
            target_peers=kept(target_peers, list(self._targets)),
            target_site_id=kept(target_site_id, self._site_id),
            target_pubkey=kept(target_pubkey, self._target_pubkey),
            bin_type=kept(bin_type, self._bin_type),
            metadata=kept(metadata, dict(self._meta)))

    @property
    def as_json(self) -> str:
        return json.dumps(self.as_dict, ensure_ascii=False)

    def serialize(self) -> str:
        return self.as_json

    @staticmethod
    def _wire_payload(msg_type: Any, payload: Any) -> dict:
        """The payload of a wire frame, refused unless it is a JSON object.

        This library requires an object, with ``{}`` the only empty form, and
        never repairs another shape: it raises rather than substituting a
        value the sender did not send.

        That requirement is the library's own. HIVEMIND-MSG-1 §4 states a
        form per ``msg_type`` rather than one blanket object rule: it names a
        "JSON object" for five types and an envelope or a byte string for the
        rest. What §4 forbids, and what this refusal enforces, is rewriting
        the inner payload of a wrapped routing message, which is what parsing
        a string here would do.

        The Python constructor keeps its own default: ``HiveMessage(TYPE)``
        with no payload is an API convenience and builds ``{}``. That is not
        a repair of a wire value, because no wire value was read. Everything
        that DOES read the wire comes through here.
        """
        if isinstance(payload, dict):
            if not payload and msg_type in _ENVELOPE_PAYLOAD:
                raise MalformedWirePayload(
                    f"{msg_type} payload is empty, and HIVEMIND-MSG-1 §4 "
                    f"gives this type an envelope: a Layer-1 bus message for "
                    f"BUS and SHARED_BUS, a HiveMessage for the routing "
                    f"types. Each carries a required type field, and {{}} "
                    f"carries none")
            return payload
        raise MalformedWirePayload(
            f"{msg_type} payload must be an object on the wire, got "
            f"{type(payload).__name__}. Parsing it here would rewrite a "
            f"wrapped inner payload, which HIVEMIND-MSG-1 §4 forbids")

    @staticmethod
    def from_wire(frame: Union[str, dict]) -> 'HiveMessage':
        """Build a message from a wire frame, payload validated.

        This is the one door for a frame that arrived over a connection. It
        keeps the per-hop fields the frame carries, which
        :meth:`deserialize` deliberately drops for a node that is about to
        re-route the message: a client reads ``source_peer`` to decide
        whether a PROPAGATE is trusted, so dropping it here would silently
        change that decision.
        """
        if isinstance(frame, str):
            frame = json.loads(frame)
        if not isinstance(frame, dict):
            raise MalformedWirePayload(
                f"a wire frame must be an object carrying the envelope, got "
                f"{type(frame).__name__} (HIVEMIND-MSG-1 §2)")
        if "msg_type" not in frame:
            raise MalformedWirePayload(f"not a HiveMind message: {frame}")
        kwargs = dict(frame)
        msg_type = kwargs.pop("msg_type")
        if "payload" not in kwargs:
            # Absent is refused only for the types in _PAYLOAD_REQUIRED; a
            # PING frame is the whole message and has nothing to put in a
            # payload, so an absent key there is treated as the frame's shape
            # and not a missing value. See the note on _PAYLOAD_REQUIRED:
            # the split is architecture's answer under T-4702, not an open
            # question, and §2's table reads "yes, except PING" to match
            # (JarbasHiveMind/architecture#32, merged as 7eabe88).
            if msg_type in _PAYLOAD_REQUIRED:
                raise MalformedWirePayload(
                    f"{msg_type} frame carries no payload, which "
                    f"HIVEMIND-MSG-1 §2 marks required for every type "
                    f"except PING")
            return HiveMessage(msg_type, **kwargs)
        payload = HiveMessage._wire_payload(msg_type, kwargs.pop("payload"))
        return HiveMessage(msg_type, payload, **kwargs)

    @staticmethod
    def deserialize(payload: Union[str, dict]) -> 'HiveMessage':
        if isinstance(payload, str):
            payload = json.loads(payload)

        if "msg_type" in payload:
            # §4 again: a frame whose payload is not an object is refused
            # here, and the refusal is not swallowed by the `except` below,
            # which exists to fall through to the BUS shape.
            if "payload" in payload:
                HiveMessage._wire_payload(payload["msg_type"],
                                          payload["payload"])
            try:
                return HiveMessage(payload["msg_type"], payload["payload"],
                                   metadata=payload.get("metadata", {}),
                                   route=payload.get("route"),
                                   # NOTE: node, source_peer and target_peers
                                   # are not restored here - they are per-hop.
                                   # The receiving node sets node/source_peer
                                   # from the connection, and it decides its
                                   # own next-hop targets.
                                   target_site_id=payload.get("target_site_id"),
                                   target_pubkey=payload.get("target_pubkey"))
            except Exception:
                pass  # not a hivemind message

        if "type" in payload:
            try:
                # NOTE: technically could also be SHARED_BUS
                return HiveMessage(HiveMessageType.BUS,
                                   payload=Message.deserialize(payload),
                                   metadata=payload.get("metadata", {}),
                                   target_site_id=payload.get("target_site_id"),
                                   target_pubkey=payload.get("target_pubkey"))
            except Exception:
                pass  # not a mycroft message

        raise ValueError(f"not a HiveMind message: {payload}")

    def __getitem__(self, item):
        if not isinstance(self._payload, dict):
            raise TypeError(f"Item access not supported for payload type {type(self._payload)}")
        return self._payload.get(item)

    def __setitem__(self, key, value):
        if isinstance(self._payload, dict):
            self._payload[key] = value
            self._payload_view = None
        else:
            raise TypeError(f"Item assignment not supported for payload type {type(self._payload)}")

    def __str__(self):
        if self.msg_type == HiveMessageType.BINARY:
            return f"HiveMessage(BINARY:{len(self._payload)}])"
        return self.as_json

    def update_hop_data(self, data=None, **kwargs):
        """
        Append/refresh this node's hop entry at the end of `route`.

        A route entry is only trusted when it is a dict exposing a `source`
        (same shape check as the `route` property, HIVEMIND-MSG-1 §5). An
        inbound frame is attacker-controlled and may carry a malformed last
        entry (e.g. `{}` or a bare string) -- rather than raising on that
        (pre-auth DoS), we treat a malformed last entry the same as a
        missing one and APPEND a fresh, well-formed hop for this node. The
        malformed entry is left in place earlier in the list (not dropped),
        it is just never indexed into or merged with.
        """
        last = self._route[-1] if self._route else None
        last_source = last.get("source") if isinstance(last, dict) else None
        if not self._route or last_source != self.source_peer:
            self._route += [{"source": self.source_peer,
                             "targets": self.target_peers}]
        if self._route and data and isinstance(self._route[-1], dict):
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
            self._targets.remove(peer)