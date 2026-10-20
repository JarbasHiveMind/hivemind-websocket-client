"""The client returns the session the hub sent, so follow-ups keep their state.

HIVEMIND-BRIDGE-1 §4 makes the client the authority for its own session, and
the hub keeps nothing between utterances. A hub reply carries the full session
(``response_mode`` while a skill waits for an answer). ``emit`` has to send
that session back on the next utterance, or the answer to a ``get_response``
question reaches the orchestrator with no pending response and goes unmatched.
"""
import json
import time
import unittest
from unittest.mock import MagicMock, patch

from ovos_bus_client.message import Message
from ovos_bus_client.session import Session
from ovos_utils.fakebus import FakeBus

from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol


def _client(site_id="s"):
    # bound the way the terminal and the voice satellite bind it:
    # connect(FakeBus()) puts the protocol on a bus of its own, so the client
    # emits inbound frames to internal_bus itself
    client = HiveMessageBusClient(key="k", password="p", host="127.0.0.1",
                                  port=1, useragent="t", self_signed=True)
    client.binarize = False
    client.crypto_key = None
    client.noise_transport = None
    client.client = MagicMock()
    client.connected_event.set()
    client.site_id = site_id
    proto = HiveMindSlaveProtocol(client, shared_bus=False, site_id=site_id)
    proto.bind(FakeBus())
    return client


def _hub_speaks(client, session: Session):
    """What the hub returns for a question: a speak with the session attached."""
    reply = Message("speak", {"utterance": "what is your name"},
                    {"destination": "t", "session": session.serialize()})
    client._handle_hive_protocol(HiveMessage(HiveMessageType.BUS, reply))


def _waiting_session(session_id: str, skill_id: str = "ask.skill") -> Session:
    sess = Session(session_id=session_id)
    sess.enable_response_mode(skill_id)
    return sess


def _sent_session(client) -> dict:
    frame = json.loads(client.client.send.call_args[0][0])
    return frame["payload"]["context"]["session"]


class TestSessionEchoedOnNextEmit(unittest.TestCase):

    def test_response_mode_from_the_hub_reaches_the_next_utterance(self):
        client = _client()
        _hub_speaks(client, _waiting_session(client.session_id))

        client.emit(Message("recognizer_loop:utterance",
                            {"utterances": ["Miro"], "lang": "en-US"}))

        sess = _sent_session(client)
        self.assertEqual(sess["session_id"], client.session_id)
        self.assertEqual(sess["response_mode"]["skill_id"], "ask.skill")
        self.assertGreater(sess["response_mode"]["expires_at"], time.time())

    def test_site_id_stays_the_clients(self):
        client = _client(site_id="kitchen")
        hub_copy = _waiting_session(client.session_id)
        hub_copy.site_id = "hub-side-site"
        _hub_speaks(client, hub_copy)

        client.emit(Message("recognizer_loop:utterance",
                            {"utterances": ["Miro"]}))

        self.assertEqual(_sent_session(client)["site_id"], "kitchen")

    def test_first_utterance_still_sends_the_bare_ids(self):
        client = _client()

        client.emit(Message("recognizer_loop:utterance",
                            {"utterances": ["hello"]}))

        sess = _sent_session(client)
        self.assertEqual(sess["session_id"], client.session_id)
        self.assertNotIn("response_mode", sess)

    def test_a_session_set_by_the_caller_is_kept(self):
        client = _client()
        _hub_speaks(client, _waiting_session(client.session_id))
        explicit = {"session_id": client.session_id, "lang": "pt-PT"}

        client.emit(Message("recognizer_loop:utterance",
                            {"utterances": ["Miro"]}, {"session": explicit}))

        sess = _sent_session(client)
        self.assertEqual(sess["lang"], "pt-PT")
        self.assertNotIn("response_mode", sess)

    def test_a_session_for_another_id_is_not_adopted(self):
        client = _client()
        _hub_speaks(client, _waiting_session("someone-elses-session"))

        client.emit(Message("recognizer_loop:utterance",
                            {"utterances": ["Miro"]}))

        sess = _sent_session(client)
        self.assertEqual(sess["session_id"], client.session_id)
        self.assertNotIn("response_mode", sess)

    def test_two_clients_keep_their_own_pending_question(self):
        first, second = _client(), _client()
        self.assertNotEqual(first.session_id, second.session_id)
        _hub_speaks(first, _waiting_session(first.session_id, "first.skill"))
        _hub_speaks(second, _waiting_session(second.session_id, "second.skill"))

        first.emit(Message("recognizer_loop:utterance", {"utterances": ["a"]}))
        second.emit(Message("recognizer_loop:utterance", {"utterances": ["b"]}))

        self.assertEqual(_sent_session(first)["response_mode"]["skill_id"],
                         "first.skill")
        self.assertEqual(_sent_session(second)["response_mode"]["skill_id"],
                         "second.skill")

    def test_a_hub_notice_without_a_session_is_not_adopted(self):
        # hive.policy.denied reaches the client as a BUS frame with no session;
        # the client's own fresh defaults must not be mistaken for hub state
        client = _client()
        notice = Message("hive.policy.denied", {"code": "acl_disallowed_type"},
                         {"source": "hivemind-core", "destination": "t"})
        client._handle_hive_protocol(HiveMessage(HiveMessageType.BUS, notice))

        client.emit(Message("recognizer_loop:utterance", {"utterances": ["a"]}))

        self.assertEqual(set(_sent_session(client)), {"session_id", "site_id"})

    def test_the_session_is_kept_until_the_hub_sends_another(self):
        client = _client()
        _hub_speaks(client, _waiting_session(client.session_id))

        client.emit(Message("recognizer_loop:utterance", {"utterances": ["a"]}))
        client.emit(Message("recognizer_loop:utterance", {"utterances": ["b"]}))

        self.assertEqual(_sent_session(client)["response_mode"]["skill_id"],
                         "ask.skill")

        _hub_speaks(client, Session(session_id=client.session_id))
        client.emit(Message("recognizer_loop:utterance", {"utterances": ["c"]}))

        self.assertNotIn("response_mode", _sent_session(client))

    def test_override_fields_from_the_hub_are_not_sent_again(self):
        # pipeline and blacklisted_skills belong to the node: an operator
        # change must reach the next utterance, so the client never repeats
        # the value the hub returned (OVOS-SESSION-1 §2.1)
        client = _client(site_id="kitchen")
        returned = _waiting_session(client.session_id)
        returned.pipeline = ["old-pipeline-stage"]
        returned.blacklisted_skills = ["blocked.skill"]
        _hub_speaks(client, returned)

        client.emit(Message("recognizer_loop:utterance",
                            {"utterances": ["Miro"]}))

        sent = _sent_session(client)
        self.assertEqual(set(sent), {"session_id", "site_id", "response_mode"})
        self.assertEqual(sent["session_id"], client.session_id)
        self.assertEqual(sent["site_id"], "kitchen")
        self.assertEqual(sent["response_mode"]["skill_id"], "ask.skill")

    def test_the_other_state_record_fields_are_sent_again(self):
        client = _client()
        returned = Session(
            session_id=client.session_id,
            active_handlers=[{"skill_id": "a.skill", "activated_at": 123.0}],
            converse_handlers=[{"skill_id": "c.skill", "activated_at": 124.0}])
        returned.intent_context = {"frame": "x"}
        _hub_speaks(client, returned)

        client.emit(Message("recognizer_loop:utterance", {"utterances": ["a"]}))

        sent = _sent_session(client)
        self.assertEqual(sent["active_handlers"],
                         [{"skill_id": "a.skill", "activated_at": 123.0}])
        self.assertEqual(sent["converse_handlers"],
                         [{"skill_id": "c.skill", "activated_at": 124.0}])
        self.assertEqual(sent["intent_context"], {"frame": "x"})

    def test_an_expired_response_mode_is_not_sent(self):
        client = _client()
        returned = _waiting_session(client.session_id)
        returned.response_mode["expires_at"] = time.time() - 1
        _hub_speaks(client, returned)

        client.emit(Message("recognizer_loop:utterance", {"utterances": ["a"]}))

        self.assertNotIn("response_mode", _sent_session(client))

    def test_a_response_mode_that_expires_between_turns_is_not_sent(self):
        client = _client()
        returned = _waiting_session(client.session_id)
        expires_at = returned.response_mode["expires_at"]
        _hub_speaks(client, returned)

        client.emit(Message("recognizer_loop:utterance", {"utterances": ["a"]}))
        self.assertEqual(_sent_session(client)["response_mode"]["expires_at"],
                         expires_at)

        with patch("time.time",
                   return_value=expires_at + 1):
            client.emit(Message("recognizer_loop:utterance",
                                {"utterances": ["b"]}))

        self.assertNotIn("response_mode", _sent_session(client))


if __name__ == "__main__":
    unittest.main()
