"""The async client returns the session the hub sent, so follow-ups keep their state.

Same contract as tests/test_session_echo.py for the sync client: the answer to
a ``get_response`` question reaches the orchestrator only if the next utterance
carries the ``response_mode`` the hub returned (OVOS-SESSION-1 §2.1).
"""
import json
import time
from unittest.mock import AsyncMock, patch

import pytest
from ovos_bus_client.message import Message
from ovos_bus_client.session import Session

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from tests.test_async_client import _bare_client


def _client(site_id="s"):
    client = _bare_client(_site_id=site_id)
    client._ws = AsyncMock()
    client.connected_event.set()
    return client


def _hub_speaks(client, session: Session):
    reply = Message("speak", {"utterance": "what is your name"},
                    {"destination": "t", "session": session.serialize()})
    client._handle_hive_protocol(HiveMessage(HiveMessageType.BUS, reply))


def _waiting_session(session_id: str, skill_id: str = "ask.skill") -> Session:
    sess = Session(session_id=session_id)
    sess.enable_response_mode(skill_id)
    return sess


async def _utter(client, text="Miro") -> dict:
    """Emit an utterance and return the session the client put on the wire."""
    await client.emit(Message("recognizer_loop:utterance",
                              {"utterances": [text], "lang": "en-US"}))
    frame = json.loads(client._ws.send.call_args[0][0])
    return frame["payload"]["context"]["session"]


@pytest.mark.asyncio
async def test_response_mode_from_the_hub_reaches_the_next_utterance():
    client = _client()
    _hub_speaks(client, _waiting_session(client.session_id))

    sess = await _utter(client)

    assert sess["session_id"] == client.session_id
    assert sess["response_mode"]["skill_id"] == "ask.skill"
    assert sess["response_mode"]["expires_at"] > time.time()


@pytest.mark.asyncio
async def test_site_id_stays_the_clients():
    client = _client(site_id="kitchen")
    hub_copy = _waiting_session(client.session_id)
    hub_copy.site_id = "hub-side-site"
    _hub_speaks(client, hub_copy)

    assert (await _utter(client))["site_id"] == "kitchen"


@pytest.mark.asyncio
async def test_first_utterance_still_sends_the_bare_ids():
    client = _client()

    assert set(await _utter(client)) == {"session_id", "site_id"}


@pytest.mark.asyncio
async def test_a_session_set_by_the_caller_is_kept():
    client = _client()
    _hub_speaks(client, _waiting_session(client.session_id))

    await client.emit(Message("recognizer_loop:utterance", {"utterances": ["a"]},
                              {"session": {"session_id": client.session_id,
                                           "lang": "pt-PT"}}))
    sess = json.loads(client._ws.send.call_args[0][0])["payload"]["context"]["session"]

    assert sess["lang"] == "pt-PT"
    assert "response_mode" not in sess


@pytest.mark.asyncio
async def test_a_session_for_another_id_is_not_adopted():
    client = _client()
    _hub_speaks(client, _waiting_session("someone-elses-session"))

    sess = await _utter(client)

    assert sess["session_id"] == client.session_id
    assert "response_mode" not in sess


@pytest.mark.asyncio
async def test_a_hub_notice_without_a_session_is_not_adopted():
    client = _client()
    notice = Message("hive.policy.denied", {"code": "acl_disallowed_type"},
                     {"source": "hivemind-core", "destination": "t"})
    client._handle_hive_protocol(HiveMessage(HiveMessageType.BUS, notice))

    assert set(await _utter(client)) == {"session_id", "site_id"}


@pytest.mark.asyncio
async def test_the_session_is_kept_until_the_hub_sends_another():
    client = _client()
    _hub_speaks(client, _waiting_session(client.session_id))

    await _utter(client, "a")
    assert (await _utter(client, "b"))["response_mode"]["skill_id"] == "ask.skill"

    _hub_speaks(client, Session(session_id=client.session_id))
    assert "response_mode" not in await _utter(client, "c")


@pytest.mark.asyncio
async def test_override_fields_from_the_hub_are_not_sent_again():
    client = _client(site_id="kitchen")
    returned = _waiting_session(client.session_id)
    returned.pipeline = ["old-pipeline-stage"]
    returned.blacklisted_skills = ["blocked.skill"]
    _hub_speaks(client, returned)

    sent = await _utter(client)

    assert set(sent) == {"session_id", "site_id", "response_mode"}
    assert sent["site_id"] == "kitchen"
    assert sent["response_mode"]["skill_id"] == "ask.skill"


@pytest.mark.asyncio
async def test_the_other_state_record_fields_are_sent_again():
    client = _client()
    returned = Session(
        session_id=client.session_id,
        active_handlers=[{"skill_id": "a.skill", "activated_at": 123.0}],
        converse_handlers=[{"skill_id": "c.skill", "activated_at": 124.0}])
    returned.intent_context = {"frame": "x"}
    _hub_speaks(client, returned)

    sent = await _utter(client, "a")

    assert sent["active_handlers"] == [{"skill_id": "a.skill", "activated_at": 123.0}]
    assert sent["converse_handlers"] == [{"skill_id": "c.skill", "activated_at": 124.0}]
    assert sent["intent_context"] == {"frame": "x"}


@pytest.mark.asyncio
async def test_an_expired_response_mode_is_not_sent():
    client = _client()
    returned = _waiting_session(client.session_id)
    returned.response_mode["expires_at"] = time.time() - 1
    _hub_speaks(client, returned)

    assert "response_mode" not in await _utter(client, "a")


@pytest.mark.asyncio
async def test_a_response_mode_that_expires_between_turns_is_not_sent():
    client = _client()
    returned = _waiting_session(client.session_id)
    expires_at = returned.response_mode["expires_at"]
    _hub_speaks(client, returned)

    assert (await _utter(client, "a"))["response_mode"]["expires_at"] == expires_at

    with patch("time.time", return_value=expires_at + 1):
        assert "response_mode" not in await _utter(client, "b")
