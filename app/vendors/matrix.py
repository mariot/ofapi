"""Matrix homeserver: password login, key upload, ``/sync`` and media download (client
API), read by the OpenCTI matrix connector (``matrix-nio``).

``matrix-nio`` ignores proxy variables: the connector's ``MATRIX_SERVER`` points at
this module directly.
"""

import asyncio
import base64
import time
import uuid

from fastapi import APIRouter, Query, Response

from app.fake import fake

HOSTS = ["matrix.staticfire.test"]
router = APIRouter(prefix="/matrix", tags=["Matrix"])

SERVER = "matrix.example.org"
BOT = f"@octi-bot:{SERVER}"
# a 1x1 transparent PNG
PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA"
    "60e6kgAAAABJRU5ErkJggg=="
)


def _event_id() -> str:
    return f"${uuid.uuid4().hex}"


def _now_ms(minutes_ago: int = 0) -> int:
    return int((time.time() - minutes_ago * 60) * 1000)


def _event(sender: str, content: dict, minutes_ago: int) -> dict:
    return {
        "type": "m.room.message",
        "event_id": _event_id(),
        "sender": sender,
        "origin_server_ts": _now_ms(minutes_ago),
        "content": content,
        "unsigned": {"age": minutes_ago * 60000},
    }


def _state(kind: str, state_key: str, content: dict, sender: str) -> dict:
    return {
        "type": kind,
        "state_key": state_key,
        "event_id": _event_id(),
        "sender": sender,
        "origin_server_ts": _now_ms(600),
        "content": content,
    }


def _room(name: str, users: list[str]) -> tuple[str, dict]:
    """A room with text posts, a notice, a thread reply, an edit and attachments."""
    room_id = f"!{uuid.uuid4().hex[:18]}:{SERVER}"
    state = [
        _state(
            "m.room.create", "", {"creator": users[0], "room_version": "10"}, users[0]
        ),
        _state("m.room.name", "", {"name": name}, users[0]),
        *(
            _state("m.room.member", user, {"membership": "join"}, user)
            for user in [*users, BOT]
        ),
    ]
    root = _event(users[0], {"msgtype": "m.text", "body": fake.sentence()}, 50)
    events = [
        root,
        _event(
            users[1], {"msgtype": "m.text", "body": f"New C2 {fake.ipv4_public()}"}, 45
        ),
        _event(users[0], {"msgtype": "m.notice", "body": fake.sentence()}, 40),
        _event(
            users[1],
            {
                "msgtype": "m.text",
                "body": fake.sentence(),
                "m.relates_to": {"rel_type": "m.thread", "event_id": root["event_id"]},
            },
            35,
        ),
        _event(
            users[0],
            {
                "msgtype": "m.text",
                "body": "* corrected sentence",
                "m.new_content": {"msgtype": "m.text", "body": "corrected sentence"},
                "m.relates_to": {"rel_type": "m.replace", "event_id": root["event_id"]},
            },
            30,
        ),
        _event(
            users[1],
            {
                "msgtype": "m.image",
                "body": "screenshot.png",
                "url": f"mxc://{SERVER}/{uuid.uuid4().hex[:24]}",
                "info": {"mimetype": "image/png", "size": len(PIXEL)},
            },
            25,
        ),
        _event(
            users[0],
            {
                "msgtype": "m.file",
                "body": "iocs.txt",
                "url": f"mxc://{SERVER}/{uuid.uuid4().hex[:24]}",
                "info": {"mimetype": "text/plain", "size": 12},
            },
            20,
        ),
    ]
    joined = {
        "timeline": {"events": events, "limited": False, "prev_batch": "p0"},
        "state": {"events": state},
        "ephemeral": {"events": []},
        "account_data": {"events": []},
        "unread_notifications": {"highlight_count": 0, "notification_count": 0},
    }
    return room_id, joined


@router.post("/_matrix/client/v3/login")
async def login() -> dict:
    return {
        "user_id": BOT,
        "access_token": f"syt_{uuid.uuid4().hex}",
        "device_id": "STATICFIRE",
        "home_server": SERVER,
    }


@router.post("/_matrix/client/v3/keys/upload")
async def keys_upload() -> dict:
    return {"one_time_key_counts": {"signed_curve25519": 50}}


@router.post("/_matrix/client/v3/keys/query")
async def keys_query() -> dict:
    return {"device_keys": {}, "failures": {}}


@router.get("/_matrix/client/v3/sync")
async def sync(since: str | None = Query(None)) -> dict:
    """The joined rooms and their history at the first call; then long polls, empty."""
    body = {
        "next_batch": "s1",
        "device_one_time_keys_count": {"signed_curve25519": 50},
        "device_lists": {"changed": [], "left": []},
        "to_device": {"events": []},
        "presence": {"events": []},
        "account_data": {"events": []},
        "rooms": {"join": {}, "invite": {}, "leave": {}},
    }
    if since:
        await asyncio.sleep(20)
        return body
    alice, bob = f"@alice:{SERVER}", f"@bob:{SERVER}"
    for name in ("Threat intel sharing", "Incident response"):
        room_id, joined = _room(name, [alice, bob])
        body["rooms"]["join"][room_id] = joined
    return body


@router.get("/_matrix/client/v1/media/download/{server}/{media_id}")
@router.get("/_matrix/media/v3/download/{server}/{media_id}")
async def download(server: str, media_id: str) -> Response:  # noqa: ARG001
    return Response(PIXEL, media_type="image/png")
