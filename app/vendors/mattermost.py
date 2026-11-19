"""Mattermost server: REST API v4 (token auth) for users, teams, channels, posts and
files, read by the OpenCTI mattermost connector (``mattermostdriver``)."""

import time

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["mattermost.example.org"]
router = APIRouter(prefix="/mattermost", tags=["Mattermost"])

PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c6360f8cfc0f01f0005000201a5f645400000000049454e44ae426082"
)


def _id() -> str:
    return fake.bothify("#?" * 13, letters="abcdefghijklmnopqrstuvwxyz")


@router.get("/api/v4/users/me")
async def me() -> dict:
    return {"id": _id(), "username": "octi-bot", "email": "octi-bot@example.org"}


@router.get("/api/v4/users/{user_id}")
async def user(user_id: str) -> dict:
    """The email of an author, derived from its id."""
    return {
        "id": user_id,
        "username": f"user-{user_id[:6]}",
        "email": f"{user_id[:10]}@example.org",
    }


@router.get("/api/v4/channels/{channel_id}")
async def channel(channel_id: str) -> dict:
    """A channel of a team, named afresh on every call."""
    name = f"{fake.word()}-{fake.random_int(100, 999)}"
    return {
        "id": channel_id,
        "team_id": channel_id[::-1],
        "name": name,
        "display_name": name.title(),
        "type": "O",
        "purpose": fake.sentence(),
        "header": fake.sentence(nb_words=4),
    }


@router.get("/api/v4/teams/{team_id}")
async def team(team_id: str) -> dict:
    return {"id": team_id, "name": f"team-{fake.random_int(100, 999)}"}


@router.get("/api/v4/channels/{channel_id}/posts")
async def posts(channel_id: str) -> dict:
    """Newest first: three authors, a root post with a reply, and posts with files."""
    users = [_id() for _ in range(3)]
    now = int(time.time() * 1000)
    items = {}
    for age, user_id in enumerate(users + users[:2]):
        post_id = _id()
        items[post_id] = {
            "id": post_id,
            "create_at": now - age * 60_000,
            "update_at": now - age * 60_000,
            "delete_at": 0,
            "user_id": user_id,
            "channel_id": channel_id,
            "root_id": "",
            "message": f"{fake.sentence()} {fake.domain_name()}",
            "type": "",
            "metadata": {"files": []},
        }
    order = list(items)
    items[order[1]]["root_id"] = order[0]
    items[order[3]]["metadata"]["files"] = [
        {
            "id": _id(),
            "name": "capture.png",
            "mime_type": "image/png",
            "size": len(PNG),
            "extension": "png",
        }
    ]
    items[order[4]]["delete_at"] = now - 1000
    return {"order": order, "posts": items, "next_post_id": "", "prev_post_id": ""}


@router.get("/api/v4/files/{file_id}")
async def file(file_id: str) -> Response:  # noqa: ARG001
    return Response(PNG, media_type="image/png")
