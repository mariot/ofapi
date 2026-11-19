"""RansomLook: claims, group profiles, notes, wallets, torrents and leaks (ransomlook).

The groups of the posts served are remembered: actors, torrents and leaks refer to
them, as the real corpus does.
"""

import base64
import struct
import zlib
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Query

from app.fake import fake

HOSTS = ["www.ransomlook.io"]
router = APIRouter(prefix="/ransomlook", tags=["RansomLook"])


def _png() -> str:
    """A 1x1 PNG, the capture carried by claims and locations."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    image = zlib.compress(b"\x00\xff\x00\x00")
    raw = b"\x89PNG\r\n\x1a\n"
    raw += chunk(b"IHDR", header) + chunk(b"IDAT", image) + chunk(b"IEND", b"")
    return base64.b64encode(raw).decode()


PNG = _png()
HTML = base64.b64encode(b"<html><body><h1>Leak site</h1></body></html>").decode()

_groups: list[str] = []


def _group_names() -> list[str]:
    return _groups[:2] or [fake.intrusion_set()]


def _onion() -> str:
    return f"http://{fake.pystr(min_chars=16, max_chars=16).lower()}.onion/"


@router.get("/api/posts")
async def posts(
    start: str = Query("", alias="from"),  # noqa: ARG001
    end: str = Query("", alias="to"),  # noqa: ARG001
) -> list[dict]:
    """Claims discovered in the window (the connector queries 7 days at a time)."""
    result = []
    for index in range(4):
        group = (
            fake.random_element(_groups)
            if _groups and index % 2
            else fake.intrusion_set()
        )
        if group not in _groups:
            _groups.append(group)
        result.append(
            {
                "id": str(fake.uuid4()),
                "group_name": group,
                "post_title": fake.company(),
                "discovered": (
                    datetime.now(UTC) - timedelta(hours=fake.random_int(1, 90))
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
    return result


@router.get("/api/group/{name}")
async def group(name: str) -> list:
    """The profile of a group (description, profile links, locations) and its claims."""
    return [
        {
            "name": name,
            "meta": f"<p>{name} is a ransomware operation with a data leak site.</p>",
            "profile": [fake.url()],
            "updated": "2026-11-01T10:00:00Z",
            "locations": [
                {
                    "slug": _onion(),
                    "available": True,
                    "private": False,
                    "fs": False,
                    "chat": False,
                    "admin": False,
                    "screen": PNG,
                    "source": HTML,
                },
                {"slug": _onion(), "available": False, "private": True, "chat": True},
            ],
        },
        [
            {
                "group_name": name,
                "post_title": fake.company(),
                "discovered": "2026-11-10T08:00:00Z",
            }
        ],
    ]


@router.get("/api/post/{group_name}/{title}")
async def post(group_name: str, title: str) -> dict:
    """One claim with its capture (screenshot and page source)."""
    return {
        "group_name": group_name,
        "post_title": title,
        "discovered": (datetime.now(UTC) - timedelta(hours=3)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "description": f"<p>{fake.paragraph()}</p>",
        "link": _onion() + "victim",
        "website": f"https://www.{fake.domain_name()}",
        "screen": PNG,
        "source": HTML,
    }


@router.get("/api/actors/")
async def actors() -> list[dict]:
    """The named actors."""
    return [{"name": "Named Actor", "aliases": ["na-alias"], "has_wanted": True}]


@router.get("/api/actors/{name}")
async def actor(name: str) -> dict:
    """A named actor and the groups it is explicitly tied to."""
    return {
        "name": name,
        "aliases": ["na-alias"],
        "wanted": {"fbi": {"url": "https://www.fbi.gov/wanted/cyber/named-actor"}},
        "contacts": {"telegram": "named_actor"},
        "profile": [fake.url()],
        "relations": {"groups": _group_names(), "forums": ["xss.is"], "peers": []},
    }


@router.get("/api/notes/group/{name}")
async def group_notes(name: str) -> list[dict]:
    """The ransom notes of a group."""
    return [{"id": f"{name}-note-1", "name": f"{name} ransom note"}]


@router.get("/api/notes/{note_id}")
async def note(note_id: str) -> dict:
    """A ransom note with its original text."""
    return {
        "id": note_id,
        "title": "Ransom note",
        "content": "All your files are encrypted. Contact us to recover them.",
        "format": "txt",
        "updated_at": "2026-11-05T09:00:00Z",
        "groups": _group_names(),
    }


@router.get("/api/crypto/{name}")
async def crypto(name: str) -> dict:
    """The wallets of a group by blockchain."""
    return {
        "group": name,
        "aliases": [],
        "total": 2,
        "by_chain": {
            "bitcoin": [
                {
                    "blockchain": "bitcoin",
                    "address": "bc1q" + fake.pystr(min_chars=34, max_chars=34).lower(),
                    "tx_count": 12,
                    "source": "ransom-note",
                }
            ],
            "monero": [
                {
                    "blockchain": "monero",
                    "address": "4" + fake.pystr(min_chars=94, max_chars=94),
                    "tx_count": 0,
                    "source": "ransom-note",
                }
            ],
        },
    }


@router.get("/api/torrent/health")
async def torrents(q: str = "", page: int = 1, per_page: int = 200) -> dict:
    """Torrent health records, filtered by group."""
    results = [
        {
            "infohash": fake.sha1(),
            "name": f"{q or 'leak'} archive",
            "groups": [q or _group_names()[0]],
            "webseeds": [f"https://{fake.domain_name()}/files/"],
        }
    ]
    return {
        "total": len(results),
        "page": page,
        "per_page": per_page,
        "results": results if page == 1 else [],
    }


@router.get("/api/leaks/leaks")
async def leaks() -> list[dict]:
    """The data-leak corpus."""
    return [{"id": 1, "name": "Synthetic breach"}]


@router.get("/api/leaks/leaks/{leak_id}")
async def leak(leak_id: int) -> dict:
    """A leak and the group it is explicitly attributed to."""
    if leak_id != 1:
        raise HTTPException(404)
    return {
        "id": leak_id,
        "name": "Synthetic breach",
        "columns": ["email", "password"],
        "records": 1200,
        "domain": fake.domain_name(),
        "date": "2026-11-01",
        "description": "Credentials published on a leak site.",
        "groups": _group_names()[:1],
    }
