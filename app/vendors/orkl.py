"""ORKL (orkl.eu): the public library of threat reports, read by the OpenCTI orkl
connector. Answers are wrapped in the API's ``{"data", "message", "status"}``
envelope."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["orkl.eu"]
router = APIRouter(prefix="/orkl", tags=["ORKL"])

# The API's "no known date" sentinel
NO_DATE = "0001-01-01T00:00:00Z"
SOURCES = ["Mandiant", "CrowdStrike", "ESET", "Unit 42", "Kaspersky"]

_entries: dict[str, dict] = {}


def _ok(data: object) -> dict:
    return {"data": data, "message": "", "status": "success"}


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _actor() -> dict:
    name = fake.intrusion_set()
    return {
        "id": str(uuid4()),
        "created_at": _iso(datetime.now(UTC) - timedelta(days=400)),
        "updated_at": _iso(datetime.now(UTC) - timedelta(days=2)),
        "deleted_at": None,
        "main_name": name,
        "aliases": [f"{name} ", fake.intrusion_set()],
        "source_name": f"{fake.mitre_attack_technique_id()}",
        "source_id": "MITRE",
        "tools": [fake.threat_tool(), fake.malware_family(), ""],
        "reports": None,
    }


def _entry(deleted: bool = False, dated: bool = True, actors: int = 2) -> dict:
    entry_id = str(uuid4())
    created = datetime.now(UTC) - timedelta(days=fake.random_int(1, 30))
    published = created - timedelta(days=fake.random_int(1, 90))
    title = fake.stix_report()["name"]
    entry = {
        "id": entry_id,
        "created_at": _iso(created),
        "updated_at": _iso(datetime.now(UTC)),
        "deleted_at": _iso(datetime.now(UTC)) if deleted else None,
        "sha1_hash": fake.sha1(),
        "title": title,
        "llm_title": title,
        "authors": fake.name(),
        "file_creation_date": _iso(published) if dated else NO_DATE,
        "file_modification_date": _iso(published),
        "file_size": fake.random_int(80_000, 4_000_000),
        "plain_text": "\n".join(fake.paragraph() for _ in range(6)),
        "extraction_quality": fake.random_element([1, 0.986, 0.73]),
        "language": "en",
        "sources": fake.random_elements(SOURCES, length=2, unique=True),
        "origins": ["pdf"],
        "references": [fake.url(), "not a url"],
        "report_names": [title],
        "threat_actors": [_actor() for _ in range(actors)],
        "ts_created_at": int(created.timestamp()),
        "ts_updated_at": int(datetime.now(UTC).timestamp()),
        "ts_creation_date": int(published.timestamp()),
        "ts_modification_date": int(published.timestamp()),
        "files": {
            "pdf": f"https://orkl.eu/archive/{entry_id}.pdf",
            "text": f"https://orkl.eu/archive/{entry_id}.txt",
            "img": f"https://orkl.eu/archive/{entry_id}.png",
        },
    }
    _entries[entry_id] = entry
    return entry


@router.get("/api/v1/library/version")
async def library_version() -> dict:
    return _ok({"ID": fake.random_int(1000, 5000), "date": _iso(datetime.now(UTC))})


@router.get("/api/v1/library/entries")
async def library_entries(limit: int = 10, offset: int = 0) -> dict:
    """The first page holds a few entries (a short page ends the walk): one deleted, one
    without publication date, one without threat actor."""
    if offset:
        return _ok(None)
    page = [
        _entry(),
        _entry(),
        _entry(dated=False),
        _entry(actors=0),
        _entry(deleted=True),
        _entry(actors=3),
    ]
    return _ok(page[:limit])


@router.get("/api/v1/library/version/entries")
async def library_versions(limit: int = 10, offset: int = 0) -> dict:
    """The nightly versions, newest first, each listing the entries it created."""
    if offset:
        return _ok({"entries": []})
    version = fake.random_int(1000, 5000)
    created = [_entry() for _ in range(2)]
    return _ok(
        {
            "entries": [
                {
                    "ID": version,
                    "date": _iso(datetime.now(UTC)),
                    "created_library_entries": [
                        {"id": e["id"], "label": e["title"]} for e in created
                    ],
                }
            ][:limit]
        }
    )


@router.get("/api/v1/library/entry/{entry_id}")
async def library_entry(entry_id: str) -> dict:
    if entry_id not in _entries:
        raise HTTPException(status_code=404, detail="library entry not found")
    return _ok(_entries[entry_id])
