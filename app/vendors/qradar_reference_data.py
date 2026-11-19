"""IBM QRadar reference data sets (the OpenCTI qradar stream connector): sets and their
entries, kept in memory. The Ariel search API of the OpenAEV collector is fake in
app/main.py under /qradar."""

import itertools
import re

from fastapi import APIRouter, HTTPException, Request

HOSTS = ["qradar.staticfire.test"]
router = APIRouter(prefix="/qradar-reference-data", tags=["QRadar reference data"])

_ids = itertools.count(1)
_sets: dict[int, dict] = {}
_entries: dict[int, dict] = {}


def _set(body: dict) -> dict:
    return {
        "id": next(_ids),
        "name": body["name"],
        "element_type": body.get("entry_type", "ALNIC"),
        "number_of_elements": 0,
        "namespace": "SHARED",
        "creation_time": 1_760_000_000_000,
        "timeout_type": "UNKNOWN",
        "time_to_live": None,
    }


@router.get("/api/reference_data_collections/sets")
async def list_sets() -> list[dict]:
    """The reference sets."""
    return list(_sets.values())


@router.post("/api/reference_data_collections/sets", status_code=201)
async def create_set(request: Request) -> dict:
    """A reference set of the given name and entry type."""
    created = _set(await request.json())
    _sets[created["id"]] = created
    return created


@router.get("/api/reference_data_collections/set_entries")
async def search_entries(filter: str = "") -> list[dict]:  # noqa: A002
    """Entries matching ``collection_id=<id> and notes="<text>"``."""
    collection = re.search(r"collection_id=(\d+)", filter)
    notes = re.search(r'notes="([^"]*)"', filter)
    return [
        entry
        for entry in _entries.values()
        if (not collection or entry["collection_id"] == int(collection.group(1)))
        and (not notes or entry["notes"] == notes.group(1))
    ]


@router.post("/api/reference_data_collections/set_entries", status_code=201)
async def create_entry(request: Request) -> dict:
    """A value in a set."""
    body = await request.json()
    if body["collection_id"] not in _sets:
        raise HTTPException(404, {"message": "The reference set does not exist"})
    entry = {"id": next(_ids), **body, "first_seen": 1_760_000_000_000}
    _entries[entry["id"]] = entry
    return entry


@router.post("/api/reference_data_collections/set_entries/{entry_id}")
async def update_entry(entry_id: int, request: Request) -> dict:
    """The entry's source and notes are replaced."""
    if entry_id not in _entries:
        raise HTTPException(404, {"message": "The entry does not exist"})
    _entries[entry_id].update(await request.json())
    return _entries[entry_id]


@router.delete(
    "/api/reference_data_collections/set_entries/{entry_id}", status_code=202
)
async def delete_entry(entry_id: int) -> dict:
    """The entry is removed."""
    _entries.pop(entry_id, None)
    return {"id": entry_id, "status": "COMPLETED"}
