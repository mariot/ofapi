"""Vectra AI: the threat feeds API (v2.5), written by the OpenCTI vectra-ai stream
connector (it creates its feed, then uploads STIX 1.2 files of indicators to it)."""

from fastapi import APIRouter, HTTPException, Request

from app.fake import fake

HOSTS = ["vectra.staticfire.test"]
router = APIRouter(prefix="/vectra-ai", tags=["Vectra AI"])

FEEDS: dict[int, dict] = {}


def _feed(feed_id: int, name: str, defaults: dict) -> dict:
    return {
        "id": feed_id,
        "name": name,
        "default_category": defaults.get("category", "cnc"),
        "default_certainty": defaults.get("certainty", "High"),
        "default_duration": defaults.get("duration", 14),
        "indicator_type": "Anonymize",
        "last_updated": fake.date_time_this_month().isoformat() + "Z",
    }


@router.get("/api/{version}/threatFeeds")
async def list_feeds(version: str) -> dict:  # noqa: ARG001
    return {"threatFeeds": list(FEEDS.values())}


@router.post("/api/{version}/threatFeeds")
async def create_feed(version: str, body: dict) -> dict:  # noqa: ARG001
    feed_id = fake.random_int(1, 9999)
    FEEDS[feed_id] = _feed(feed_id, body["name"], body.get("defaults", {}))
    return {"threatFeed": FEEDS[feed_id]}


@router.post("/api/{version}/threatFeeds/{feed_id}")
async def upload_feed(version: str, feed_id: int, request: Request) -> dict:  # noqa: ARG001
    """A STIX file posted to a feed (multipart ``file``)."""
    if feed_id not in FEEDS:
        raise HTTPException(status_code=404, detail="Threat feed not found")
    return {"threatFeed": FEEDS[feed_id], "status": "ok"}
