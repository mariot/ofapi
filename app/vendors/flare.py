"""Flare: token generation, the tenant event feed (cursor scrolled) and the event detail
(flare external import connector, through flareio)."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["api.flare.io", "api.eu.flare.io"]
router = APIRouter(prefix="/flare", tags=["Flare"])

SEVERITIES = ["info", "low", "medium", "high", "critical"]
# uid -> the event listed by the feed, served again by its detail
FEED: dict[str, dict] = {}


def timestamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def event_data(index: str, uid: str, created: datetime) -> dict:
    """The ``data`` of an event of one of the types the connector maps."""
    data = {
        "uid": uid,
        "index": index,
        "metadata": {
            "flare_url": f"https://app.flare.io/#/{index}/{uid}",
            "estimated_created_at": timestamp(created),
            "first_crawled_at": timestamp(created),
        },
    }
    if index == "stealer_log":
        data["features"] = {
            "emails": [fake.email(), fake.email()],
            "usernames": [fake.user_name()],
            "ip_addresses": [fake.ipv4_public(), fake.ipv6()],
        }
        data["malware_information"] = {"malware_family": fake.malware_family()}
    elif index == "leak":
        data["id"] = fake.email()
        data["identity_name"] = fake.email()
    elif index == "domain":
        data["identifier_domain"] = [fake.domain_name()]
        data["name"] = fake.domain_name()
    elif index == "ransomleak":
        data["docmeta"] = {"title": f"{fake.company()} data leak"}
        data["url"] = f"http://{fake.lexify('?' * 16)}.onion/{fake.slug()}"
        data["victim_metadata"] = {"name": fake.company()}
    return data


@router.post("/tokens/generate")
async def generate_token() -> dict:
    """A short-lived API token for the key sent as Authorization."""
    return {"token": f"staticfire.{uuid.uuid4().hex}"}


@router.post("/firework/v4/events/tenant/_search")
@router.post("/firework/v4/events/identifier_groups/{group}/_search")
async def search_events(request: Request) -> dict:
    """Two pages of events, scrolled by the ``next`` cursor, none after."""
    body = await request.json()
    cursor = body.get("from")
    if cursor and cursor != "page-2":
        return {"items": [], "next": None}
    now = datetime.now(UTC)
    page = 2 if cursor else 1
    items = []
    for number, index in enumerate(["stealer_log", "leak", "domain", "ransomleak"]):
        uid = f"{index}/{uuid.uuid4().hex}"
        created = now - timedelta(days=page, hours=number * 3)
        FEED[uid] = event_data(index, uid, created)
        override = fake.random_element(SEVERITIES)
        items.append(
            {
                "metadata": {
                    "uid": uid,
                    "matched_at": timestamp(created + timedelta(minutes=5)),
                    "severity": fake.random_element(SEVERITIES),
                },
                "tenant_metadata": {
                    "severity": {"original": "medium", "override": override},
                    "notes": fake.sentence(),
                    "tags": [],
                },
            }
        )
    return {"items": items, "next": None if cursor else "page-2"}


@router.get("/firework/v2/activities/{uid:path}")
async def activity(uid: str) -> dict:
    """The detail of an event listed by the feed."""
    index = uid.split("/", 1)[0]
    data = FEED.get(uid) or event_data(index, uid, datetime.now(UTC))
    return {
        "activity": {
            "data": data,
            "header": {"remediated_at": None, "ignored_at": None},
        }
    }
