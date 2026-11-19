"""Doppel brand protection API: the alert feed (doppel import connector) and the alert
creation, lookup and takedown update (doppel-alert-takedown enrichment connector)."""

import math
import zlib
from datetime import UTC, datetime, timedelta

from faker import Faker
from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.fake import fake

HOSTS = ["api.doppel.com"]
router = APIRouter(prefix="/doppel", tags=["Doppel"])

# (product, platform, queue state) of the alerts of the feed, newest activity last
FEED = [
    ("domains", "domains", "doppel_review"),
    ("domains", "domains", "actioned"),
    ("domains", "domains", "taken_down"),
    ("social_media", "instagram", "taken_down"),
    ("email", "email", "actioned"),
    ("telco", "telco", "doppel_review"),
    ("mobile_apps", "google_play", "monitoring"),
    ("paid_ads", "google", "doppel_review"),
]


def _alert_id(entity: str) -> str:
    return f"DOP-{zlib.crc32(entity.encode()) % 90000 + 10000}"


def _seeded(rank: int, salt: int) -> Faker:
    """A Faker seeded by the alert's rank and the request's window start: paging one
    window lists the same alerts, a later run (another window) lists new ones."""
    faker = Faker()
    faker.seed_instance(rank + salt)
    return faker


def _content(product: str, rank: int, salt: int) -> tuple[str, dict]:
    """The entity of an alert and its entity_content, by product."""
    faker = _seeded(rank, salt)
    token = f"{faker.domain_word()}{rank}"
    if product == "domains":
        return f"{token}-login.{faker.tld()}", {
            "root_domain": {
                "ip_address": faker.ipv4_public(),
                "country_code": faker.country_code(),
                "registrar": faker.company(),
                "hosting_provider": faker.company(),
                "contact_email": faker.email(),
                "mx_records": [{"exchange": f"mx.{token}.com", "preference": 10}],
                "nameservers": [f"ns1.{token}.net", f"ns2.{token}.net"],
            }
        }
    if product == "telco":
        return faker.numerify("+1##########"), {}
    if product == "email":
        return faker.email(), {}
    return f"https://{token}.example.com/{faker.slug()}", {}


def _alert(
    entity: str,
    product: str,
    platform: str,
    state: str,
    activity: datetime,
    content: dict | None = None,
) -> dict:
    created = activity - timedelta(hours=5)
    alert_id = _alert_id(entity)
    return {
        "id": alert_id,
        "entity": entity,
        "brand": "Filigran",
        "product": product,
        "platform": platform,
        "source": "Doppel",
        "queue_state": state,
        "entity_state": "active",
        "severity": fake.random_element(["low", "medium", "high"]),
        "score": round(fake.random.uniform(0.3, 0.99), 2),
        "created_at": created.isoformat(),
        "last_activity_timestamp": activity.isoformat(),
        "doppel_link": f"https://app.doppel.com/alerts/{alert_id}",
        "notes": fake.sentence(),
        "uploaded_by": fake.email(),
        "assignee": fake.email(),
        "screenshot_url": f"https://cdn.doppel.com/screens/{fake.uuid4()}.png",
        "tags": [{"name": "phishing"}, {"name": "brand-abuse"}],
        "audit_logs": [
            {
                "timestamp": created.isoformat(),
                "type": "queue_state",
                "value": state,
                "changed_by": "doppel-analyst",
            }
        ],
        "entity_content": content or {},
    }


def _parse(stamp: str) -> datetime:
    parsed = datetime.fromisoformat(stamp)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


@router.get("/v1/alerts")
@router.get("/v2/alerts")
async def list_alerts(
    last_activity_timestamp: str,
    last_activity_before: str,
    page: int = 0,
    page_size: int = 100,
    sort_order: str = "asc",
) -> dict:
    """Alerts with a last activity in [timestamp, before), paged from page 0."""
    now = datetime.now(UTC).replace(microsecond=0)
    salt = zlib.crc32(last_activity_timestamp.encode())
    alerts = []
    for rank, (product, platform, state) in enumerate(FEED):
        # Activity every few minutes, the oldest first, all in the last hour
        activity = now - timedelta(minutes=(len(FEED) - rank) * 5)
        entity, content = _content(product, rank, salt)
        alerts.append(_alert(entity, product, platform, state, activity, content))
    low, high = _parse(last_activity_timestamp), _parse(last_activity_before)
    selected = [a for a in alerts if low <= _parse(a["last_activity_timestamp"]) < high]
    selected.sort(
        key=lambda a: a["last_activity_timestamp"], reverse=sort_order == "desc"
    )
    window = selected[page * page_size : (page + 1) * page_size]
    return {
        "alerts": window,
        "metadata": {
            "count": len(selected),
            "page": page,
            "page_size": page_size,
            "total_pages": math.ceil(len(selected) / page_size),
        },
    }


@router.post("/oauth/token")
async def oauth_token() -> dict:
    """The V2 client credentials grant."""
    return {
        "access_token": fake.sha256(),
        "token_type": "Bearer",
        "expires_in": 3600,
    }


class AlertCreation(BaseModel):
    entity: str
    entity_type: str = "domain"
    tags: list[str] = []


class AlertUpdate(BaseModel):
    queue_state: str | None = None
    entity_state: str | None = None
    comment: str | None = None
    tag_action: str | None = None
    tag_name: str | None = None


@router.post("/v1/alert")
async def create_alert(body: AlertCreation) -> dict:
    """The alert Doppel opens for a reported entity, in review."""
    now = datetime.now(UTC).replace(microsecond=0)
    alert = _alert(body.entity, "domains", "domains", "doppel_review", now)
    alert["entity_type"] = body.entity_type
    alert["tags"] = [{"name": tag} for tag in body.tags]
    return alert


@router.get("/v1/alert")
async def get_alert(
    id: str | None = Query(None), entity: str | None = Query(None)
) -> dict:
    """One alert, by id or entity."""
    now = datetime.now(UTC).replace(microsecond=0)
    alert = _alert(
        entity or "reported.example.com", "domains", "domains", "doppel_review", now
    )
    if id:
        alert["id"] = id
    return alert


@router.put("/v1/alert")
async def update_alert(
    body: AlertUpdate, id: str | None = Query(None), entity: str | None = Query(None)
) -> dict:
    """The alert after the update (queue state, entity state, comment, tags)."""
    now = datetime.now(UTC).replace(microsecond=0)
    alert = _alert(
        entity or "reported.example.com", "domains", "domains", "doppel_review", now
    )
    if id:
        alert["id"] = id
    if body.queue_state:
        alert["queue_state"] = body.queue_state
    if body.entity_state:
        alert["entity_state"] = body.entity_state
    return alert
