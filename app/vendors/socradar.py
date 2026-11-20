"""SOCRadar: threat feed lists (socradar connector)."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["platform.socradar.com"]
router = APIRouter(prefix="/socradar", tags=["SOCRadar"])


def _item(feed_type: str, value: str) -> dict:
    first = datetime.now(UTC) - timedelta(days=fake.random_int(2, 20))
    last = first + timedelta(days=fake.random_int(0, 5))
    return {
        "feed": value,
        "feed_type": feed_type,
        "first_seen_date": first.strftime("%Y-%m-%dT%H:%M:%S"),
        "latest_seen_date": last.strftime("%Y-%m-%dT%H:%M:%S"),
        "maintainer_name": fake.random_element(["SOCRadar", "Abuse.ch", "Spamhaus"]),
        "extra_info": {
            "score": fake.random_int(40, 100),
            "seen_count": fake.random_int(1, 50),
        },
    }


@router.get("/api/threat/intelligence/feed_list/{collection}.json")
async def feed_list(collection: str) -> list[dict]:  # noqa: ARG001
    """The items of a feed list: addresses, domains, URLs and file hashes."""
    return [
        _item("ip", fake.ipv4_public()),
        _item("ip", fake.ipv4_public()),
        _item("domain", fake.domain_name()),
        _item("url", fake.url()),
        _item("md5", fake.md5()),
        _item("sha1", fake.sha1()),
        _item("sha256", fake.sha256()),
    ]
