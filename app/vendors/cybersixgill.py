"""Cybersixgill: OAuth token and the Darkfeed IOC stream (STIX 2.1 indicators), read by
the OpenCTI cybersixgill connector through the sixgill-clients library."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.cybersixgill.com"]
router = APIRouter(prefix="/cybersixgill", tags=["Cybersixgill"])

FEEDS = [
    ("darkfeed_001", "Hashes of malware files"),
    ("darkfeed_002", "Malicious IPs"),
    ("darkfeed_003", "Malicious domains"),
    ("darkfeed_004", "Malicious URLs"),
]


def _indicator(pattern: str, feed: tuple[str, str], marking: str) -> dict:
    stamp = (datetime.now(UTC) - timedelta(minutes=fake.random_int(5, 600))).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    )[:-3]
    post_id = fake.sha1()
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{fake.uuid4()}",
        "created": f"{stamp}Z",
        "modified": f"{stamp}Z",
        "name": pattern,
        "description": f"{feed[1]} seen in an underground post",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": f"{stamp}Z",
        "labels": ["malware", "darkfeed"],
        "lang": "en",
        "object_marking_refs": [marking],
        "external_references": [
            {
                "source_name": "Sixgill",
                "url": f"https://portal.cybersixgill.com/{post_id}",
            }
        ],
        "sixgill_actor": fake.user_name(),
        "sixgill_feedid": feed[0],
        "sixgill_feedname": feed[1],
        "sixgill_postid": post_id,
        "sixgill_posttitle": fake.sentence(nb_words=5),
        "sixgill_severity": fake.random_int(60, 90),
        "sixgill_confidence": fake.random_int(60, 90),
        "sixgill_source": "forum_exploit",
    }


@router.post("/auth/token")
async def token() -> dict:
    return {"access_token": fake.sha256(), "token_type": "bearer", "expires_in": 600}


@router.get("/darkfeed/ioc")
async def ioc(limit: int = 1000) -> dict:
    """One batch of Darkfeed indicators, in a bundle starting with the TLP marking."""
    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:WHITE",
        "definition": {"tlp": "white"},
    }
    patterns = [
        f"[ipv4-addr:value = '{fake.ipv4_public()}']",
        f"[ipv4-addr:value = '{fake.ipv4_public()}']",
        f"[domain-name:value = '{fake.domain_name()}']",
        f"[url:value = 'http://{fake.domain_name()}/{fake.word()}.php']",
        f"[file:hashes.MD5 = '{fake.md5()}' OR file:hashes.'SHA-1' = '{fake.sha1()}' "
        f"OR file:hashes.'SHA-256' = '{fake.sha256()}']",
        f"[file:hashes.'SHA-256' = '{fake.sha256()}']",
    ]
    objects = [
        _indicator(pattern, FEEDS[i % len(FEEDS)], marking["id"])
        for i, pattern in enumerate(patterns)
    ]
    return {
        "type": "bundle",
        "id": f"bundle--{fake.uuid4()}",
        "objects": [marking, *objects[:limit]],
    }


@router.post("/darkfeed/ioc/ack")
async def ack() -> int:
    """Number of indicators marked as consumed."""
    return 6
