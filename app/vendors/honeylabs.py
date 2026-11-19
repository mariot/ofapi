"""HoneyLabs: the TAXII 2.1 server of honeypot indicators (attacker addresses, malware
URLs), read by the OpenCTI honeylabs connector."""

import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["honeylabs.net"]
router = APIRouter(prefix="/honeylabs", tags=["HoneyLabs"])

TAXII_MEDIA = "application/taxii+json;version=2.1"
PAGE_SIZE = 3
TOTAL = 5
COLLECTIONS = {
    "attackers": "Attackers",
    "exploiters": "Exploiters",
    "cve-probers": "CVE probers",
    "malware-infrastructure": "Malware infrastructure",
}


def _stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def _indicator(alias: str) -> tuple[dict, datetime]:
    added = datetime.now(UTC) - timedelta(minutes=fake.random_int(5, 2000))
    if alias == "malware-infrastructure":
        value = fake.url()
        kind, name = "url", value
        labels = ["malware", fake.malware_family().lower()]
        types = ["malicious-activity"]
    else:
        value = fake.ipv4_public()
        kind, name = "ipv4-addr", value
        labels = ["scanner", "exploit-attempt"]
        types = ["malicious-activity"]
        if alias == "cve-probers":
            labels.append(fake.cve_id())
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{fake.uuid4()}",
        "created": _stamp(added),
        "modified": _stamp(added),
        "name": name,
        "description": f"Seen {fake.random_int(2, 80)} times on HoneyLabs sensors.",
        "indicator_types": types,
        "pattern": f"[{kind}:value = '{value}']",
        "pattern_type": "stix",
        "valid_from": _stamp(added),
        "valid_until": _stamp(added + timedelta(days=7)),
        "confidence": fake.random_element([60, 80, 90]),
        "labels": labels,
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
        ],
        "external_references": [
            {
                "source_name": "HoneyLabs evidence",
                "url": f"https://honeylabs.net/evidence/{fake.sha1()[:16]}",
                "description": "Captured commands and payloads",
            }
        ],
    }
    return indicator, added


@router.get("/taxii2/api/collections/")
async def collections() -> Response:
    """The collections of the API root."""
    body = {
        "collections": [
            {"id": fake.uuid4(), "title": title, "alias": alias, "can_read": True}
            for alias, title in COLLECTIONS.items()
        ]
    }
    return _taxii(body)


@router.get("/taxii2/api/collections/{alias}/objects/")
async def objects(
    alias: str, limit: int = PAGE_SIZE, next: str | None = None
) -> Response:  # noqa: A002
    """Indicators in pages of three; ``next`` is the offset of the following page."""
    offset = int(next) if next else 0
    count = min(PAGE_SIZE, limit, TOTAL - offset)
    page = sorted((_indicator(alias) for _ in range(max(count, 0))), key=lambda p: p[1])
    following = offset + count
    envelope: dict = {"objects": [indicator for indicator, _ in page]}
    if following < TOTAL:
        envelope.update(more=True, next=str(following))
    else:
        envelope["more"] = False
    headers = {"X-TAXII-Date-Added-Last": _stamp(page[-1][1])} if page else {}
    return _taxii(envelope, headers)


def _taxii(body: dict, headers: dict | None = None) -> Response:
    return Response(json.dumps(body), media_type=TAXII_MEDIA, headers=headers or {})
