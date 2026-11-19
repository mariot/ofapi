"""Lab539 AiTM Feed: the last-event pre-check and the record list, read by the OpenCTI
lab539-aitm-feed connector."""

import time

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["aitm.lab539.io"]
router = APIRouter(prefix="/lab539", tags=["Lab539"])


def _record(now: int) -> dict:
    domain = fake.domain_name()
    return {
        "hostname": f"login.{domain}",
        "domain": domain,
        "ip": fake.ipv6() if fake.boolean(20) else fake.ipv4_public(),
        "rdns": "" if fake.boolean() else fake.domain_name(),
        "asn": fake.company(),
        "frontend": fake.boolean(),
        "backend": fake.boolean(),
        "active": fake.boolean(),
        "timestamp": now - fake.random_int(0, 3600),
        "detected": now - fake.random_int(3600, 86400),
        "confidence": fake.random_element(["high", "medium", "low"]),
        "country": fake.country_code(),
        "eventid": fake.uuid4(),
    }


@router.get("/v1.0/last-event")
async def last_event() -> dict:
    return {"eventid": fake.uuid4()}


@router.get("/v1.0/list")
async def records() -> list[dict]:
    """Recent records (the connector also passes ``after``, a Unix time)."""
    now = int(time.time())
    return [_record(now) for _ in range(8)]
