"""Malbeacon: the C2 beacons seen for an address or domain, read by the OpenCTI
malbeacon enrichment connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.malbeacon.com"]
router = APIRouter(prefix="/malbeacon", tags=["Malbeacon"])


def _beacon(c2: str) -> dict:
    """One beacon: the actor (the one logging in to the C2 panel) and the C2 itself."""
    actor_ip = fake.ipv4_public()
    return {
        "tstamp": fake.date_time_this_month().strftime("%Y-%m-%d %H:%M:%S"),
        "actorasnorg": fake.company(),
        "actorcity": fake.city(),
        "actorcountrycode": fake.country_code(),
        "actorhostname": fake.domain_name() if fake.boolean() else "NA",
        "actorip": actor_ip,
        "actorloc": f"{fake.latitude()},{fake.longitude()}",
        "actorregion": fake.state(),
        "actortimezone": fake.timezone(),
        "c2": c2,
        "c2asnorg": fake.company(),
        "c2city": fake.city(),
        "c2countrycode": fake.country_code(),
        "c2domain": "NA",
        "c2domainresolved": "NA",
        "c2hostname": "NA",
        "c2loc": f"{fake.latitude()},{fake.longitude()}",
        "c2region": fake.state(),
        "c2timezone": fake.timezone(),
        "cookie_id": fake.sha1(),
        "useragent": fake.user_agent(),
        "tags": "c2,botnet",
    }


@router.get("/v1/c2/c2/{value}")
async def c2(value: str) -> list[dict]:
    return [_beacon(value) for _ in range(3)]
