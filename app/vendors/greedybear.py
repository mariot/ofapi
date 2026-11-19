"""GreedyBear (honeynet.org honeypot feeds): advanced IoC feed, ASN feed, standard feed
and enrichment, read by the OpenCTI greedybear connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["greedybear.honeynet.org"]
router = APIRouter(prefix="/greedybear", tags=["GreedyBear"])

HONEYPOTS = ["cowrie", "log4pot", "heralding", "ciscoasa", "dionaea"]
REPUTATIONS = ["known attacker", "mass scanner", "tor exit node", ""]
ASNS = {
    16276: "OVH SAS",
    14061: "DIGITALOCEAN-ASN",
    4134: "CHINANET-BACKBONE",
    45090: "Shenzhen Tencent Computer Systems",
}
LICENSE = "https://greedybear.honeynet.org/api/feeds/license (CC BY-NC 4.0)"


def _day(days_ago: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%d")


def _ioc(value: str, geolocated: bool = True) -> dict:
    """One entry of FeedsResponseSerializer (a domain has no GeoIP data)."""
    scanner = fake.boolean()
    ioc = {
        "value": value,
        "feed_type": fake.random_elements(HONEYPOTS, length=2, unique=True),
        "scanner": scanner,
        "payload_request": not scanner,
        "first_seen": _day(fake.random_int(2, 3)),
        "last_seen": _day(fake.random_int(0, 1)),
        "attack_count": fake.random_int(1, 500),
        "interaction_count": fake.random_int(1, 5000),
        "ip_reputation": fake.random_element(REPUTATIONS),
        "firehol_categories": [],
        "asn": fake.random_element(list(ASNS)),
        "destination_port_count": fake.random_int(1, 20),
        "login_attempts": fake.random_int(0, 300),
        "recurrence_probability": round(fake.random.random(), 3),
        "expected_interactions": round(fake.random.random() * 100, 2),
        "attacker_country": fake.random_element(["China", "France", "Brazil"]),
        "attacker_country_code": fake.random_element(["CN", "FR", "BR"]),
        "tags": [],
        "sensors": [],
    }
    if not geolocated:
        ioc.update(asn=None, attacker_country=None, attacker_country_code=None)
    return ioc


def _iocs() -> list[dict]:
    values = [fake.ipv4_public() for _ in range(6)] + [fake.ipv6()]
    return [_ioc(value) for value in values] + [_ioc(fake.domain_name(), False)]


@router.get("/api/feeds/advanced/")
async def advanced_feed() -> dict:
    """The enriched IoCs (token authentication)."""
    return {"iocs": _iocs(), "license": LICENSE}


@router.get("/api/feeds/asn/")
async def asn_feed() -> list[dict]:
    """The IoCs aggregated by autonomous system."""
    return [
        {
            "asn": asn,
            "as_name": name,
            "ioc_count": fake.random_int(1, 50),
            "total_attack_count": fake.random_int(1, 5000),
            "total_interaction_count": fake.random_int(1, 50000),
            "total_login_attempts": fake.random_int(0, 3000),
            "honeypots": fake.random_elements(HONEYPOTS, length=2, unique=True),
            "expected_ioc_count": round(fake.random.random() * 20, 2),
            "expected_interactions": round(fake.random.random() * 500, 2),
            "first_seen": f"{_day(3)}T08:00:00Z",
            "last_seen": f"{_day(0)}T08:00:00Z",
        }
        for asn, name in ASNS.items()
    ]


@router.get("/api/feeds/{feed_type}/{attack_type}/{prioritize}.json")
async def standard_feed(
    feed_type: str,  # noqa: ARG001
    attack_type: str,  # noqa: ARG001
    prioritize: str,  # noqa: ARG001
) -> dict:
    """The public feed, without authentication."""
    return {"iocs": _iocs(), "license": LICENSE}


@router.get("/api/enrichment")
async def enrichment(query: str) -> dict:
    """The full record of one IoC (deep enrichment)."""
    return {
        "found": True,
        "ioc": {
            **_ioc(query),
            "destination_ports": [22, 23, 80, 2222],
            "sensors": [{"address": fake.ipv4_public(), "label": "honeypot-1"}],
            "credential_count": fake.random_int(1, 40),
            "firehol_categories": ["blocklist_de", "firehol_level1"],
            "number_of_days_seen": fake.random_int(1, 30),
        },
    }
