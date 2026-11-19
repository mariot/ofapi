"""IronNet ThreatAnalysis: the daily threat feed (indicator -> port -> entries), read by
the OpenCTI ironnet connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.threatanalysis.io"]
router = APIRouter(prefix="/ironnet", tags=["IronNet"])

THREAT_TYPES = ["botnet", "malware", "c2", "phishing"]


def _entry(kind: str, indicator: str, port: int, threat: str) -> dict:
    return {
        "type": kind,
        "indicator": indicator,
        "port": port,
        "last_seen": fake.date_time_between("-2d", "now").strftime(
            "%Y-%m-%dT%H:%M:%S+00:00"
        ),
        "threat": threat,
        "threat_type": fake.random_element(THREAT_TYPES),
        "confidence": fake.random_element(["Low", "Medium", "High"]),
        "tlp": fake.random_element(["WHITE", "GREEN", "AMBER"]),
    }


@router.get("/prod/all/1d/json")
async def feed_1d() -> dict:
    """The indicators of the last day: domains and addresses with the threats seen on
    each port."""
    feed: dict[str, dict[str, list[dict]]] = {}
    for _ in range(4):
        kind, indicator = "ipv4-addr", fake.ipv4_public()
        feed[indicator] = {
            str(port): [_entry(kind, indicator, port, fake.malware_family())]
            for port in (80, 443)
        }
    for _ in range(3):
        indicator = fake.domain_name()
        threats = [fake.malware_family(), fake.malware_family()]
        feed[indicator] = {
            "443": [_entry("domain-name", indicator, 443, t) for t in threats]
        }
    indicator = fake.ipv6()
    feed[indicator] = {"8080": [_entry("ipv6-addr", indicator, 8080, "Emotet")]}
    return feed
