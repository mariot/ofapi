"""Corelight Investigator alerts, read by the corelight-investigator connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["*.api.investigator.corelight.com"]
router = APIRouter(prefix="/corelight-investigator", tags=["Corelight Investigator"])


def _alert(src_ip: str, dst_ip: str) -> dict:
    return {
        "alert_id": fake.uuid4(),
        "EventType": fake.random_element(["Detection", "Alert"]),
        "name": f"{fake.malware_family()} command and control",
        "description": fake.sentence(),
        "severity": fake.random_int(1, 10),
        "timestamp": fake.date_time_between("-3d", "now", tzinfo=None).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "src_ip": src_ip,
        "dest_ip": dst_ip,
    }


@router.get("/api/v1/alerts")
async def alerts(limit: int = 1000) -> dict:
    """Alerts between internal hosts and public addresses, one with an IPv6 peer."""
    items = [_alert(fake.ipv4_private(), fake.ipv4_public()) for _ in range(5)]
    items.append(_alert(fake.ipv6(), fake.ipv4_public()))
    return {"data": items[:limit]}
