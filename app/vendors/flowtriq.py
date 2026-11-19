"""Flowtriq: DDoS incidents (flowtriq external-import connector)."""

from datetime import timedelta

from fastapi import APIRouter, HTTPException, Query

from app.fake import fake

HOSTS = ["app.flowtriq.com"]
router = APIRouter(prefix="/flowtriq", tags=["Flowtriq"])

FAMILIES = ["syn_flood", "udp_flood", "dns_amplification", "ntp_amplification", "mixed"]
SEVERITIES = ["low", "medium", "high", "critical"]


def _incidents() -> list[dict]:
    incidents = []
    for index in range(6):
        started = fake.date_time_between(start_date="-3d", end_date="-1d")
        incidents.append(
            {
                "uuid": f"0f4c7d1e-5b2a-4c3d-9e8f-00000000000{index}",
                "status": "resolved",
                "severity": SEVERITIES[index % len(SEVERITIES)],
                "family": FAMILIES[index % len(FAMILIES)],
                "peak_pps": fake.random_int(10_000, 5_000_000),
                "peak_bps": fake.random_int(10_000_000, 4_000_000_000),
                "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "ended_at": (started + timedelta(minutes=17)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "node": {
                    "name": f"edge-{index}",
                    # one IPv6 target to cover that branch
                    "ip": fake.ipv6() if index == 5 else fake.ipv4_public(),
                },
            }
        )
    return incidents


INCIDENTS = _incidents()


@router.get("/api/v1/incidents")
async def incidents(
    limit: int = 50,
    offset: int = 0,
    status: str = "",
    severity: str = Query(""),
) -> dict:
    """One page of incidents, newest first, filtered like the real API."""
    found = [
        item
        for item in INCIDENTS
        if (not status or item["status"] == status)
        and (not severity or item["severity"] == severity)
    ]
    return {
        "incidents": found[offset : offset + limit],
        "total": len(found),
        "limit": limit,
        "offset": offset,
    }


@router.get("/api/v1/incidents/{uuid}")
async def incident(uuid: str) -> dict:
    """One incident with the extended data: top attack sources (some IPv6)."""
    for item in INCIDENTS:
        if item["uuid"] == uuid:
            sources = [{"ip": fake.ipv4_public(), "pps": 1000} for _ in range(3)]
            sources.append({"ip": fake.ipv6(), "pps": 500})
            return {"incident": {**item, "sp_top_sources": sources}}
    raise HTTPException(404, "incident not found")
