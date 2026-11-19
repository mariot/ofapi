"""FortiSIEM supervisor: incidents (fortisiem-incidents external-import connector) and
watch lists (fortisiem stream connector)."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request

from app.fake import fake

HOSTS = ["fortisiem.staticfire.test"]
router = APIRouter(prefix="/fortisiem", tags=["FortiSIEM"])

TITLES = [
    "Suspicious login from rare location",
    "Brute force on VPN gateway",
    "Outbound traffic to known C2",
    "Malware detected on endpoint",
    "Port scan from external host",
]


def _check_auth(request: Request) -> None:
    if not request.headers.get("authorization", "").startswith("Basic "):
        raise HTTPException(401, "authentication required")


@router.get("/phoenix/rest/pub/incident")
async def incidents(request: Request, update_from: str = "") -> list[dict]:
    """The incidents seen recently, with epoch-millisecond timestamps and the network
    fields the connector turns into observables (one has a domain host name)."""
    _check_auth(request)
    now = datetime.now(UTC)
    since = datetime.fromisoformat(update_from) if update_from else None
    found = []
    for index, title in enumerate(TITLES):
        first_seen = now - timedelta(hours=index * 5 + 2)
        last_seen = first_seen + timedelta(hours=1)
        if since and last_seen < since:
            continue
        found.append(
            {
                "incidentId": 1000 + index,
                "incidentTitle": title,
                "incidentDetail": fake.sentence(),
                "incidentSeverity": [3, 5, 8, 9, 6][index],
                "incidentFirstSeen": int(first_seen.timestamp() * 1000),
                "incidentLastSeen": int(last_seen.timestamp() * 1000),
                "srcIpAddr": fake.ipv4_public(),
                "destIpAddr": fake.ipv6() if index == 2 else fake.ipv4_private(),
                "hostIpAddr": fake.ipv4_private(),
                "hostName": fake.domain_name() if index != 4 else "workstation-12",
            }
        )
    return found


@router.post("/phoenix/rest/watchlist/addTo")
async def watchlist_add(request: Request) -> dict:
    """Add entries to a watch list."""
    _check_auth(request)
    body = await request.json()
    entries = body.get("json_body") or []
    if not entries or not body.get("parameters", {}).get("watchlistId"):
        raise HTTPException(400, "watchlistId and entries are required")
    return {"added": len(entries)}
