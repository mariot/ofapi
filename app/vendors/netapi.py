"""NetAPI JSON API: the compromised feed check and the Top 1M rank, read by the OpenCTI
netapi enrichment connector."""

import ipaddress
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["netapi.com"]
router = APIRouter(prefix="/netapi", tags=["NetAPI"])

LISTS_DOMAINS = {
    "page": "https://netapi.com/compromised-urls/",
    "current": "https://netapi.com/api2/?method=compromised&dataset_type=url",
    "all_time": "https://netapi.com/api2/?method=compromised&dataset_type=url-all",
}
LISTS_IPS = {
    "page": "https://netapi.com/compromised-ips/",
    "current": "https://netapi.com/api2/?method=compromised&dataset_type=ip",
    "all_time": "https://netapi.com/api2/?method=compromised&dataset_type=ip-all",
}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _compromised_check(value: str) -> dict:
    """A value listed now in the feed: domains by public feeds, IPs by the sensors."""
    seen = datetime.now(UTC) - timedelta(hours=3)
    first = seen - timedelta(days=fake.random_int(30, 900))
    if _is_ip(value):
        return {
            "value": value,
            "type": "ip",
            "listed_now": True,
            "listed_ever": True,
            "matched_value": value,
            "first_seen": first.strftime("%Y-%m-%d"),
            "last_seen": seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "block_reason": "NetAPI network sensors: service exploit",
            "registrar": None,
            "note": "Seen in the compromised feed within the last 48 hours.",
            "lists": LISTS_IPS,
            "source": "NetAPI Nightwatch compromised IP feed (CC BY 4.0)",
        }
    return {
        "value": value,
        "type": "domain",
        "listed_now": True,
        "listed_ever": True,
        "matched_value": value,
        "first_seen": first.strftime("%Y-%m-%d"),
        "last_seen": seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "block_reason": fake.random_element(["blackbook", "phishing", "malware"]),
        "registrar": {
            "id": 1599,
            "name": "Alibaba Cloud Computing Ltd. d/b/a HiChina (www.net.cn)",
            "brand_name": "Alibaba Cloud",
            "page": "https://netapi.com/whois-alibaba-cloud-computing-ltd-d-b-a-hichina/",
        },
        "note": "Seen in the compromised feed within the last 24 hours.",
        "lists": LISTS_DOMAINS,
        "source": "NetAPI compromised feed, updated daily (CC BY 4.0)",
    }


def _domain_rank(domain: str) -> dict:
    return {
        "domain": domain,
        "in_top_1m": True,
        "rank": fake.random_int(1000, 900000),
        "snapshot_date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "tld": domain.rsplit(".", 1)[-1],
        "note": "Rank 1 = most popular. The list is rebuilt daily.",
        "links": {
            "top_1m": "https://netapi.com/top-1-mln-websites/",
            "csv": "https://netapi.com/netapi_top1mln.csv",
        },
    }


@router.get("/api-json/")
async def api_json(
    method: str,
    value: str | None = None,
    domain: str | None = None,
) -> JSONResponse:
    """The two methods of the connector, selected by the ``method`` parameter."""
    if method == "compromised-check" and value:
        return JSONResponse(_compromised_check(value))
    if method == "domain-rank" and domain:
        return JSONResponse(_domain_rank(domain))
    error = {"code": "invalid_method", "message": "unknown method or missing parameter"}
    return JSONResponse({"error": error}, status_code=400)
