"""WhoisFreaks: daily feed status, threat feeds and newly registered domains (CSV),
read by the OpenCTI whoisfreaks connector."""

import csv
import io
from datetime import UTC, datetime

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import PlainTextResponse

from app.fake import fake

HOSTS = ["files.whoisfreaks.com"]
router = APIRouter(prefix="/whoisfreaks", tags=["WhoisFreaks"])

TOTAL = 7
THREAT_TYPES = ["malware", "phishing", "spam"]
THREAT_COLUMNS = [
    "domain",
    "threat_type",
    "confidence",
    "first_seen",
    "last_seen",
    "No_of_threat_matched_pivots",
]
NRD_COLUMNS = [
    "num",
    "domain_name",
    "query_time",
    "create_date",
    "update_date",
    "expiry_date",
    "domain_registrar_name",
    "domain_registrar_url",
    "registrant_name",
    "registrant_country_code",
    "registrant_email",
    "name_server_1",
    "name_server_2",
    "domain_status_1",
]


def _auth(key: str | None) -> None:
    if not key:
        raise HTTPException(401, "API key missing")


def _csv(columns: list[str], rows: list[list]) -> PlainTextResponse:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(columns)
    writer.writerows(rows)
    return PlainTextResponse(out.getvalue(), media_type="text/csv")


def _page(offset: int, limit: int) -> int:
    """How many rows the page holds: the feed has TOTAL rows, then ends."""
    return max(0, min(limit, TOTAL - offset))


@router.get("/v3.4/status")
async def status(x_api_key: str | None = Header(None)) -> dict:
    """Latest snapshot of each feed."""
    _auth(x_api_key)
    today = datetime.now(UTC).date().isoformat()
    feed = {"last_update": today, "available_from": today}
    return {
        "threat_feed": dict.fromkeys(THREAT_TYPES, feed),
        "newly": {"gtld": feed, "cctld": feed},
    }


@router.get("/v3.4/stream/threat-feed/{feed_type}")
async def threat_feed(
    feed_type: str,
    offset: int = 0,
    limit: int = 5000,
    x_api_key: str | None = Header(None),
) -> PlainTextResponse:
    """Threat feed rows of one day, a page at a time."""
    _auth(x_api_key)
    rows = []
    for _ in range(_page(offset, limit)):
        seen = fake.date_time_between("-3d", "-1h")
        rows.append(
            [
                fake.domain_name(),
                feed_type,
                round(fake.pyfloat(min_value=0.4, max_value=1, right_digits=2), 2),
                seen.strftime("%Y-%m-%d %H:%M:%S"),
                datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
                fake.random_int(0, 12),
            ]
        )
    return _csv(THREAT_COLUMNS, rows)


@router.get("/v3.3/stream/domainer/{feed_type}")
async def newly_registered(
    feed_type: str,  # noqa: ARG001
    whois: str = "false",
    offset: int = 0,
    limit: int = 5000,
    x_api_key: str | None = Header(None),
) -> PlainTextResponse:
    """Newly registered domains: WHOIS CSV, or bare domain lines without a header."""
    _auth(x_api_key)
    count = _page(offset, limit)
    if whois != "true":
        lines = [fake.domain_name() for _ in range(count)]
        return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""))
    now = datetime.now(UTC)
    rows = []
    for number in range(offset + 1, offset + count + 1):
        created = fake.date_time_between("-2d", "-1h")
        rows.append(
            [
                number,
                fake.domain_name(),
                now.strftime("%Y-%m-%d"),
                created.strftime("%Y-%m-%d"),
                created.strftime("%Y-%m-%d"),
                created.replace(year=created.year + 1).strftime("%Y-%m-%d"),
                fake.company(),
                fake.url(),
                fake.name(),
                fake.country_code(),
                fake.email(),
                f"ns1.{fake.domain_name()}",
                f"ns2.{fake.domain_name()}",
                "clientTransferProhibited",
            ]
        )
    return _csv(NRD_COLUMNS, rows)
