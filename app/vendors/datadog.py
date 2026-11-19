"""Datadog: Security Monitoring signals (v2) read by the OpenCTI datadog connector, and
the threat intel feed (gzipped JSON) the OpenCTI datadog-intel stream connector pushes
to.

Pushed batches arrive gzipped: the endpoint also posts their decoded content to
``.../threat-intel-feed/received`` so the journal (which shows request bodies as text)
holds the indicators that were sent.
"""

import gzip
import json
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import APIRouter, HTTPException, Request

from app.fake import fake

HOSTS = ["api.datadoghq.com", "app.datadoghq.com"]
router = APIRouter(prefix="/datadog", tags=["Datadog"])

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SIGNALS: list[dict] = []
BUILT_AT: list[datetime] = []


def _signal(index: int) -> dict:
    moment = datetime.now(UTC) - timedelta(minutes=10 + index * 37)
    host = fake.domain_name()
    # Timestamps come as ISO strings or epoch milliseconds
    timestamp = moment.isoformat() if index % 2 else int(moment.timestamp() * 1000)
    return {
        "id": fake.uuid4(),
        "type": "signal",
        "attributes": {
            "timestamp": timestamp,
            "severity": SEVERITIES[index % len(SEVERITIES)],
            "status": fake.random_element(["open", "under_review", "archived"]),
            "message": f"Suspicious activity on {host} %%% {{}} %%% reported by "
            f"{fake.email()}",
            "tags": ["env:prod", "source:appsec", f"team:{fake.word()}"],
            "service": [fake.word(), fake.word()],
            "attributes": {
                "title": f"Attack attempt against {host}",
                "workflow": {
                    "rule": {
                        "id": fake.bothify("???-???-???").lower(),
                        "name": "Web application attack",
                        "tags": ["tactic:TA0001-initial-access"],
                        "query": "@appsec.attack_attempt:true",
                        "creation_author_handle": fake.email(),
                    },
                    "triage": {"assignee": {"handle": fake.email()}},
                },
                "appsec": {
                    "attack_attempt": "sql_injection",
                    "category": "attack_attempt",
                    "blocked": False,
                },
                "http": {
                    "client_ip": fake.ipv4_public(),
                    "client_ip_details": {
                        "country": {"name": "France"},
                        "city": {"name": "Paris"},
                        "as": {
                            "name": "Example Net",
                            "number": "AS64500",
                            "type": "hosting",
                        },
                    },
                    "method": "POST",
                    "status_code": 403,
                    "url": f"https://{host}/login?next=/admin",
                    "url_details": {"host": host, "path": ["/login"]},
                    "useragent": "Mozilla/5.0 (X11; Linux x86_64) sqlmap/1.7",
                },
            },
        },
    }


@router.get("/api/v2/security_monitoring/signals")
async def signals(request: Request) -> dict:
    """Signals in pages of ``page[limit]``, chained by ``page[cursor]``."""
    params = request.query_params
    if not request.headers.get("dd-api-key") or not request.headers.get(
        "dd-application-key"
    ):
        raise HTTPException(403, "Forbidden")
    if not SIGNALS or datetime.now(UTC) - BUILT_AT[0] > timedelta(minutes=30):
        SIGNALS[:] = [_signal(i) for i in range(7)]
        BUILT_AT[:] = [datetime.now(UTC)]
    limit = int(params.get("page[limit]", 10))
    start = int(params.get("page[cursor]", 0))
    page = SIGNALS[start : start + limit]
    meta = (
        {"page": {"after": str(start + limit)}} if start + limit < len(SIGNALS) else {}
    )
    return {"data": page, "meta": meta}


@router.post("/api/v2/security/threat-intel-feed")
async def threat_intel_feed(request: Request) -> dict:
    """A gzipped batch of OpenCTI indicator events, with the Datadog keys."""
    headers = request.headers
    if not headers.get("dd-api-key") or not headers.get("dd-application-key"):
        raise HTTPException(403, "Forbidden")
    body = await request.body()
    if headers.get("content-encoding") == "gzip":
        body = gzip.decompress(body)
    indicators = json.loads(body)
    async with httpx.AsyncClient(base_url=str(request.base_url)) as client:
        await client.post(
            "/datadog/api/v2/security/threat-intel-feed/received",
            json={"vendor": headers.get("ti_vendor"), "indicators": indicators},
        )
    return {"status": "ok", "received": len(indicators)}


@router.post("/api/v2/security/threat-intel-feed/received")
async def received(payload: dict) -> dict:
    return {"received": len(payload.get("indicators", []))}
