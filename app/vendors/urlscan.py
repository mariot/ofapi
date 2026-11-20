"""urlscan.io: the phishing feed (urlscan connector), scan submission, result, quotas
and screenshots (urlscan-enrichment connector). A result describes the URL submitted."""

import base64
from urllib.parse import urlparse

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["urlscan.io"]
router = APIRouter(prefix="/urlscan", tags=["urlscan"])

# uuid -> URL submitted, and the uuids whose result was asked once (still running)
SCANS: dict[str, str] = {}
POLLED: set[str] = set()
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/"
    "iZk9HQAAAABJRU5ErkJggg=="
)
LIMITS = {"day": 1000, "hour": 500, "minute": 60}


@router.get("/api/v1/pro/phishfeed")
async def phishfeed() -> dict:
    """Recent phishing page URLs: a blob URL and an IP host are mixed in."""
    urls = [f"https://{fake.domain_name()}/{fake.word()}/login.html" for _ in range(6)]
    urls.append(f"blob:https://{fake.domain_name()}/{fake.uuid4()}")
    urls.append(f"http://{fake.ipv4_public()}/{fake.word()}.php")
    return {"results": [{"page_url": url} for url in urls]}


@router.get("/user/quotas/")
async def quotas() -> dict:
    """Quotas per visibility and period, none used."""
    usage = {
        scope: {
            period: {"limit": limit, "used": 0, "remaining": limit, "percent": 0}
            for period, limit in LIMITS.items()
        }
        for scope in ("public", "unlisted", "private")
    }
    return {"limits": usage, "source": "apikey"}


@router.post("/api/v1/scan/")
async def scan(request: Request) -> dict:
    """Queue a scan of the URL (or domain) submitted."""
    body = await request.json()
    uuid = fake.uuid4()
    SCANS[uuid] = body["url"]
    return {
        "message": "Submission successful",
        "uuid": uuid,
        "result": f"https://urlscan.io/result/{uuid}/",
        "api": f"https://urlscan.io/api/v1/result/{uuid}/",
        "visibility": body.get("visibility", "public"),
        "url": body["url"],
    }


def _ip_stat(domains: list[str]) -> dict:
    asn = fake.random_int(1000, 399999)
    return {
        "requests": fake.random_int(1, 20),
        "domains": domains,
        "ip": fake.ipv4_public(),
        "asn": {
            "ip": fake.ipv4_public(),
            "asn": str(asn),
            "country": "US",
            "registrar": "arin",
            "date": "2005-01-01",
            "description": f"{fake.company()}, US",
            "route": "104.16.0.0/12",
            "name": fake.word().upper(),
        },
        "geoip": {"country": "US", "city": "San Francisco"},
        "countries": ["US"],
    }


@router.get("/api/v1/result/{uuid}")
@router.get("/api/v1/result/{uuid}/")
async def result(uuid: str) -> Response:
    """The scan is unfinished (404) the first time it is asked, then complete."""
    if uuid not in SCANS:
        return JSONResponse(
            {"message": "We could not find this scan", "status": 404}, status_code=404
        )
    if uuid not in POLLED:
        POLLED.add(uuid)
        return JSONResponse(
            {"message": "Scan is not finished yet", "status": 404}, status_code=404
        )
    url = SCANS[uuid]
    host = urlparse(url if "//" in url else f"http://{url}").hostname or url
    apex = ".".join(host.split(".")[-2:])
    return JSONResponse(
        {
            "data": {
                "requests": [
                    {
                        "request": {"request": {"url": url, "method": "GET"}},
                        "response": {
                            "dataLength": fake.random_int(2000, 90000),
                            "response": {"status": 200, "mimeType": "text/html"},
                        },
                    }
                ]
            },
            "stats": {
                "ipStats": [
                    _ip_stat([host]),
                    _ip_stat([f"cdn.{apex}", "fonts.gstatic.com"]),
                ]
            },
            "page": {
                "url": url,
                "domain": host,
                "apexDomain": apex,
                "title": f"Sign in to your {fake.word()} account",
                "status": "200",
            },
            "lists": {
                "servers": ["nginx", "cloudflare"],
                "ips": [fake.ipv4_public()],
                "domains": [host],
            },
            "verdicts": {
                "overall": {
                    "score": 100,
                    "malicious": True,
                    "categories": ["phishing"],
                    "brands": [fake.company().split(",")[0]],
                    "tags": ["phishing"],
                    "hasVerdicts": True,
                }
            },
            "task": {
                "uuid": uuid,
                "url": url,
                "domain": host,
                "apexDomain": apex,
                "visibility": "public",
                "reportURL": f"https://urlscan.io/result/{uuid}/",
                "screenshotURL": f"https://urlscan.io/screenshots/{uuid}.png",
                "time": "2026-01-01T00:00:00.000Z",
            },
        }
    )


@router.get("/screenshots/{name}")
async def screenshot(name: str) -> Response:  # noqa: ARG001
    return Response(PNG, media_type="image/png")
