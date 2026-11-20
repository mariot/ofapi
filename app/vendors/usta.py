"""USTA (PRODAFT) Threat Stream v4: IOC feeds (malicious URLs, phishing sites, malware
hashes: the first and last cursor paginated), compromised credential, credit card and
Deep Sight tickets, and a report PDF, read by the OpenCTI usta connector. Every feed has
two pages, the second reached through the ``next`` URL."""

import base64
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Request, Response

from app.fake import fake

HOSTS = ["usta.prodaft.com"]
router = APIRouter(prefix="/usta", tags=["USTA"])

API = "/api/threat-stream/v4"
BASE = "https://usta.prodaft.com"
PAGE_SIZE = 3
# A one page PDF
PDF = base64.b64decode(
    "JVBERi0xLjQKMSAwIG9iajw8L1R5cGUvQ2F0YWxvZy9QYWdlcyAyIDAgUiA+PmVuZG9iagoyIDAgb2Jq"
    "PDwvVHlwZS9QYWdlcy9LaWRzWzMgMCBSXS9Db3VudCAxPj5lbmRvYmoKMyAwIG9iajw8L1R5cGUvUGFn"
    "ZS9QYXJlbnQgMiAwIFIvTWVkaWFCb3hbMCAwIDIwMCAyMDBdPj5lbmRvYmoKdHJhaWxlcjw8L1Jvb3Qg"
    "MSAwIFI+PgolJUVPRgo="
)


def _created(offset: int) -> str:
    moment = datetime.now(UTC) - timedelta(hours=offset)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _valid() -> dict:
    now = datetime.now(UTC)
    return {
        "valid_from": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "valid_until": (now + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }


def _page(request: Request, path: str, make, cursor: bool) -> dict:
    """Page 1 (no ``page`` parameter) points to page 2, which is the last."""
    page = int(request.query_params.get("page", 1))
    results = [make(page * 10 + i) for i in range(PAGE_SIZE)]
    last = page >= 2
    query = urlencode({"page": page + 1, "size": PAGE_SIZE, "format": "json"})
    body = {"next": None if last else f"{BASE}{path}?{query}", "results": results}
    if cursor:
        body["cursor"] = None if last else fake.uuid4()
    else:
        body["count"] = 2 * PAGE_SIZE
        body["previous"] = None
    return body


def _malicious_url(i: int) -> dict:
    if i % 2:
        host = fake.domain_name()
        return {
            "id": fake.uuid4(),
            "url": f"{host}/{fake.word()}/gate.php",
            "host": host,
            "is_domain": True,
            "ip_addresses": [fake.ipv4_public()],
            "tags": [fake.malware_family()],
            "created": _created(i),
            **_valid(),
        }
    ip = fake.ipv4_public()
    return {
        "id": fake.uuid4(),
        "url": f"{ip}:{fake.random_int(1024, 60000)}",
        "host": ip,
        "is_domain": False,
        "ip_addresses": [ip],
        "tags": [fake.malware_family()],
        "created": _created(i),
        **_valid(),
    }


def _phishing_site(i: int) -> dict:
    return {
        "id": fake.random_int(40000, 90000),
        "url": f"http://{fake.domain_name()}/{fake.word()}",
        "host": "",
        "is_domain": True,
        "ip_addresses": [],
        "country": "",
        "created": _created(i),
    }


def _malware_hash(i: int) -> dict:
    return {
        "id": fake.uuid4(),
        "hashes": {"md5": fake.md5(), "sha1": fake.sha1(), "sha256": fake.sha256()},
        "tags": [fake.malware_family()],
        "created": _created(i),
        **_valid(),
    }


def _company() -> dict:
    return {"id": 1, "name": "API Integration Demo Company"}


def _credential(i: int) -> dict:
    victim = {
        "victim_uid": fake.uuid4(),
        "username": fake.user_name(),
        "phone_number": "",
        "country": fake.country(),
        "ip": fake.ipv4_public(),
        "computer_name": f"DESKTOP-{fake.bothify('??#####').upper()}",
        "victim_os": "Windows 11",
        "memory": "16 GB",
        "cpu": "Intel(R) Core(TM) i7-1185G7 CPU @ 3.00GHz",
        "gpu": "",
        "infection_date": (datetime.now(UTC) - timedelta(days=3)).strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "malware": fake.malware_family(),
    }
    return {
        "id": fake.random_int(1_000_000, 9_000_000),
        "status": "open",
        "created": _created(i),
        "content_type": "compromised-credentials",
        "company": _company(),
        "content": {
            "username": fake.email(),
            "password": fake.password(),
            "password_complexity": {"score": "medium", "length": 12},
            "url": f"https://login.{fake.domain_name()}/signin",
            "source": "malware" if i % 2 else "phishing_site",
            "is_corporate": True,
            "victim_detail": victim if i % 2 else None,
        },
    }


def _credit_card(i: int) -> dict:
    return {
        "id": fake.random_int(100_000, 900_000),
        "status": "open",
        "created": _created(i),
        "content_type": "credit-card",
        "company": _company(),
        "content": {
            "number": fake.credit_card_number(),
            "expiration_date": (datetime.now(UTC) + timedelta(days=700)).strftime(
                "%Y-%m-%d"
            ),
        },
    }


def _deep_sight(i: int) -> dict:
    created = _created(i)
    report = (
        f"{BASE}/attachments/Report_{fake.bothify('??????')}.pdf"
        "?AWSAccessKeyId=EXO&Signature=xxx&Expires=1893456000"
        if i % 2
        else None
    )
    return {
        "id": fake.random_int(1_000_000, 9_000_000),
        "status": "open",
        "status_timestamp": created,
        "created": created,
        "content_type": "deep-sight",
        "company": _company(),
        "content": {
            "title": f"[REGIONAL] {fake.catch_phrase()}",
            "threat_actors": [
                {
                    "nickname": f"UNC{fake.random_int(10000, 99999)}",
                    "real_name": "",
                    "country": "us",
                    "motivations": ["ideological"],
                }
            ],
            "targets": [
                {
                    "name": fake.company(),
                    "risk_score": "medium",
                    "analyst_notes": f"<p>{fake.sentence()}</p>",
                }
            ],
            "detected_platforms": ["sigint"],
            "analyst_notes": f"<p>{fake.paragraph()}</p>",
            "tlp": "amber",
            "labels": ["ransomware"],
            "report": report,
            "detected_at": created.split(".")[0] + "Z",
            "markers": ["regional"],
        },
    }


@router.get(f"{API}/security-intelligence/ioc/malicious-urls")
async def malicious_urls(request: Request) -> dict:
    path = f"{API}/security-intelligence/ioc/malicious-urls"
    return _page(request, path, _malicious_url, cursor=True)


@router.get(f"{API}/security-intelligence/ioc/phishing-sites")
async def phishing_sites(request: Request) -> dict:
    path = f"{API}/security-intelligence/ioc/phishing-sites"
    return _page(request, path, _phishing_site, cursor=False)


@router.get(f"{API}/security-intelligence/ioc/malware-hashes")
async def malware_hashes(request: Request) -> dict:
    path = f"{API}/security-intelligence/ioc/malware-hashes"
    return _page(request, path, _malware_hash, cursor=True)


@router.get(
    f"{API}/security-intelligence/account-takeover-prevention/compromised-credentials-tickets"
)
async def compromised_credentials(request: Request) -> dict:
    path = f"{API}/security-intelligence/account-takeover-prevention"
    path += "/compromised-credentials-tickets"
    return _page(request, path, _credential, cursor=False)


@router.get(f"{API}/fraud-intelligence/credit-card-tickets")
async def credit_card_tickets(request: Request) -> dict:
    path = f"{API}/fraud-intelligence/credit-card-tickets"
    return _page(request, path, _credit_card, cursor=False)


@router.get(f"{API}/deep-sight-tickets")
async def deep_sight_tickets(request: Request) -> dict:
    return _page(request, f"{API}/deep-sight-tickets", _deep_sight, cursor=False)


@router.get("/attachments/{name}")
async def attachment(name: str) -> Response:  # noqa: ARG001
    return Response(PDF, media_type="application/pdf")
