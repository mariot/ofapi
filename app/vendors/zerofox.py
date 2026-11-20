"""ZeroFox: the CTI feeds (JWT login, paged JSON) read by the OpenCTI zerofox connector,
and the alerts API (cursor pages, token auth) read by the zerofox-alerts connector."""

import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Header, HTTPException

from app.fake import fake

HOSTS = ["api.zerofox.com"]
router = APIRouter(prefix="/zerofox", tags=["ZeroFox"])

BASE = "https://api.zerofox.com"
PER_PAGE = 2
PAGES = 2
FAMILIES = ["emotet", "qakbot", "lockbit", "agenttesla"]


def _iso(days: float = 0) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hashes() -> dict:
    return {
        "md5": fake.md5(),
        "sha1": fake.sha1(),
        "sha256": fake.sha256(),
        "sha512": fake.sha256() + fake.sha256(),
    }


def _c2_domain() -> dict:
    return {
        "domain": fake.domain_name(),
        "port": fake.random_element([80, 443, 8080]),
        "tags": ["sample_type:exe", "botnet"],
        "ip_addresses": [fake.ipv4_public(), fake.ipv4_public()],
        "created_at": _iso(0.2),
        "updated_at": _iso(0.1),
    }


def _exploit() -> dict:
    cve = fake.cve_id()
    return {
        "created_at": _iso(0.3),
        "cve": cve,
        "urls": [fake.url(), fake.url()],
        "exploit": f"# proof of concept for {cve}\nimport requests\n",
    }


def _malware() -> dict:
    return {
        "created_at": _iso(0.3),
        **_hashes(),
        "family": [fake.random_element(FAMILIES)],
        "tags": ["trojan"],
        "botnet": None,
        "c2": [fake.url()],
    }


def _phishing() -> dict:
    domain = fake.domain_name()
    return {
        "scanned": _iso(0.2),
        "domain": domain,
        "url": f"https://{domain}/login",
        "host": {
            "ip": fake.ipv4_public(),
            "asn": fake.random_int(1000, 64000),
            "geo": "US",
        },
        "cert": {
            "authority": "Let's Encrypt",
            "fingerprint": fake.sha1().upper(),
            "issued": _iso(5),
        },
    }


def _ransomware() -> dict:
    return {
        "created_at": _iso(0.3),
        **_hashes(),
        "emails": [fake.email()],
        "ransom_note": "Your files are encrypted. Contact us to recover them.",
        "ransomware_name": [fake.random_element(FAMILIES)],
        "tags": ["ransomware", "family:lockbit"],
    }


def _vulnerability() -> dict:
    return {
        "base_score": 9.8,
        "description": fake.sentence(),
        "exploitability_score": 3.9,
        "impact_score": 5.9,
        "created_at": _iso(0.3),
        "updated_at": _iso(0.1),
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cve": fake.cve_id(),
        "summary": fake.sentence(),
        "remediation": "Apply the vendor patch.",
    }


def _botnet() -> dict:
    return {
        "bot_name": fake.random_element(FAMILIES),
        "c2_domain": fake.domain_name(),
        "c2_ip_address": fake.ipv4_public(),
        "ip_address": fake.ipv4_public(),
        "listed_at": _iso(0.2),
        "country_code": fake.country_code(),
        "zip_code": fake.postcode(),
        "tags": ["botnet"],
    }


FEEDS = {
    "c2-domains": _c2_domain,
    "exploits": _exploit,
    "malware": _malware,
    "phishing": _phishing,
    "ransomware": _ransomware,
    "vulnerabilities": _vulnerability,
    "botnet": _botnet,
}


@router.post("/auth/token/")
async def auth_token() -> dict:
    """The CTI JWT pair, for the username and password of the form body."""
    return {"access": fake.sha256(), "refresh": fake.sha256()}


@router.get("/cti/{feed}/")
async def cti_feed(
    feed: str, page: int = 1, authorization: str | None = Header(None)
) -> dict:
    """PER_PAGE records a page, PAGES pages; ``next`` is an absolute URL."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication credentials were not provided.")
    if feed not in FEEDS:
        raise HTTPException(404, "Not found.")
    results = [FEEDS[feed]() for _ in range(PER_PAGE)]
    following = f"{BASE}/cti/{feed}/?page={page + 1}" if page < PAGES else None
    return {
        "count": PER_PAGE * PAGES,
        "next": following,
        "previous": None,
        "results": results,
    }


ALERT_TYPES = [
    "phishing",
    "compromised_credential",
    "data_leakage",
    "impersonation",
    "domain_squatting",
    "search_query",
]


def _alert(number: int) -> dict:
    kind = ALERT_TYPES[number % len(ALERT_TYPES)]
    seen = _iso(2 - number * 0.2)
    perpetrator = fake.user_name()
    metadata = {
        "justification": "Matches the monitored brand",
        "alert_reasons": [{"value": {"text_content": f"{kind} detected by a rule"}}],
        "occurrences": [{"term": fake.domain_name()}],
        "content_raw_data": {"details": fake.sentence()},
    }
    return {
        "id": 700000 + number,
        "alert_type": kind,
        "status": ["open", "escalated", "investigation_completed"][number % 3],
        "severity": 1 + number % 4,
        "timestamp": seen,
        "content_created_at": seen,
        "last_modified": seen,
        "rule_name": f"Brand protection {kind}",
        "network": fake.random_element(["twitter", "domain", "facebook", "darkweb"]),
        "notes": fake.sentence(),
        "escalated": number == 3,
        "tags": ["staticfire"],
        "offending_content_url": f"hxxps://{fake.domain_name()}/offending[.]html",
        "darkweb_term": fake.word() if kind == "data_leakage" else None,
        "entity": {"id": 12, "name": "Staticfire Brand"},
        "perpetrator": {
            "name": perpetrator,
            "display_name": perpetrator.title(),
            "url": f"https://social.example.net/{perpetrator}",
            "timestamp": seen,
        },
        # a JSON string in the real answer
        "metadata": json.dumps(metadata),
        "logs": [{"action": "created", "timestamp": seen}],
    }


ALERTS = 6


@router.get("/1.0/alerts/")
async def alerts(
    limit: int = 100,
    cursor: int = 0,
    authorization: str | None = Header(None),
) -> dict:
    """Alerts, oldest first, ``limit`` a page; ``next`` carries the cursor."""
    if not authorization or not authorization.startswith("Token "):
        raise HTTPException(401, "Invalid token.")
    page = [_alert(n) for n in range(cursor, min(cursor + limit, ALERTS))]
    end = cursor + limit
    following = (
        f"{BASE}/1.0/alerts/?limit={limit}&cursor={end}" if end < ALERTS else None
    )
    return {"alerts": page, "next": following}


@router.get("/1.0/alerts/{alert_id}/")
async def alert_detail(alert_id: int) -> dict:
    """One alert."""
    return _alert(alert_id % ALERTS)
