"""CrowdSec CTI API v2: smoke search and IP lookup.

Read by the OpenCTI crowdsec-import connector (smoke search, paginated) and the crowdsec
enrichment connector (``smoke/<ip>``).
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["cti.api.crowdsec.net"]
router = APIRouter(prefix="/crowdsec", tags=["CrowdSec"])

PAGE_SIZE = 3
PAGES = 2

REPUTATIONS = ["malicious", "suspicious", "known"]
BEHAVIORS = [
    ("ssh:bruteforce", "SSH Bruteforce", "Reported for brute forcing ssh services."),
    ("http:scan", "HTTP Scan", "Reported for HTTP vulnerability scanning."),
    ("tcp:scan", "TCP Scan", "Reported for TCP port scanning."),
]
MITRE = [
    ("T1110", "Brute Force", "Adversaries may use brute force to gain access."),
    ("T1595", "Active Scanning", "Adversaries may run active reconnaissance scans."),
]
SCENARIOS = [
    ("crowdsecurity/ssh-bf", "SSH Bruteforce", "Detect ssh bruteforce"),
    ("crowdsecurity/http-probing", "HTTP Probing", "Detect site scanning/probing"),
    ("crowdsecurity/CVE-2022-26134", "Confluence CVE-2022-26134", "Detect exploits"),
]


def _stamp(days_ago: int) -> str:
    moment = datetime.now(UTC) - timedelta(days=days_ago)
    return moment.replace(microsecond=0).isoformat()


def _entry(name: str, label: str, description: str) -> dict:
    return {"name": name, "label": label, "description": description, "references": []}


def _smoke(ip: str, reputation: str | None = None) -> dict:
    """The CTI record of an address: behaviors, scenarios, CVEs, MITRE, countries."""
    reputation = reputation or fake.random_element(REPUTATIONS)
    return {
        "ip": ip,
        "reputation": reputation,
        "ip_range": f"{ip.rsplit('.', 1)[0]}.0/24",
        "background_noise": "high",
        "confidence": fake.random_element(["high", "medium", "low"]),
        "background_noise_score": 7,
        "ip_range_score": 5,
        "as_name": fake.company(),
        "as_num": fake.random_int(1000, 64000),
        "location": {
            "country": "FR",
            "city": fake.city(),
            "latitude": float(fake.latitude()),
            "longitude": float(fake.longitude()),
        },
        "reverse_dns": None,
        "behaviors": [_entry(*b) for b in BEHAVIORS[:2]],
        "history": {
            "first_seen": _stamp(30),
            "last_seen": _stamp(1),
            "full_age": 30,
            "days_age": 29,
        },
        "classifications": {"false_positives": [], "classifications": []},
        "attack_details": [_entry(*s) for s in SCENARIOS],
        "references": [
            {
                "name": "list:crowdsec_web_scan",
                "label": "CrowdSec Web Scan Blocklist",
                "description": "IPs scanning web applications.",
                "references": ["https://www.crowdsec.net/blocklists"],
            }
        ],
        "mitre_techniques": [_entry(*m) for m in MITRE],
        "cves": ["CVE-2022-26134"],
        "target_countries": {"US": 45, "DE": 30, "FR": 25},
        "scores": {"overall": {"aggressiveness": 4, "threat": 4, "trust": 5}},
    }


@router.get("/v2/smoke/search")
async def smoke_search(page: int = 1) -> dict:
    """``PAGES`` pages of ``PAGE_SIZE`` records, linked by ``_links.next.href``."""
    base = "https://cti.api.crowdsec.net/v2/smoke/search"
    links = {"self": {"href": f"{base}?page={page}"}}
    if page < PAGES:
        links["next"] = {"href": f"{base}?page={page + 1}"}
    return {
        "items": [_smoke(fake.ipv4_public()) for _ in range(PAGE_SIZE)],
        "_links": links,
    }


@router.get("/v2/smoke/{ip}")
async def smoke_ip(ip: str) -> dict:
    """The CTI record of one address."""
    return _smoke(ip, "malicious")
