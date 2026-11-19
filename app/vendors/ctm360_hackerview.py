"""CTM360 HackerView (external attack surface): issues, resolved issues and assets
(API v2), read by the OpenCTI ctm360-hackerview-feed connector."""

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["hackerview.ctm360.com"]
router = APIRouter(prefix="/ctm360-hackerview", tags=["CTM360 HackerView"])

SEVERITIES = ["Critical", "High", "Medium", "Low"]
TECHNOLOGIES = ["nginx", "Apache HTTP Server", "WordPress", "OpenSSH", "jQuery"]


def _time() -> str:
    return fake.date_time_between(start_date="-20d").strftime("%d-%m-%Y %I:%M:%S %p")


def _issue(ticket_id: str | None = None, resolved: bool = False) -> dict:
    domain = fake.domain_name()
    host = f"www.{domain}"
    return {
        "ticket_id": ticket_id or f"HV-{fake.random_int(10000, 99999)}",
        "issue_name": fake.random_element(
            ["Exposed admin panel", "Outdated web server", "Expired TLS certificate"]
        ),
        "severity": fake.random_element(SEVERITIES),
        "issue_type": fake.random_element(["Vulnerability", "Misconfiguration"]),
        "issue_category": ["Web Application"],
        "cve_id": fake.cve_id(),
        "cwe": [
            {"cwe_id": "CWE-200", "cwe_detail": "Exposure of Sensitive Information"},
            {"cwe_id": "CWE-79", "cwe_detail": "Cross-site Scripting"},
        ],
        "potential_attack_type": ["Information disclosure"],
        "potential_impact": ["Data leak"],
        "status": "Resolved" if resolved else "Open",
        "progress_status": "Fixed" if resolved else "In Progress",
        "hackerview_link": f"https://hackerview.ctm360.com/issues/{fake.uuid4()}",
        "last_updated": _time(),
        "meta": {
            "domain": domain,
            "host": host,
            "resolved_ip": fake.ipv4_public(),
            "technologies": fake.random_elements(TECHNOLOGIES, length=2, unique=True),
            "environments": ["production"],
            "first_seen": _time(),
            "last_seen": _time(),
            "asset": host,
            "asset_type": "host",
            "port": 443,
            "discovery_source": "Scan",
            "brand": fake.company(),
        },
    }


def _page(key: str, items: list[dict]) -> dict:
    return {key: items, "count": len(items)}


@router.get("/api/v2/issues")
async def issues() -> dict:
    return _page("issues", [_issue() for _ in range(4)])


@router.get("/api/v2/issues/{ticket_id}")
async def issue(ticket_id: str) -> dict:
    if not ticket_id.startswith("HV-"):
        raise HTTPException(404, "Issue not found")
    return {"issues": [_issue(ticket_id)], "count": 1}


@router.get("/api/v2/resolved_issues")
async def resolved_issues() -> dict:
    return _page("issues", [_issue(resolved=True) for _ in range(3)])


@router.get("/api/v2/assets/domain")
async def domain_assets() -> dict:
    return _page("data", [{"domain": fake.domain_name()} for _ in range(3)])


@router.get("/api/v2/assets/host")
async def host_assets() -> dict:
    return _page("data", [{"host": f"www.{fake.domain_name()}"} for _ in range(3)])


@router.get("/api/v2/assets/ip_address")
async def ip_assets() -> dict:
    return _page("data", [{"ip_address": fake.ipv4_public()} for _ in range(3)])
