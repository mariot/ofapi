"""Criminal IP: IP report, malicious info and domain scan reports.

Read by the OpenCTI criminal-ip enrichment connector (IPv4 and domain).
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Form

from app.fake import fake

HOSTS = ["api.criminalip.io"]
router = APIRouter(prefix="/criminal-ip", tags=["Criminal IP"])

SCORES = ["Safe", "Low", "Moderate", "Dangerous", "Critical"]
CATEGORIES = ["scanner", "malware", "c2", "vpn", "tor", "hosting", "darkweb"]


@router.get("/v1/asset/ip/report")
async def ip_report(ip: str) -> dict:
    """The IP report: scores, issues, categories, whois and exposed vulnerabilities."""
    return {
        "ip": ip,
        "score": {
            "inbound": fake.random_element(SCORES[2:]),
            "outbound": fake.random_element(SCORES),
        },
        "issues": {
            "is_vpn": False,
            "is_cloud": True,
            "is_tor": False,
            "is_proxy": True,
            "is_hosting": True,
            "is_mobile": False,
            "is_darkweb": False,
            "is_scanner": True,
            "is_snort": True,
            "is_anonymous_vpn": False,
        },
        "ip_category": {
            "count": 2,
            "data": [
                {
                    "type": category,
                    "detect_source": "Criminal IP",
                    "confirmed_time": "2026-11-10 08:00:00",
                }
                for category in fake.random_elements(CATEGORIES, 2, unique=True)
            ],
        },
        "whois": {
            "count": 1,
            "data": [
                {
                    "as_name": fake.company(),
                    "as_no": fake.random_int(1000, 64000),
                    "city": fake.city(),
                    "region": fake.state(),
                    "org_name": fake.company(),
                    "org_country_code": "us",
                    "latitude": float(fake.latitude()),
                    "longitude": float(fake.longitude()),
                    "modified_date": "2026-01-05 00:00:00",
                }
            ],
        },
        "vulnerability": {
            "count": 2,
            "data": [
                {
                    "cve_id": fake.cve_id(),
                    "cve_description": fake.sentence(),
                    "cvssv3_score": 9.8,
                    "app_name": "nginx",
                    "app_version": "1.18.0",
                }
                for _ in range(2)
            ],
        },
        "message": "api success",
        "status": 200,
    }


@router.get("/v1/feature/ip/malicious-info")
async def malicious_info(ip: str) -> dict:
    """The malicious flags of an address."""
    return {
        "ip": ip,
        "is_malicious": True,
        "is_anonymous_vpn": True,
        "can_remote_access": True,
        "is_vpn": False,
        "message": "api success",
        "status": 200,
    }


@router.get("/v1/domain/reports")
async def domain_reports(query: str, offset: int = 0) -> dict:
    """A recent scan report of the domain: the connector starts no new scan."""
    stamp = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "data": {
            "count": 1 - offset,
            "reports": [
                {
                    "reg_dtime": stamp,
                    "scan_id": fake.random_int(1_000_000, 9_999_999),
                    "url": f"https://{query}",
                    "title": fake.sentence(nb_words=3),
                    "score": "Dangerous",
                }
            ][offset:],
        },
        "message": "api success",
        "status": 200,
    }


@router.post("/v1/domain/scan")
async def domain_scan(query: str = Form("")) -> dict:
    """A scan request (only used when the domain has no recent report)."""
    return {
        "data": {"scan_id": fake.random_int(1_000_000, 9_999_999), "url": query},
        "message": "api success",
        "status": 200,
    }


@router.get("/v1/domain/status/{scan_id}")
async def domain_status(scan_id: int) -> dict:
    return {
        "data": {"scan_id": scan_id, "scan_percentage": 100},
        "message": "api success",
        "status": 200,
    }


@router.get("/v2/domain/report/{scan_id}")
async def domain_report(scan_id: int) -> dict:
    """The scan report: phishing summary, countries and connected IPs."""
    return {
        "data": {
            "scan_id": scan_id,
            "summary": {
                "url_phishing_prob": 62,
                "phishing_record": 1,
                "suspicious_file": 1,
                "cred_input": 1,
                "diff_domain_favicon": 1,
                "list_of_countries": ["us", "de", None],
            },
            "connected_ip": [
                {"ip": fake.ipv4_public(), "score": "Dangerous"} for _ in range(3)
            ],
        },
        "message": "api success",
        "status": 200,
    }
