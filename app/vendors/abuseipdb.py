"""AbuseIPDB: the IP check, read by the OpenCTI abuseipdb enrichment connector."""

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["api.abuseipdb.com"]
router = APIRouter(prefix="/abuseipdb", tags=["AbuseIPDB"])

# https://www.abuseipdb.com/categories
CATEGORIES = list(range(3, 24))


@router.get("/api/v2/check")
async def check(ip_address: str = Query(alias="ipAddress"), verbose: str = "") -> dict:
    """A reported (not whitelisted) address, with reports from a few countries."""
    reports = [
        {
            "reportedAt": fake.date_time_this_year().isoformat() + "+00:00",
            "comment": fake.sentence(),
            "categories": fake.random_elements(CATEGORIES, length=2, unique=True),
            "reporterId": fake.random_int(1, 99999),
            "reporterCountryCode": country,
            "reporterCountryName": country,
        }
        for country in fake.random_elements(["FR", "US", "DE", "JP"], length=3)
    ]
    # The API lists the most recent reports first
    reports.sort(key=lambda r: r["reportedAt"], reverse=True)
    return {
        "data": {
            "ipAddress": ip_address,
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": fake.random_int(50, 100),
            "countryCode": "FR",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": fake.company(),
            "domain": fake.domain_name(),
            "hostnames": [],
            "isTor": False,
            "totalReports": len(reports),
            "numDistinctUsers": len(reports),
            "lastReportedAt": reports[0]["reportedAt"],
            "reports": reports if verbose else [],
        }
    }
