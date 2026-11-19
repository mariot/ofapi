"""AbuseIPDB: the IP check (abuseipdb enrichment connector) and the blacklist
(abuseipdb-ipblacklist import connector)."""

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


@router.get("/api/v2/blacklist")
async def blacklist(
    confidence_minimum: int = Query(100, alias="confidenceMinimum"),
    limit: int = 10000,
    ip_version: int | None = Query(None, alias="ipVersion"),
) -> dict:
    """The most reported addresses (IPv4 and IPv6) above the confidence score asked."""
    versions = [ip_version] if ip_version else [4, 4, 4, 4, 4, 6, 6]
    data = [
        {
            "ipAddress": fake.ipv4_public() if version == 4 else fake.ipv6(),
            "countryCode": fake.random_element(["FR", "US", "DE", "CN", "BR", "NL"]),
            "abuseConfidenceScore": fake.random_int(confidence_minimum, 100),
            "lastReportedAt": fake.date_time_this_month().isoformat() + "+00:00",
        }
        for version in versions[:limit]
    ]
    return {
        "meta": {"generatedAt": fake.date_time_this_month().isoformat() + "+00:00"},
        "data": data,
    }
