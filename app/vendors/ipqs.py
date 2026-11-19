"""IPQualityScore: the fraud and risk scoring endpoints (IP, URL, email, phone), read by
the OpenCTI ipqs enrichment connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["ipqualityscore.com"]
router = APIRouter(prefix="/ipqs", tags=["IPQS"])


@router.get("/api/json/ip")
async def ip_lookup(ip: str) -> dict:
    """The fraud score, network and location of an address."""
    asn = fake.random_int(1000, 399999)
    return {
        "success": True,
        "message": "Success",
        "fraud_score": fake.random_int(85, 100),
        "country_code": "NL",
        "region": "North Holland",
        "city": "Amsterdam",
        "ISP": fake.company().split(",")[0],
        "ASN": asn,
        "organization": fake.company().split(",")[0],
        "is_crawler": False,
        "timezone": "Europe/Amsterdam",
        "mobile": False,
        "host": f"host-{ip.replace('.', '-')}.{fake.domain_name()}",
        "proxy": True,
        "vpn": True,
        "tor": False,
        "active_vpn": False,
        "active_tor": False,
        "recent_abuse": True,
        "bot_status": True,
        "connection_type": "Premium required.",
        "abuse_velocity": "high",
        "zeroed_fields": [],
        "latitude": 52.37,
        "longitude": 4.89,
        "request_id": fake.lexify("?????????"),
    }


@router.get("/api/json/url")
async def url_lookup(url: str) -> dict:
    """The risk score and verdicts of a URL or domain."""
    return {
        "success": True,
        "message": "Success.",
        "unsafe": True,
        "domain": url,
        "server": "nginx",
        "content_type": "text/html",
        "status_code": 200,
        "page_size": fake.random_int(1000, 90000),
        "domain_rank": fake.random_int(1000, 999999),
        "dns_valid": True,
        "parking": False,
        "spamming": True,
        "malware": True,
        "phishing": False,
        "suspicious": True,
        "adult": False,
        "risk_score": fake.random_int(85, 100),
        "category": "Malware",
        "domain_age": {
            "human": "3 days ago",
            "timestamp": 1790000000,
            "iso": "2026-11-16T10:00:00-05:00",
        },
        "ip_address": fake.ipv4_public(),
        "request_id": fake.lexify("?????????"),
    }


@router.get("/api/json/email")
async def email_lookup(email: str) -> dict:
    """The validity and fraud score of an email address."""
    return {
        "success": True,
        "message": "Success.",
        "valid": True,
        "disposable": False,
        "smtp_score": 3,
        "overall_score": 4,
        "first_name": "Unknown",
        "generic": False,
        "common": False,
        "dns_valid": True,
        "honeypot": False,
        "deliverability": "high",
        "frequent_complainer": False,
        "spam_trap_score": "none",
        "catch_all": False,
        "timed_out": False,
        "suspect": False,
        "recent_abuse": True,
        "fraud_score": fake.random_int(60, 100),
        "suggested_domain": "N/A",
        "leaked": True,
        "sanitized_email": email,
        "domain_age": {"human": "9 years ago", "iso": "2017-11-01T00:00:00-04:00"},
        "first_seen": {"human": "2 years ago", "iso": "2024-11-01T00:00:00-04:00"},
        "request_id": fake.lexify("?????????"),
    }
