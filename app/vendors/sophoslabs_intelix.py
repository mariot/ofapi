"""SophosLabs Intelix: OAuth token and IP, URL and file lookups (sophoslabs-intelix
connector)."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.labs.sophos.com", "*.api.labs.sophos.com"]
router = APIRouter(prefix="/sophoslabs-intelix", tags=["SophosLabs Intelix"])


@router.post("/oauth2/token")
async def token() -> dict:
    return {
        "access_token": fake.sha256(),
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "intelix",
    }


@router.get("/lookup/ips/v1/{ip}")
async def lookup_ip(ip: str) -> dict:
    return {"ipAddress": ip, "category": ["botnet"], "ttl": 1800}


@router.get("/lookup/urls/v1/{url:path}")
async def lookup_url(url: str) -> dict:
    return {
        "url": url,
        "productivityCategory": "PROD_UNCATEGORIZED",
        "securityCategory": "SEC_MALWARE_REPOSITORY",
        "riskLevel": "HIGH",
        "ttl": 1800,
    }


@router.get("/lookup/files/v1/{sha256}")
async def lookup_file(sha256: str) -> dict:  # noqa: ARG001
    return {
        "reputationScore": fake.random_int(0, 19),
        "detectionName": f"Mal/{fake.word().title()}-A",
        "ttl": 1800,
    }
