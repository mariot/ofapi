"""Google Safe Browsing (v4 Lookup API), read by the OpenCTI google-safebrowsing
enrichment connector."""

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["safebrowsing.googleapis.com"]
router = APIRouter(prefix="/google-safebrowsing", tags=["Google Safe Browsing"])


@router.post("/v4/threatMatches:find")
async def threat_matches(request: Request) -> dict:
    """Every entry asked is flagged as malware."""
    body = await request.json()
    info = body.get("threatInfo", {})
    return {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "threat": entry,
                "cacheDuration": f"{fake.random_int(300, 3600)}.000s",
            }
            for entry in info.get("threatEntries", [])
        ]
    }
