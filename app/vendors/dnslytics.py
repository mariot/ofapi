"""DNSlytics: the premium domain search, the free IP2ASN lookup and the account info,
read by the OpenCTI dnslytics connector."""

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["api.dnslytics.net", "freeapi.dnslytics.net"]
router = APIRouter(prefix="/dnslytics", tags=["DNSlytics"])

# Names that really resolve, so a networked run also exercises the hosting lookups
RESOLVABLE = ["example.com", "example.org", "example.net"]


def _authorize(apikey: str) -> None:
    if not apikey:
        raise HTTPException(
            status_code=403,
            detail={"status": "error", "data": "Forbidden access denied!"},
        )


@router.get("/v2/dataset/domains")
async def dataset_domains(q: str = "", page: int = 1, apikey: str = "") -> dict:
    """The domains matching a search query: a few active ones and a dropped one."""
    _authorize(apikey)
    domains = [
        {"domain": fake.domain_name(), "active": True},
        {"domain": fake.domain_name(), "active": True},
        {"domain": fake.domain_name(), "active": False},
        *({"domain": name, "active": True} for name in RESOLVABLE),
    ]
    return {
        "status": "succeed",
        "data": {
            "question": {"query": q, "page": page},
            "typeinfo": "dataset/domains",
            "ndomains": len(domains),
            "domains": domains,
        },
    }


@router.get("/v1/accountinfo")
async def account_info(apikey: str = "") -> dict:
    _authorize(apikey)
    return {
        "status": "succeed",
        "data": {
            "typeinfo": "accountinfo",
            "apicredits": 1000,
            "apilimits": 20000,
            "apicalls": 0,
        },
    }


@router.get("/v1/ip2asn/{ip}")
async def ip2asn(ip: str) -> dict:
    """The AS announcing the address (a private-range AS number and a short name)."""
    return {
        "ip": ip,
        "announced": True,
        "asn": fake.random_int(64512, 65534),
        "shortname": fake.company().upper().replace(" ", "-")[:20],
    }
