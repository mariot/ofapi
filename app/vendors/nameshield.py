"""Nameshield registrar API: the domains of an account and their details, read by the
OpenCTI nameshield connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["api.nameshield.net"]
router = APIRouter(prefix="/nameshield", tags=["Nameshield"])

DATE = "%Y-%m-%dT%H:%M:%S"
DOMAINS: dict[str, dict] = {}


def _domain(index: int) -> dict:
    name = f"{fake.domain_word()}-{index}.{fake.tld()}"
    created = datetime.now(UTC) - timedelta(days=400 + index * 30)
    return {
        "domain": name,
        "unicode": name,
        "nicCreationDate": created.strftime(DATE),
        "expirationDate": (created + timedelta(days=1095)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        ),
        "class": "brand-protection",
        "property": fake.random_element(["lookalike", "typosquatting", "homograph"]),
        "threat_level": fake.random_int(40, 95),
        "registrar": "Nameshield",
        "status": "active",
        "dnsServers": [f"ns{n}.{fake.domain_name()}" for n in (1, 2)],
    }


@router.get("/registrar/v1/domains")
async def domains() -> dict:
    """The domains of the account (their names only)."""
    DOMAINS.clear()
    for i in range(6):
        item = _domain(i)
        DOMAINS[item["domain"]] = item
    return {"data": [{"domain": name} for name in DOMAINS]}


@router.get("/registrar/v1/domains/{domain}")
async def domain_details(domain: str) -> dict:
    if domain not in DOMAINS:
        raise HTTPException(404, "Domain not found")
    return {"data": DOMAINS[domain]}
