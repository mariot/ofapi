"""CTM360 CyberBlindSpot: incidents and leaks (API v2), read by the OpenCTI
ctm360-cyberblindspot-feed connector."""

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["cbs.ctm360.com"]
router = APIRouter(prefix="/ctm360-cbs", tags=["CTM360 CyberBlindSpot"])

INCIDENT_TYPES = ["Phishing Site", "Brand Impersonation", "Fake Mobile App"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
STATUSES = ["Open", "In Progress", "Resolved"]


def _ctm_date() -> str:
    """The incident date format of CBS: day-month-year, 12-hour clock."""
    return fake.date_time_between(start_date="-20d").strftime("%d-%m-%Y %I:%M:%S %p")


def _incident(ticket_id: str | None = None) -> dict:
    return {
        "id": ticket_id or f"CBS-{fake.random_int(10000, 99999)}",
        "subject": f"Phishing page impersonating {fake.company()}",
        "severity": fake.random_element(SEVERITIES),
        "type": fake.random_element(INCIDENT_TYPES),
        "status": fake.random_element(STATUSES),
        "coa": fake.random_element(["Takedown", "Monitor", "None"]),
        "source": fake.random_element(["Web", "Social Media", "Dark Web"]),
        "remarks": fake.sentence(),
        "brand": fake.company(),
        "created_date": _ctm_date(),
    }


def _page(key: str, items: list[dict]) -> dict:
    return {key: items, "count": len(items)}


@router.get("/api/v2/incidents")
async def incidents() -> dict:
    return _page("incident_list", [_incident() for _ in range(4)])


@router.get("/api/v2/incidents/{ticket_id}")
async def incident(ticket_id: str) -> dict:
    if not ticket_id.startswith("CBS-"):
        raise HTTPException(404, "Incident not found")
    return {"incident": _incident(ticket_id)}


@router.get("/api/v2/leaks/malware_logs")
async def malware_logs() -> dict:
    logs = [
        {
            "malware_family": fake.malware_family(),
            "domain": fake.domain_name(),
            "ip": fake.ipv4_public(),
            "email": fake.email(),
            "date": fake.date_time_between(start_date="-20d").isoformat() + "Z",
        }
        for _ in range(5)
    ]
    return _page("data", logs)


@router.get("/api/v2/leaks/breached_credentials")
async def breached_credentials() -> dict:
    creds = [
        {
            "id": fake.uuid4(),
            "email": fake.email(),
            "username": fake.user_name(),
            "domain": fake.domain_name(),
            "breach_source": fake.random_element(["Combolist", "Stealer logs"]),
            "date": fake.date_time_between(start_date="-20d").isoformat() + "Z",
        }
        for _ in range(4)
    ]
    return _page("data", creds)


@router.get("/api/v2/leaks/card_leaks")
async def card_leaks() -> dict:
    cards = [
        {
            "id": fake.uuid4(),
            "bank_name": fake.company(),
            "date": fake.date_time_between(start_date="-20d").isoformat() + "Z",
        }
        for _ in range(3)
    ]
    return _page("data", cards)


@router.get("/api/v2/domain_protection")
async def domain_protection() -> dict:
    findings = [
        {
            "id": fake.uuid4(),
            "domain": fake.domain_name(),
            "type": fake.random_element(["Typosquatting", "Lookalike"]),
            "risk_score": fake.random_int(40, 100),
            "finding_status": "Open",
            "ip_address": fake.ipv4_public(),
            "created_date": _ctm_date(),
        }
        for _ in range(4)
    ]
    return _page("data", findings)
