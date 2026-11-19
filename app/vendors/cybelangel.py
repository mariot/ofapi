"""CybelAngel: OAuth2 token and claimed ransomware/DDoS attacks, read by the OpenCTI
cybelangel connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["auth.cybelangel.com", "platform.cybelangel.com"]
router = APIRouter(prefix="/cybelangel", tags=["CybelAngel"])

CATEGORIES = ["ransomware", "ddos", "data leak", "defacement"]
COUNTRIES = ["France", "Germany", "United States", "Japan", "Brazil"]
INDUSTRIES = ["Healthcare", "Manufacturing", "Finance", "Education", "Energy"]
ATTACKS: list[dict] = []
BUILT_AT: list[datetime] = []


def _attack(index: int) -> dict:
    claimed_at = datetime.now(UTC) - timedelta(hours=3 + index * 7)
    victims = [fake.company() for _ in range(fake.random_int(0, 2))]
    return {
        "id": fake.uuid4(),
        "category": fake.random_element(CATEGORIES),
        "claimed_at": claimed_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        # the first attack has no victim: a generic campaign
        "threat_actors": [fake.intrusion_set()] if index else [],
        "countries": fake.random_elements(COUNTRIES, length=2, unique=True),
        "industries": fake.random_elements(INDUSTRIES, length=2, unique=True),
        "victims": victims if index else [],
        "domains": [fake.domain_name() for _ in victims],
    }


@router.post("/oauth/token")
async def token() -> dict:
    return {
        "access_token": fake.sha256(),
        "scope": "read:claimed-attacks",
        "expires_in": 86400,
        "token_type": "Bearer",
    }


@router.get("/api/v1/threat-intelligence/claimed-attacks")
async def claimed_attacks(
    limit: int = 50,
    skip: int = 0,
    start_date: str | None = Query(None),
) -> dict:
    """Most recent first; an empty page ends the pagination."""
    if not ATTACKS or datetime.now(UTC) - BUILT_AT[0] > timedelta(minutes=30):
        ATTACKS[:] = [_attack(i) for i in range(8)]
        BUILT_AT[:] = [datetime.now(UTC)]
    found = [a for a in ATTACKS if not start_date or a["claimed_at"] >= start_date]
    return {"claimed_attacks": found[skip : skip + limit], "total": len(found)}
