"""RansomFeed: the recent ransomware claims, read by the ransomfeed connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.ransomfeed.it"]
router = APIRouter(prefix="/ransomfeed", tags=["RansomFeed"])

COUNTRIES = ["US", "IT", "DE", "FR", "GB", "BR", "CA", "ES"]


def _claim(index: int) -> dict:
    return {
        "id": str(fake.random_int(100000, 999999)),
        "date": fake.date_time_between(start_date="-20h").strftime("%Y-%m-%d %H:%M:%S"),
        "victim": fake.company(),
        "gang": fake.intrusion_set(),
        "country": fake.random_element(COUNTRIES),
        "website": fake.domain_name() if index % 4 else "",
        "hash": fake.sha256() if index % 2 == 0 else "",
    }


@router.get("/")
async def recent_claims() -> list[dict]:
    """The claims published during the last day (the since parameter is ignored)."""
    return [_claim(index) for index in range(8)]
