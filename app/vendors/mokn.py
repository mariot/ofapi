"""MokN: the login attempts caught by the bait console, read by the OpenCTI mokn
connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["console.mokn.io"]
router = APIRouter(prefix="/mokn", tags=["MokN"])

PAGE_SIZE = 4
PAGES = 2
# status: 0 invalid, 1 valid credentials, 2 could lock, 8 locked account
STATUSES = [1, 0, 0, 2, 8, 1, 0, 0]


def _attempt(index: int) -> dict:
    when = datetime.now(UTC) - timedelta(hours=1 + index * 5)
    return {
        "ip": fake.ipv4_public(),
        "date": when.isoformat().replace("+00:00", "Z"),
        "threat_level": "HIGH" if index % 3 != 2 else "MEDIUM",
        "status": STATUSES[index % len(STATUSES)],
        "username": fake.user_name(),
        "bait": fake.domain_name(),
        "country": fake.country_code(),
    }


@router.post("/api/v1/baits/logins")
async def logins(request: Request, page: int = 1) -> dict:
    """A page of login attempts; ``next`` is the absolute URL of the following page."""
    await request.body()
    first = (page - 1) * PAGE_SIZE
    data = [_attempt(first + i) for i in range(PAGE_SIZE)]
    nxt = None
    if page < PAGES:
        nxt = f"https://console.mokn.io/api/v1/baits/logins?page={page + 1}"
    return {
        "count": PAGE_SIZE * PAGES,
        "next": nxt,
        "previous": None,
        "data": data,
    }
