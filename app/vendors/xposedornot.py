"""XposedOrNot: breach analytics of an email address, read by the xposedornot connector.

The community API (no key) and the Plus API (key) answer with different shapes; an
address starting with "clean" is unknown to both and gets a 404.
"""

from fastapi import APIRouter, Header, HTTPException

from app.fake import fake

HOSTS = ["api.xposedornot.com", "plus-api.xposedornot.com"]
router = APIRouter(prefix="/xposedornot", tags=["XposedOrNot"])

BREACHES = ["Adobe", "LinkedIn", "Dropbox", "MyFitnessPal", "Canva", "Zynga"]
PASSWORD_RISKS = ["plaintext", "easytocrack", "hardtocrack", "unknown"]
DATA = [
    "Email addresses;Passwords;Usernames",
    "Email addresses;IP addresses;Names",
    "Email addresses;Phone numbers;Physical addresses",
]


def _entry(name_key: str, date_key: str, name: str, index: int) -> dict:
    return {
        name_key: name,
        date_key: str(2012 + 2 * index),
        "xposed_records": fake.random_int(10_000, 90_000_000),
        "domain": f"{name.lower()}.com",
        "industry": fake.random_element(["Technology", "Social media", "Retail"]),
        "password_risk": PASSWORD_RISKS[index % len(PASSWORD_RISKS)],
        "verified": "Yes",
        "xposed_data": DATA[index % len(DATA)],
        "details": f"{name} suffered a breach that exposed customer accounts.",
    }


def _breaches(name_key: str, date_key: str) -> list[dict]:
    names = fake.random_elements(BREACHES, length=3, unique=True)
    return [_entry(name_key, date_key, name, i) for i, name in enumerate(names)]


@router.get("/v1/breach-analytics")
async def breach_analytics(email: str) -> dict:
    """Community API: breaches of an address with a risk summary."""
    if email.startswith("clean"):
        raise HTTPException(404, "Not found")
    return {
        "ExposedBreaches": {"breaches_details": _breaches("breach", "xposed_date")},
        "BreachesSummary": {"site": "Adobe;LinkedIn"},
        "BreachMetrics": {"risk": [{"risk_label": "High", "risk_score": 72}]},
        "status": "success",
    }


@router.get("/v3/check-email/{email}")
async def check_email(email: str, x_api_key: str | None = Header(None)) -> dict:
    """Plus API: breaches of an address, detailed with the API key."""
    if not x_api_key:
        raise HTTPException(401, "API key required")
    if email.startswith("clean"):
        raise HTTPException(404, "Not found")
    return {"email": email, "breaches": _breaches("breach_id", "breached_date")}
