"""Phishunt (phishunt.io): the public feed of phishing URLs, read by the OpenCTI
phishunt connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["phishunt.io"]
router = APIRouter(prefix="/phishunt", tags=["Phishunt"])


@router.get("/feed.json")
async def feed() -> list[dict]:
    """Recent phishing URLs with their domain, address, hosting company and country."""
    entries = []
    for index in range(8):
        domain = fake.domain_name()
        entries.append(
            {
                "url": f"https://{domain}/{fake.word()}/login.php",
                "date": (
                    datetime.now(UTC) - timedelta(hours=fake.random_int(1, 70))
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "domain": domain,
                "ip": fake.ipv4_public() if index != 3 else "-",
                "company": fake.random_element(
                    ["cloudflare", "ovh", "godaddy", "namecheap"]
                ),
                "country": fake.random_element(["US", "FR", "DE", "NL"])
                if index != 5
                else "-",
            }
        )
    return entries
