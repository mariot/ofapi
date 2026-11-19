"""isMalicious: the /check verdict of an IP address or domain, read by the OpenCTI
ismalicious enrichment connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.ismalicious.com"]
router = APIRouter(prefix="/ismalicious", tags=["isMalicious"])

LISTS = [
    ("URLhaus", "https://urlhaus.abuse.ch", "malware"),
    ("Feodo Tracker", "https://feodotracker.abuse.ch", "c2"),
    ("OpenPhish", "https://openphish.com", "phishing"),
    ("Spamhaus DROP", "https://www.spamhaus.org/drop", "botnet"),
]


@router.get("/check")
async def check(query: str) -> dict:
    """A malicious verdict with its risk score, the lists that detect the value, its
    reputation and country, and an infrastructure row that is not a detection."""
    detections = fake.random_elements(LISTS, length=3, unique=True)
    sources = [
        {
            "name": name,
            "url": url,
            "category": category,
            "threatClass": "threat",
            "lastSeen": fake.date_time_this_month().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        for name, url, category in detections
    ]
    sources.append(
        {
            "name": "Cloud ranges",
            "url": "https://ip-ranges.amazonaws.com",
            "category": "cloud",
            "threatClass": "infrastructure",
        }
    )
    return {
        "query": query,
        "type": "domain" if any(c.isalpha() for c in query) else "ip",
        "malicious": True,
        "riskScore": {"score": fake.random_int(70, 100), "level": "high"},
        "sources": sources,
        "reputation": {
            "malicious": len(detections),
            "suspicious": 1,
            "harmless": 40,
            "undetected": 20,
        },
        "infrastructure": {"attributes": ["cloud", "hosting"]},
        "geo": {"country": "Germany", "countryCode": "DE", "city": "Frankfurt"},
        "timestamp": fake.date_time_this_month().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
