"""ChapsVision: the social media and web documents search, read by the OpenCTI
chapsvision connector (TLS client certificate, verification off)."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["ns3360046.ip-178-33-235.eu"]
router = APIRouter(prefix="/chapsvision", tags=["ChapsVision"])

CATEGORIES = {
    "Micro Blogging": ["X", "Mastodon", "Bluesky"],
    "Messaging": ["Telegram", "Discord", "Signal"],
    "Website": ["Dark web forum", "Paste site", "News"],
}


def _document(category: str) -> dict:
    broadcaster = fake.random_element(CATEGORIES[category])
    published = datetime.now(UTC) - timedelta(hours=fake.random_int(1, 20))
    document = {
        "id": fake.uuid4(),
        "broadcaster": broadcaster,
        "broadcaster_category": category,
        "content_provider": broadcaster,
        "link": fake.url() + fake.pystr(8, 8),
        "content": fake.paragraph(),
        "hashtag": [f"#{fake.word()}", f"#{fake.malware_family()}"],
        "publication_date": published.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timestamp": published.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if category != "Website":
        document["profile_link"] = f"https://{fake.domain_name()}/@{fake.user_name()}"
    else:
        document["title"] = fake.sentence()
        document["description"] = fake.paragraph()
    return document


@router.get("/mcapi/documents")
async def documents(rows: int = 1000) -> dict:
    """Solr-style answer: a few documents of each category of the queried day."""
    docs = [_document(category) for category in CATEGORIES for _ in range(3)]
    return {"numFound": len(docs), "start": 0, "docs": docs[:rows]}
