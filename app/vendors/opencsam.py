"""OpenCSAM: the threat news search, read by the OpenCTI opencsam connector."""

from datetime import datetime, timedelta

from dateutil.parser import parse
from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["api.opencsam.com"]
router = APIRouter(prefix="/opencsam", tags=["OpenCSAM"])

TAG_SETS = [
    ["ransomware", "lockbit"],
    ["breach", "database"],
    ["incident", "phishing"],
    ["vulnerability", "patch-tuesday"],
]


def _news(day: datetime, index: int) -> dict:
    published = day + timedelta(hours=6 + index * 3)
    source = {
        "title": f"{fake.company()} hit by {fake.malware_family()} {fake.word()}",
        "link": f"https://{fake.domain_name()}/news/{fake.slug()}",
        "source_link_news": f"https://www.{fake.domain_name()}/rss",
        "published": published.isoformat() + "Z",
        "categories": ["Threats"],
        "resource_type": "news",
        "tags": TAG_SETS[index % len(TAG_SETS)],
    }
    # an article carries either a summary or its full content
    key = "summary" if index % 2 == 0 else "content"
    source[key] = fake.paragraph(nb_sentences=3)
    return {"_index": "news", "_id": fake.uuid4(), "_score": 1.0, "_source": source}


@router.get("/search/")
async def search(start_date: str, offset: int = Query(0, alias="from")) -> dict:
    """The news of the day in the request; the pages after the first are empty."""
    hits = []
    if offset == 0:
        day = parse(start_date).replace(tzinfo=None)
        hits = [_news(day, i) for i in range(4)]
    return {"took": 5, "hits": {"total": {"value": len(hits)}, "hits": hits}}
