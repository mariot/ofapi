"""CTM360 CYNA (cyber news and alerts): the news feed with cursor pagination, read by
the OpenCTI ctm360-cyna-feed connector."""

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["cyna.ctm360.com"]
router = APIRouter(prefix="/ctm360-cyna", tags=["CTM360 CYNA"])

TOTAL = 7


def _news_item(index: int) -> dict:
    cve = fake.cve_id()
    subjects = [
        f"Critical vulnerability {cve} exploited in the wild",
        f"{fake.malware_family()} ransomware hits a {fake.industry_sector()} provider",
        f"Phishing campaign by APT group targets {fake.company()}",
        f"Data breach exposes customers of {fake.company()}",
    ]
    published = fake.date_time_between(start_date="-10d").strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "_id": fake.sha1()[:24],
        "metadata": {
            "title": subjects[index % len(subjects)],
            "description": f"{fake.paragraph(nb_sentences=3)} Tracked as {cve}.",
            "link": fake.url(),
            "published_date": published,
            "source": fake.company(),
        },
    }


@router.get("/api/v1/news")
async def news(
    size: int = Query(25, ge=1), search_after: str = Query("", alias="searchAfter")
) -> dict:
    """``size`` items after the cursor (an offset); ``hasMore`` ends the pagination."""
    start = int(search_after) if search_after.isdigit() else 0
    end = min(start + size, TOTAL)
    return {
        "success": True,
        "statusCode": 200,
        "total": {"value": TOTAL, "relation": "eq"},
        "data": [_news_item(i) for i in range(start, end)],
        "hasMore": end < TOTAL,
        "nextSearchAfter": str(end) if end < TOTAL else None,
    }
