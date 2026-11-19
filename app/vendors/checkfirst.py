"""Checkfirst: the Pravda network articles feed (keyset pagination on ``_id``), read by
the OpenCTI checkfirst-import-connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.checkfirst.network"]
router = APIRouter(prefix="/checkfirst", tags=["Checkfirst"])

PAGES = 2
PAGE_SIZE = 5
SITES = ["news-pravda.com", "france.news-pravda.com", "deutsch.news-pravda.com"]


def _article(index: int) -> dict:
    site = SITES[index % len(SITES)]
    telegram = index % 2 == 0
    channel = fake.user_name()
    published = datetime.now(UTC) - timedelta(hours=index + 1)
    url = f"https://{site}/{fake.slug()}"
    return {
        "_id": f"{index:024x}",
        "url": url,
        "canonical_url": url,
        "title": fake.sentence(),
        "description": fake.sentence(),
        "og_description": fake.paragraph(),
        "og_image": fake.image_url(),
        "keywords": fake.words(3),
        "language": fake.random_element(["en", "fr", "de"]),
        "domain": site,
        "source_title": channel,
        "source_url": f"https://t.me/{channel}"
        if telegram
        else f"https://{fake.domain_name()}",
        "published_date": published.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scraped_date": (published + timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "alternates_urls": [
            {"url": fake.url(), "language": "en"},
            {"url": "", "language": "fr"},
        ],
    }


@router.get("/v1/articles")
async def articles(after: str = "") -> dict:
    """Pages of articles by ascending ``_id``: ``after`` is the exclusive cursor."""
    start = int(after, 16) + 1 if after else 0
    page = [
        _article(i) for i in range(start, min(start + PAGE_SIZE, PAGES * PAGE_SIZE))
    ]
    has_next = start + PAGE_SIZE < PAGES * PAGE_SIZE
    return {
        "data": page,
        "pagination": {
            "has_next": has_next,
            "next_cursor": page[-1]["_id"] if has_next else None,
        },
    }
