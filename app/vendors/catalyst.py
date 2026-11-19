"""PRODAFT Catalyst: member contents, their references and threat actors, read by the
catalyst connector through the python-catalyst client."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query, Request

from app.fake import fake

HOSTS = ["prod.blindspot.prodaft.com"]
router = APIRouter(prefix="/catalyst", tags=["Catalyst"])

CATEGORIES = ["DISCOVERY", "ATTRIBUTION", "RESEARCH", "FLASH_ALERT"]
TLPS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]

CONTENTS: list[dict] = []
REFERENCES: dict[str, list[dict]] = {}
ACTORS: dict[str, dict] = {}


def _zulu(when: datetime) -> str:
    """Timestamps the way the API writes them (Django REST framework, UTC)."""
    return when.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _reference(kind: str, value: str, value_type: str | None = None) -> dict:
    reference = {
        "entity_type": kind,
        "entity": fake.uuid4(),
        "value": value,
        "context": fake.sentence(),
    }
    if value_type:
        reference["value_type"] = value_type
    return reference


def _references() -> list[dict]:
    actor = _reference("ThreatActor", fake.intrusion_set())
    ACTORS[actor["entity"]] = {
        "id": actor["entity"],
        "name": actor["value"],
        "description": fake.paragraph(),
        "is_group": True,
        "is_abstract": len(ACTORS) % 2 == 0,
        "aliases": [{"name": fake.intrusion_set()}],
        "motivation": "financial-gain",
        "spoken_languages": [{"name": "Russian"}],
        "suspected_origins": [{"name": "Russia", "code": "ru"}],
        "associated_risks": ["ransomware"],
    }
    return [
        _reference("Observable", fake.ipv4_public(), "IP_ADDRESS"),
        _reference("Observable", fake.domain_name(), "DOMAIN_NAME"),
        _reference("Observable", fake.url(), "URL"),
        _reference("Observable", fake.sha256(), "FILE_HASH_SHA256"),
        _reference("Observable", fake.md5(), "FILE_HASH_MD5"),
        _reference("Observable", fake.email(), "EMAIL"),
        actor,
        _reference("Malware", fake.malware_family()),
        _reference("Tool", fake.threat_tool()),
        _reference("Vulnerability", fake.cve_id()),
        _reference("Campaign", f"Operation {fake.word().capitalize()}"),
        _reference("Organization", fake.company()),
        _reference("Sector", fake.industry_sector()),
        _reference("Country", fake.country()),
    ]


def _contents() -> list[dict]:
    if not CONTENTS:
        for index in range(6):
            content_id = fake.uuid4()
            updated = datetime.now(UTC) - timedelta(days=index, hours=1)
            CONTENTS.append(
                {
                    "id": content_id,
                    "title": fake.sentence(nb_words=6),
                    "slug": fake.slug(),
                    "summary": fake.paragraph(),
                    "description": fake.paragraph(),
                    "category": CATEGORIES[index % len(CATEGORIES)],
                    "sub_category": {"name": "Threat intelligence"},
                    "topics": [{"name": fake.word()}],
                    "tlp": TLPS[index % len(TLPS)],
                    "published_on": _zulu(updated - timedelta(days=1)),
                    "updated_on": _zulu(updated),
                    "tags": [fake.word()],
                }
            )
            REFERENCES[content_id] = _references()
    return CONTENTS


@router.get("/api/posts/member-contents/")
async def member_contents(
    request: Request, page: int = 1, page_size: int = 100, category: str = ""
) -> dict:
    """Contents filtered by category and TLP, newest update first, paginated."""
    tlps = request.query_params.getlist("tlp")
    results = [
        c
        for c in _contents()
        if (not category or c["category"] == category)
        and (not tlps or c["tlp"] in tlps)
    ]
    start = (page - 1) * page_size
    more = start + page_size < len(results)
    return {
        "count": len(results),
        "next": f"{request.url.include_query_params(page=page + 1)}" if more else None,
        "previous": None,
        "results": results[start : start + page_size],
    }


@router.get("/api/posts/references/")
async def post_references(
    post: str = Query(), page: int = 1, page_size: int = 100
) -> dict:
    """The entities a content mentions."""
    _contents()
    references = REFERENCES.get(post, [])
    start = (page - 1) * page_size
    more = start + page_size < len(references)
    return {
        "count": len(references),
        "next": f"page={page + 1}" if more else None,
        "previous": None,
        "results": references[start : start + page_size],
    }


@router.get("/api/actors/{actor_id}/")
async def actor(actor_id: str) -> dict:
    return ACTORS[actor_id]
