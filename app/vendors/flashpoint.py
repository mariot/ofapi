"""Flashpoint: finished intelligence reports, technical intelligence indicators, alerts
(with their communities and media documents), communities search and compromised
credential sightings (flashpoint import connector)."""

import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request, Response

from app.fake import fake

HOSTS = ["api.flashpoint.io"]
router = APIRouter(prefix="/flashpoint", tags=["Flashpoint"])

# Created in OpenCTI by the test, so that the reports' tags and actors resolve to them
KNOWN_ACTOR = "Staticfire Panda"
KNOWN_MALWARE = "StaticfireRAT"
# 1x1 transparent PNG, the media of a media alert
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c6360000002000001e221bc330000000049454e44ae426082"
)
CREDENTIALS = 4
CREDENTIALS_FIRST_PAGE = 2


def ago(**delta: int) -> datetime:
    return datetime.now(UTC).replace(microsecond=0) - timedelta(**delta)


def zulu(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@router.get("/finished-intelligence/v1/reports")
async def reports(skip: int = 0, limit: int = 100) -> dict:
    """The reports since the date asked; the connector pages until it has ``total``."""
    items = []
    for number in range(5):
        posted = ago(days=number + 1)
        title = fake.sentence(nb_words=7)
        items.append(
            {
                "id": uuid.uuid4().hex,
                "title": title,
                "summary": fake.paragraph(),
                "body": f"<h2>{title}</h2><p>{fake.paragraph(nb_sentences=6)}</p>",
                "posted_at": zulu(posted),
                "updated_at": zulu(posted),
                "tags": [KNOWN_MALWARE, "ransomware", fake.industry_sector()],
                "actors": [KNOWN_ACTOR],
                "platform_url": f"https://app.flashpoint.io/cti/intelligence/report/{uuid.uuid4().hex}",
            }
        )
    return {"total": len(items), "data": items[skip : skip + limit]}


def sighting(tags: list[str], related: list[dict], moment: datetime) -> dict:
    return {
        "id": uuid.uuid4().hex,
        "source": "flashpoint_extraction",
        "sighted_at": zulu(moment),
        "description": fake.sentence(),
        "tags": tags,
        "related_iocs": related,
    }


def indicator(kind: str, value: str, modified: datetime, **extra) -> dict:
    malware = fake.malware_family()
    tags = [f"malware:{malware}", f"actor:{KNOWN_ACTOR}", "type:botnet"]
    technique = fake.mitre_attack_technique()
    return {
        "id": uuid.uuid4().hex,
        "type": kind,
        "value": value,
        "created_at": zulu(modified - timedelta(hours=2)),
        "modified_at": zulu(modified),
        "first_seen_at": zulu(modified - timedelta(days=1)),
        "last_seen_at": zulu(modified),
        "description": fake.sentence(),
        "score": {
            "value": fake.random_element(["informational", "suspicious", "malicious"])
        },
        "malware_description": f"<p>{fake.paragraph(nb_sentences=2)}</p>",
        "mitre_attack_ids": [
            {
                "id": technique["external_id"],
                "name": technique["name"],
                "description": fake.sentence(),
                "tactics": [technique["phase_name"].replace("-", " ").title()],
            }
        ],
        "platform_urls": {
            "ignite": f"https://app.flashpoint.io/cti/malware/iocs/{uuid.uuid4().hex}"
        },
        "sightings": [
            sighting(
                tags,
                [
                    {"type": "domain", "value": fake.domain_name()},
                    {"type": "ipv4", "value": fake.ipv4_public()},
                ],
                modified,
            )
        ],
        "latest_sighting": sighting(tags, [], modified),
        **extra,
    }


def indicators_page(first: bool) -> list[dict]:
    moment = ago(days=2) if first else ago(hours=6)
    if first:
        config = {
            "C2": [fake.ipv4_public(), f"http://{fake.domain_name()}/gate.php"],
            "Port": 443,
            "Mutex": fake.bothify("Global\\????####"),
        }
        return [
            indicator("ipv4", fake.ipv4_public(), moment),
            indicator("domain", fake.domain_name(), moment + timedelta(minutes=5)),
            indicator("url", fake.url(), moment + timedelta(minutes=10)),
            indicator(
                "file",
                "",
                moment + timedelta(minutes=15),
                hashes={
                    "sha256": fake.sha256(),
                    "md5": fake.md5(),
                    "sha1": fake.sha1(),
                },
            ),
            indicator("email", fake.email(), moment + timedelta(minutes=20)),
            indicator(
                "extracted_config", json.dumps(config), moment + timedelta(minutes=25)
            ),
        ]
    return [
        indicator("ipv6", fake.ipv6(), moment),
        indicator("sha256", fake.sha256(), moment + timedelta(minutes=5)),
        indicator(
            "asn", str(fake.random_int(1000, 64000)), moment + timedelta(minutes=10)
        ),
        indicator("domain", fake.domain_name(), moment + timedelta(minutes=15)),
    ]


@router.get("/technical-intelligence/v2/indicators")
async def indicators(request: Request) -> dict:
    """Two pages sorted by modification date, the first one linking to the next."""
    page = int(request.query_params.get("page", 1))
    if page == 1:
        since = request.query_params.get("modified_after", "")
        link = (
            "https://api.flashpoint.io/technical-intelligence/v2/indicators"
            f"?size=500&sort=modified_at:asc&modified_after={since}&embed=all&page=2"
        )
        return {"items": indicators_page(True), "pagination": {"next": link}}
    return {"items": indicators_page(False), "pagination": {"next": None}}


@router.get("/alert-management/v1/notifications")
async def notifications() -> dict:
    """One alert of each source the connector knows, and one it skips."""

    def alert(source: str, resource: dict, reason: str) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "created_at": zulu(ago(hours=fake.random_int(1, 60))),
            "status": "unread",
            "source": source,
            "reason": {"id": str(uuid.uuid4()), "name": reason},
            "highlight_text": fake.paragraph(),
            "resource": resource,
        }

    def forum(title: str) -> dict:
        return {
            "id": uuid.uuid4().hex,
            "title": title,
            "site": {"title": fake.random_element(["Exploit", "XSS", "BreachForums"])},
            "site_actor": {"names": {"handle": fake.user_name()}},
        }

    return {
        "items": [
            alert(
                "communities", forum(fake.sentence(nb_words=5)), "Corporate Credentials"
            ),
            alert("media", forum(fake.sentence(nb_words=4)), "Brand Mentions"),
            alert(
                "data_exposure_github",
                {
                    "id": uuid.uuid4().hex,
                    "source": "github",
                    "repo": f"{fake.user_name()}/{fake.slug()}",
                    "owner": fake.user_name(),
                    "url": f"https://github.com/{fake.user_name()}/{fake.slug()}",
                },
                "Source Code Leak",
            ),
            alert("forums", forum("Unsupported source"), "Other"),
        ],
        "pagination": {"next": None},
    }


@router.get("/sources/v2/communities/{doc_id}")
async def communities_doc(doc_id: str) -> dict:
    """The community post an alert points to."""
    return {
        "results": {
            "id": doc_id,
            "site_actor_alias": [fake.user_name(), fake.user_name()],
            "container_external_uri": f"https://t.me/{fake.slug()}",
        }
    }


@router.get("/sources/v2/media/{doc_id}")
async def media_doc(doc_id: str) -> dict:
    """The media document an alert points to, with the asset to download."""
    return {
        "id": doc_id,
        "media_id": fake.bothify("????########"),
        "storage_uri": f"media/{uuid.uuid4().hex}.png",
    }


@router.get("/sources/v1/media")
async def media() -> Response:
    """The asset itself."""
    return Response(content=PNG, media_type="image/png")


@router.post("/sources/v2/communities")
async def communities_search(request: Request) -> dict:
    """Posts matching a query, all in one page."""
    query = (await request.json()).get("query", "")
    posted = ago(hours=fake.random_int(1, 40))
    items = []
    for number in range(3):
        first = posted - timedelta(hours=number)
        items.append(
            {
                "id": f"{uuid.uuid4().hex}",
                "title": f"{query} {fake.sentence(nb_words=4)}",
                "message": fake.paragraph(),
                "date": zulu(first),
                "first_observed_at": zulu(first),
                "last_observed_at": zulu(first + timedelta(hours=2)),
                "container_name": f"{fake.company()} chat {query}",
                "site": fake.random_element(["telegram", "discord", "xss"]),
                "site_title": "Telegram",
                "site_source_uri": f"https://t.me/{fake.slug()}",
            }
        )
    return {"items": items, "total": {"value": len(items), "relation": "eq"}}


def credential(number: int) -> dict:
    """A compromised credential sighting, as the Flashpoint documentation shows it."""
    indexed = ago(hours=number + 1)
    breach_created = indexed - timedelta(days=1)
    email = fake.email()
    domain = email.split("@")[1]
    url = f"https://{fake.domain_name()}/login"
    stamp = {
        "date-time": zulu(breach_created),
        "timestamp": int(breach_created.timestamp()),
    }
    return {
        "affected_domain": url.split("/")[2],
        "affected_url": url,
        "basetypes": ["credential-sighting"],
        "body": {"raw": f"url: {url}\r\nlogin: {email}\r\npassword: hunter{number}"},
        "breach": {
            "_header": {},
            "basetypes": ["breach"],
            "breach_type": "credential",
            "created_at": stamp,
            "first_observed_at": stamp,
            "fpid": fake.bothify("????????????????????"),
            "source": "Analyst Research",
            "source_type": "Credential Stealer",
            "title": f"Compromised users from stealer logs {fake.bothify('??####')}",
        },
        "credential_record_fpid": fake.bothify("?????????????????????"),
        "domain": domain if number % 2 else fake.ipv4_public(),
        "email": email,
        "fpid": fake.bothify("????????????????????"),
        "header_": {"indexed_at": int(indexed.timestamp())},
        "infected_host_attributes": {
            "fpid": fake.bothify("????????????????????"),
            "installed_software": [
                {"name": "Google Chrome", "version": "134.0.6998.166"}
            ],
            "isp": {"isp": fake.company(), "autonomous_system_number": 1234},
            "location": {"country_name": "Brazil", "city_name": "Salvador"},
            "machine": {"os": "Windows 11 Pro", "language": ["pt-BR"]},
            "malware": {"family": fake.malware_family(), "version": "12.3.4"},
        },
        "is_fresh": True,
        "last_observed_at": stamp,
        "password": f"hunter{number}",
        "password_complexity": {
            "has_lowercase": True,
            "has_number": True,
            "has_symbol": False,
            "has_uppercase": False,
            "length": 8,
        },
        "times_seen": 1,
        "username": email,
    }


def hits(start: int, count: int, total: int | dict) -> dict:
    return {
        "_scroll_id": uuid.uuid4().hex,
        "took": 12,
        "timed_out": False,
        "hits": {
            "total": total,
            "max_score": None,
            "hits": [
                {"_id": uuid.uuid4().hex, "_type": "_doc", "_source": credential(i)}
                for i in range(start, start + count)
            ],
        },
    }


@router.post("/sources/v1/noncommunities/search")
async def credentials_search() -> dict:
    """The first page of sightings; the total is a plain integer here."""
    return hits(0, CREDENTIALS_FIRST_PAGE, CREDENTIALS)


@router.post("/sources/v1/noncommunities/scroll")
async def credentials_scroll() -> dict:
    """The rest of the sightings; the total is an object here."""
    total = {"value": CREDENTIALS, "relation": "eq"}
    return hits(CREDENTIALS_FIRST_PAGE, CREDENTIALS - CREDENTIALS_FIRST_PAGE, total)
