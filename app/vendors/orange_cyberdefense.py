"""Orange Cyberdefense: the Datalake API (bulk searches downloaded as zipped STIX
bundles, threat library, threat lookup) and the World Watch API (advisories), read by
the orange-cyberdefense-v3 import and orange-cyberdefense-enrichment-v3 connectors.

The connectors use the datalake-scripts library, which authenticates with a long term
token (no token request) and polls bulk search tasks until their state is DONE.
"""

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["datalake.cert.orangecyberdefense.com", "api-ww.cert.orangecyberdefense.com"]
router = APIRouter(prefix="/orange-cyberdefense", tags=["Orange Cyberdefense"])

AUTHOR = fake.stix_identity("Orange Cyberdefense", "organization")
GUI = "https://datalake.cert.orangecyberdefense.com"
TAGS = ["tlp:green", "tlp:amber", "tlp:clear"]
SCAN_LABELS = ["botnet", "c2", "phishing", "ransomware", "scanner"]
# The atom types Datalake knows, with the STIX pattern of each
ATOMS = ["domain", "ip", "url", "file", "email"]

# Bulk search tasks created: their flags decide what the download holds
_tasks: dict[str, dict] = {}


def _now() -> datetime:
    return datetime.now(UTC)


def _ts(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _atom_value(atom: str, value: str | None = None) -> tuple[str, str]:
    """The value and STIX pattern of an atom."""
    match atom:
        case "ip":
            value = value or fake.ipv4_public()
            return value, f"[ipv4-addr:value = '{value}']"
        case "url":
            value = value or fake.url()
            return value, f"[url:value = '{value}']"
        case "file":
            value = value or fake.sha256()
            return value, f"[file:hashes.'SHA-256' = '{value}']"
        case "email":
            value = value or fake.email()
            return value, f"[email-addr:value = '{value}']"
        case _:
            value = value or fake.domain_name()
            return value, f"[domain-name:value = '{value}']"


def _indicator(
    atom: str,
    value: str | None = None,
    scored: bool = True,
    whitelisted: bool = False,
) -> dict:
    value, pattern = _atom_value(atom, value)
    hashkey = fake.md5()
    now = _now()
    first_seen = now - timedelta(days=fake.random_int(2, 60))
    score = (
        {
            "ddos": 0,
            "fraud": 0,
            "hack": fake.random_int(0, 40),
            "leak": 0,
            "malware": fake.random_int(60, 100),
            "phishing": fake.random_int(0, 100),
            "scam": 0,
            "scan": 0,
            "spam": 0,
        }
        if scored
        else {}
    )
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid4()}",
        "created": _ts(first_seen),
        "modified": _ts(now),
        "created_by_ref": AUTHOR["id"],
        "name": value,
        "description": f"Datalake threat {hashkey}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _ts(first_seen),
        "labels": [
            fake.random_element(TAGS),
            f"origin:{fake.random_element(['honeypot', 'sandbox', 'feed'])}",
            f'family="{fake.malware_family().lower().replace(" ", "_")}"',
        ],
        "external_references": [
            {
                "source_name": "Orange Cyberdefense",
                "url": f"{GUI}/api/v3/mrti/threats/{hashkey}/",
                "external_id": hashkey,
            }
        ],
        "x_datalake_atom_type": atom,
        "x_datalake_score": score,
        "x_datalake_sources": [
            {
                "source_id": source,
                "count": fake.random_int(1, 30),
                "first_seen": _ts(first_seen),
                "last_updated": _ts(now - timedelta(hours=fake.random_int(1, 40))),
                "min_depth": 0,
                "max_depth": fake.random_int(0, 2),
            }
            for source in fake.random_elements(
                ["ocd_peerpressure", "phishtank", "abuse_ch", "urlhaus"],
                length=2,
                unique=True,
            )
        ],
    }
    if whitelisted:
        indicator["x_datalake_whitelist_sources"] = [{"source_id": "tranco_top_1m"}]
    return indicator


def _entities(tag: str | None = None) -> list[dict]:
    """Threat library entries: a malware, a threat actor, a tool and a technique."""
    labels = ["ransomware", "tlp:clear"]
    if tag:
        labels = [tag, "tlp:clear"]
    entities = [
        fake.stix_malware(),
        fake.stix_threat_actor(),
        fake.stix_tool(),
        fake.stix_attack_pattern(),
    ]
    for entity in entities:
        entity["created_by_ref"] = AUTHOR["id"]
        entity["labels"] = labels
        entity["external_references"] = [
            *entity.get("external_references", []),
            {
                "source_name": "Orange Cyberdefense",
                "url": f"{GUI}/api/v3/mrti/threat-entity/{uuid4()}/",
            },
        ]
    return entities


def _bundle_objects(
    count: int,
    indicators_only: bool = False,
    no_sightings: bool = False,
    atoms: list[str] | None = None,
) -> list[dict]:
    """What a bulk search holds: indicators on every atom type (one without score, one
    whitelisted: the connector skips them), the threat entities they relate to and
    positive sightings."""
    atoms = atoms or ATOMS
    indicators = [_indicator(atoms[i % len(atoms)]) for i in range(count)]
    indicators.append(_indicator("domain", scored=False))
    indicators.append(_indicator("domain", whitelisted=True))
    objects: list[dict] = [AUTHOR, *indicators]
    if indicators_only:
        return objects
    entities = _entities()
    malware, actor = entities[0], entities[1]
    objects += entities
    for indicator in indicators[:count]:
        objects.append(
            fake.stix_relationship(indicator["id"], malware["id"], "indicates")
        )
    objects.append(fake.stix_relationship(actor["id"], malware["id"], "uses"))
    if not no_sightings:
        for indicator in indicators[:2]:
            moment = _now() - timedelta(days=1)
            objects.append(
                {
                    "type": "sighting",
                    "spec_version": "2.1",
                    "id": f"sighting--{uuid4()}",
                    "created": _ts(moment),
                    "modified": _ts(moment),
                    "created_by_ref": AUTHOR["id"],
                    "sighting_of_ref": indicator["id"],
                    "where_sighted_refs": [AUTHOR["id"]],
                    "count": fake.random_int(1, 20),
                    "first_seen": _ts(moment - timedelta(days=3)),
                    "last_seen": _ts(moment),
                }
            )
    return objects


# -- Datalake --


@router.get("/api/v3/users/me/")
async def users_me() -> dict:
    """The token owner, with the permission the connector checks."""
    return {
        "id": fake.random_int(1000, 9999),
        "email": fake.email(),
        "role": {
            "name": "Analyst",
            "administration_permissions": [
                {"name": "bulk_search"},
                {"name": "advanced_search"},
            ],
        },
    }


@router.get("/api/v3/mrti/advanced-queries/threats/{query_hash}/")
async def advanced_query(query_hash: str) -> dict:
    """A saved query: its body has a main AND operator, which the connector extends."""
    return {
        "query_hash": query_hash,
        "query_body": {
            "AND": [
                {
                    "AND": [
                        {
                            "field": "atom_type",
                            "type": "filter",
                            "value": ["domain", "ip", "url", "file", "email"],
                        }
                    ]
                }
            ]
        },
        "total": 0,
        "results": [],
    }


def _task(task_uuid: str, state: str = "DONE") -> dict:
    now = _now()
    return {
        "bulk_search": {
            "advanced_query_hash": fake.md5(),
            "query_fields": [],
        },
        "bulk_search_hash": fake.md5(),
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%S.%f"),
        "eta": now.strftime("%Y-%m-%dT%H:%M:%S.%f"),
        "file_delete_after": (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S"),
        "file_deleted": False,
        "file_size": 4096,
        "finished_at": now.strftime("%Y-%m-%dT%H:%M:%S.%f"),
        "progress": 100,
        "queue_position": 0,
        "results": 12,
        "started_at": now.strftime("%Y-%m-%dT%H:%M:%S.%f"),
        "state": state,
        "uuid": task_uuid,
        "user": {"id": 1, "email": fake.email()},
    }


@router.post("/api/v3/mrti/bulk-search/")
async def bulk_search_create(request: Request) -> dict:
    """A task, queued: the next call reports it done."""
    body = await request.json()
    task_uuid = str(uuid4())
    _tasks[task_uuid] = {
        "indicators_only": bool(body.get("indicators_only")),
        "no_sightings": bool(body.get("indicators_and_threat_entities_only")),
    }
    return {"task_uuid": task_uuid}


@router.post("/api/v3/mrti/bulk-search/tasks/")
async def bulk_search_tasks(request: Request) -> dict:
    body = await request.json()
    return {"count": 1, "results": [_task(body["task_uuid"])]}


@router.get("/api/v3/mrti/bulk-search/task/{task_uuid}/")
async def bulk_search_download(task_uuid: str) -> Response:
    """The results as a zip of STIX bundles, one per file."""
    flags = _tasks.get(task_uuid, {})
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for index in range(2):
            objects = _bundle_objects(
                count=3,
                indicators_only=flags.get("indicators_only", False),
                no_sightings=flags.get("no_sightings", False),
                # the identity is part of every file: keep the objects unique by file
                atoms=ATOMS[index::2],
            )
            archive.writestr(
                f"stix_{index}.json", json.dumps(fake.stix_bundle(objects=objects))
            )
    return Response(content=buffer.getvalue(), media_type="text/x-stix-zip")


@router.post("/api/v3/mrti/threat-entity/filtered/")
async def threat_entities(request: Request) -> dict:
    """Threat library entries, those carrying the tag asked when there is one."""
    body = await request.json()
    return fake.stix_bundle(objects=[AUTHOR, *_entities(body.get("tag"))])


@router.get("/api/v3/mrti/threats/lookup/")
async def threat_lookup(atom_value: str, atom_type: str = "domain") -> JSONResponse:
    """A threat for the atom: its indicator, the identity and a related malware."""
    atom = atom_type if atom_type in ATOMS else "domain"
    indicator = _indicator(atom, atom_value)
    malware = _entities()[0]
    objects = [
        AUTHOR,
        indicator,
        malware,
        fake.stix_relationship(indicator["id"], malware["id"], "indicates"),
    ]
    return JSONResponse({**fake.stix_bundle(objects=objects), "threat_found": True})


# -- World Watch --


def _content_blocks() -> list[dict]:
    now = _now()
    blocks = []
    for index in range(2):
        created = now - timedelta(days=3 - index)
        updated = created + timedelta(hours=2)
        tags = fake.random_elements(SCAN_LABELS, length=2, unique=True)
        blocks.append(
            {
                "id": fake.random_int(1000, 99999),
                "advisory": f"OCD-{now.year}-{fake.random_int(100, 999)}",
                "title": fake.sentence(nb_words=6),
                "severity": fake.random_int(1, 5),
                "timestamp_created": created.isoformat(),
                "timestamp_updated": updated.isoformat(),
                "tags": tags,
                "advisory_tags": [],
                "sources": [
                    {
                        "title": fake.company(),
                        "url": fake.url(),
                        "description": fake.sentence(),
                    },
                    {"title": None, "url": fake.url(), "description": None},
                ],
                # Only the first advisory comes with a Datalake search of its indicators
                "datalake_url": (
                    {
                        "title": "Datalake search",
                        "url": f"{GUI}/gui/search?query_hash={fake.md5()}",
                        "description": "Indicators of the advisory",
                    }
                    if index == 0
                    else None
                ),
            }
        )
    return blocks


@router.get("/api/content_block/")
async def content_blocks() -> dict:
    """World Watch advisories, oldest update first."""
    return {"items": _content_blocks(), "total": 2}


@router.get("/api/content_block/{block_id}/html")
async def content_block_html(block_id: int) -> dict:  # noqa: ARG001
    return {
        "html": (
            f"<h1>{fake.sentence(nb_words=5)}</h1><p>{fake.paragraph()}</p>"
            "<h2>Indicators</h2><ul>"
            + "".join(f"<li>{fake.domain_name()}</li>" for _ in range(3))
            + "</ul>"
        )
    }
