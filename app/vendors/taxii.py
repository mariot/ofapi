"""A generic TAXII server (2.1 under ``/taxii21``, 2.0 under ``/taxii20``) with a
readable collection whose objects are paginated, and a writable one accepting pushed
objects.

Read by the OpenCTI taxii2 connector (``taxii2-client``), written by the taxii-post
connector.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request, Response

from app.fake import fake

HOSTS = ["taxii.staticfire.test"]
router = APIRouter(prefix="/taxii", tags=["TAXII"])

TAXII21 = "application/taxii+json;version=2.1"
STIX21 = "application/stix+json;version=2.1"
TAXII20 = "application/vnd.oasis.taxii+json; version=2.0"
STIX20 = "application/vnd.oasis.stix+json; version=2.0"
BASE = "https://taxii.staticfire.test"
READ_ID = "91a7b528-80eb-42ed-a74d-c6fbd5a26116"
WRITE_ID = "52892447-4d7e-4f70-b94d-d7f22742ff63"
PAGE_SIZE = 4
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
DATE = "%Y-%m-%dT%H:%M:%S.%fZ"

# One dataset per collection and version, renewed by every request without a cursor
_datasets: dict[tuple[str, str], list[dict]] = {}


def _answer(body: dict, media: str, status: int = 200) -> Response:
    return Response(json.dumps(body), status_code=status, media_type=media)


def _stamp(moment: datetime) -> str:
    return moment.strftime(DATE)


def _uuid5(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, value)}"


def _dataset(version: str) -> list[dict]:
    """Indicators of every pattern type, observables, a vulnerability, a malware with
    its relationship and a report; ``date_added`` rises with the rank."""
    ip, ip2, domain, url = (
        fake.ipv4_public(),
        fake.ipv4_public(),
        fake.domain_name(),
        fake.url(),
    )
    sha256, md5 = fake.sha256(), fake.md5()
    cve, family = fake.cve_id(), fake.malware_family()
    other = fake.domain_name()
    created = datetime.now(UTC) - timedelta(hours=2)
    stamp = _stamp(created)
    two = version == "2.0"

    def indicator(pattern: str, name: str, labels: list[str]) -> dict:
        item = {
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": stamp,
            "modified": stamp,
            "name": name,
            "description": f"Reported by {fake.company()}",
            "pattern": pattern,
            "valid_from": stamp,
            "labels": labels,
        }
        if not two:
            item.update(
                spec_version="2.1",
                pattern_type="stix",
                indicator_types=["malicious-activity"],
            )
        return item

    malware = {
        "type": "malware",
        "id": f"malware--{uuid.uuid4()}",
        "created": stamp,
        "modified": stamp,
        "name": family,
        "labels": ["trojan"] if two else None,
        "is_family": True,
    }
    vulnerability = {
        "type": "vulnerability",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": stamp,
        "modified": stamp,
        "name": cve,
        "description": f"{cve} allows remote code execution",
        "external_references": [{"source_name": "cve", "external_id": cve}],
    }
    identity = {
        "type": "identity",
        "id": f"identity--{uuid.uuid4()}",
        "created": stamp,
        "modified": stamp,
        "name": fake.company(),
        "identity_class": "organization",
    }
    objects = [
        indicator(f"[ipv4-addr:value = '{ip}']", ip, ["malicious", "high"]),
        indicator(f"[domain-name:value = '{domain}']", domain, ["phishing", "medium"]),
        indicator(f"[url:value = '{url}']", url, ["malware-delivery", "low"]),
        indicator(f"[file:hashes.'SHA-256' = '{sha256}']", sha256[:16], ["ransomware"]),
        indicator(
            f"[ipv4-addr:value = '{ip2}' OR domain-name:value = '{other}']",
            "Multiple indicators",
            ["c2"],
        ),
        indicator(f"[file:hashes.MD5 = '{md5}']", md5, ["trojan", "high"]),
        malware,
        vulnerability,
        identity,
    ]
    if not two:
        objects += [
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": _uuid5("ipv4-addr", ip2),
                "value": ip2,
            },
            {
                "type": "domain-name",
                "spec_version": "2.1",
                "id": _uuid5("domain-name", domain),
                "value": fake.domain_name(),
            },
        ]
    objects.append(
        {
            "type": "relationship",
            "id": f"relationship--{uuid.uuid4()}",
            "created": stamp,
            "modified": stamp,
            "relationship_type": "indicates",
            "source_ref": objects[0]["id"],
            "target_ref": malware["id"],
        }
    )
    objects.append(
        {
            "type": "report",
            "id": f"report--{uuid.uuid4()}",
            "created": stamp,
            "modified": stamp,
            "name": f"{family} campaign",
            "published": stamp,
            "report_types": ["threat-report"],
            "labels": ["threat-report"] if two else None,
            "object_refs": [malware["id"], vulnerability["id"], objects[0]["id"]],
        }
    )
    objects = [{k: v for k, v in item.items() if v is not None} for item in objects]
    for item in objects:
        if item["type"] in ("relationship", "report") and not two:
            item["spec_version"] = "2.1"
        elif item["type"] in ("malware", "vulnerability", "identity") and not two:
            item["spec_version"] = "2.1"
    for rank, item in enumerate(objects):
        item["_date_added"] = _stamp(created + timedelta(minutes=rank))
    return objects


def _root(version: str, media: str) -> Response:
    versions = ["taxii-2.0"] if version == "2.0" else [TAXII21]
    return _answer(
        {
            "title": "Staticfire",
            "description": "TAXII test server",
            "versions": versions,
            "max_content_length": 104857600,
        },
        media,
    )


def _collections(version: str, media: str) -> Response:
    stix = STIX20 if version == "2.0" else STIX21
    return _answer(
        {
            "collections": [
                {
                    "id": READ_ID,
                    "title": "indicators",
                    "description": "Indicators feed",
                    "can_read": True,
                    "can_write": False,
                    "media_types": [stix],
                },
                {
                    "id": WRITE_ID,
                    "title": "inbox",
                    "description": "Objects pushed by OpenCTI",
                    "can_read": True,
                    "can_write": True,
                    "media_types": [stix],
                },
            ]
        },
        media,
    )


@router.get("/taxii21/")
@router.get("/taxii21/taxii2/")
async def discovery21() -> Response:
    return _answer(
        {
            "title": "Staticfire TAXII 2.1",
            "default": f"{BASE}/root/",
            "api_roots": [f"{BASE}/root/"],
        },
        TAXII21,
    )


@router.get("/taxii20/")
@router.get("/taxii20/taxii2/")
async def discovery20() -> Response:
    return _answer(
        {
            "title": "Staticfire TAXII 2.0",
            "default": f"{BASE}/root20/",
            "api_roots": [f"{BASE}/root20/"],
        },
        TAXII20,
    )


@router.get("/root/")
async def api_root21() -> Response:
    return _root("2.1", TAXII21)


@router.get("/root20/")
async def api_root20() -> Response:
    return _root("2.0", TAXII20)


@router.get("/root/collections/")
async def collections21() -> Response:
    return _collections("2.1", TAXII21)


@router.get("/root20/collections/")
async def collections20() -> Response:
    return _collections("2.0", TAXII20)


def _public(item: dict) -> dict:
    return {k: v for k, v in item.items() if not k.startswith("_")}


@router.get("/root/collections/{collection_id}/objects/")
async def objects21(collection_id: str, request: Request) -> Response:
    """A page of the dataset: ``limit`` objects from the cursor ``next`` (an offset)."""
    query = request.query_params
    key = (collection_id, "2.1")
    if "next" not in query or key not in _datasets:
        _datasets[key] = _dataset("2.1")
    offset = int(query.get("next", 0))
    limit = int(query.get("limit", PAGE_SIZE))
    items = _datasets[key][offset : offset + limit]
    more = offset + limit < len(_datasets[key])
    body: dict = {"more": more, "objects": [_public(item) for item in items]}
    if more:
        body["next"] = str(offset + limit)
    return _answer(body, TAXII21)


def _page20(collection_id: str, query) -> list[dict]:
    key = (collection_id, "2.0")
    after = query.get("added_after")
    # A cursor is the X-TAXII-Date-Added-Last of a page: anything else starts a new run
    cursors = {i["_date_added"] for i in _datasets.get(key, [])}
    if after not in cursors:
        _datasets[key] = _dataset("2.0")
    items = [i for i in _datasets[key] if after is None or i["_date_added"] > after]
    return items[:PAGE_SIZE]


@router.get("/root20/collections/{collection_id}/objects/")
async def objects20(collection_id: str, request: Request) -> Response:
    """A STIX 2.0 bundle of the next objects added after ``added_after``."""
    items = _page20(collection_id, request.query_params)
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [_public(item) for item in items],
    }
    response = _answer(bundle, STIX20)
    if items:
        response.headers["X-TAXII-Date-Added-Last"] = items[-1]["_date_added"]
    return response


@router.get("/root20/collections/{collection_id}/manifest/")
async def manifest20(collection_id: str, request: Request) -> Response:
    """The manifest entry of the requested object id."""
    wanted = request.query_params.get("match[id]")
    entries = [
        {
            "id": item["id"],
            "date_added": item["_date_added"],
            "versions": [item["modified"]],
            "media_types": [STIX20],
        }
        for item in _datasets.get((collection_id, "2.0"), [])
        if wanted is None or item["id"] == wanted
    ]
    return _answer({"objects": entries}, TAXII20)


@router.post("/root/collections/{collection_id}/objects/")
async def add_objects(request: Request) -> Response:
    """Accepts a pushed envelope or bundle and answers its TAXII status."""
    try:
        payload = await request.json()
    except ValueError:
        payload = {}
    count = len(payload.get("objects", [])) if isinstance(payload, dict) else 0
    return _answer(
        {
            "id": str(uuid.uuid4()),
            "status": "complete",
            "request_timestamp": _stamp(datetime.now(UTC)),
            "total_count": count,
            "success_count": count,
            "failure_count": 0,
            "pending_count": 0,
        },
        TAXII21,
        status=202,
    )
