"""Sekoia.io: the InThreat intelligence API (sekoia import connector) and the IOC
collection endpoints (sekoia-intel stream connector)."""

import base64
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["api.sekoia.io"]
router = APIRouter(prefix="/sekoia", tags=["Sekoia"])

TLP_GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
SEKOIA_IDENTITY = "identity--357447d7-9229-4ce1-b7fa-f1b83587048e"
FILE_CONTENT = b"Sekoia.io fake intelligence note\n"
FILE_SHA256 = "ba3c0a1d1e6c2f0c8cbf2bd3a1c1ba1b4d0b6d9f8d0e1d6e3a7e7a2c9f0b1d2e"

# Objects served by id, filled by every collection call
STORE: dict[str, dict] = {}
# Related objects and relationships of an indicator
RELATED: dict[str, list[dict]] = {}


def _now(delta: int = 0) -> str:
    moment = datetime.now(UTC) - timedelta(minutes=delta)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _object(kind: str, **fields) -> dict:
    stamp = _now(fake.random_int(1, 600))
    item = {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid4()}",
        "created": stamp,
        "modified": stamp,
        "created_by_ref": SEKOIA_IDENTITY,
        "object_marking_refs": [TLP_GREEN],
        "confidence": fake.random_int(50, 90),
        **fields,
    }
    STORE[item["id"]] = item
    return item


def _relationship(source: dict, target: dict, kind: str) -> dict:
    return _object(
        "relationship",
        relationship_type=kind,
        source_ref=source["id"],
        target_ref=target["id"],
    )


def _identity(identity_id: str, name: str) -> dict:
    stamp = "2020-01-01T00:00:00.000Z"
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": stamp,
        "modified": stamp,
        "name": name,
        "identity_class": "organization",
    }


def _marking(marking_id: str) -> dict:
    stamp = "2017-01-20T00:00:00.000Z"
    if marking_id == TLP_GREEN:
        return {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": marking_id,
            "created": stamp,
            "definition_type": "tlp",
            "name": "TLP:GREEN",
            "definition": {"tlp": "green"},
        }
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": stamp,
        "definition_type": "statement",
        "definition": {"statement": "Copyright SEKOIA.IO"},
    }


def _indicator(source: dict, observable: str, pattern: str) -> dict:
    return _object(
        "indicator",
        name=pattern.split("'")[1],
        pattern=pattern,
        pattern_type="stix",
        valid_from=_now(1000),
        indicator_types=["malicious-activity"],
        labels=["c2"],
        revoked=False,
        x_ic_observable_types=[observable],
        x_inthreat_sources_refs=[source["id"]],
        external_references=[
            {
                "source_name": "Sekoia.io",
                "url": "",
                "description": "",
                "external_id": "",
            }
        ],
    )


def _intel_batch() -> list[dict]:
    """Indicators of each main type with their malware, intrusion set, vulnerability and
    report; the objects linked to an indicator are served through its relationships."""
    source = _object(
        "identity",
        name=fake.company(),
        identity_class="organization",
        created_by_ref=SEKOIA_IDENTITY,
    )
    del source["confidence"], source["object_marking_refs"]
    malware = _object(
        "malware", name=fake.malware_family(), is_family=True, malware_types=["rat"]
    )
    group = _object("intrusion-set", name=fake.intrusion_set())
    technique = _object(
        "attack-pattern",
        name=fake.mitre_attack_technique()["name"],
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": "T1071",
                "url": "https://attack.mitre.org/techniques/T1071",
            }
        ],
    )
    vulnerability = _object(
        "vulnerability",
        name=fake.cve_id(),
        external_references=[{"source_name": "cve", "external_id": fake.cve_id()}],
    )
    indicators = [
        _indicator(
            source, "domain-name", f"[domain-name:value = '{fake.domain_name()}']"
        ),
        _indicator(source, "ipv4-addr", f"[ipv4-addr:value = '{fake.ipv4_public()}']"),
        _indicator(source, "url", f"[url:value = '{fake.url()}']"),
        _indicator(source, "file", f"[file:hashes.'SHA-256' = '{fake.sha256()}']"),
    ]
    for indicator in indicators:
        RELATED[indicator["id"]] = [
            {
                "related_object": malware,
                "relationship": _relationship(indicator, malware, "indicates"),
            },
            {
                "related_object": group,
                "relationship": _relationship(indicator, group, "indicates"),
            },
        ]
    report = _object(
        "report",
        name=f"Sekoia.io weekly report {fake.word()}",
        published=_now(60),
        report_types=["threat-report"],
        object_refs=[malware["id"], group["id"], indicators[0]["id"]],
        x_inthreat_uploaded_files=[
            {
                "file_name": "note",
                "sha256": FILE_SHA256,
                "mime_type": "application/pdf",
            }
        ],
    )
    return [
        malware,
        group,
        technique,
        vulnerability,
        *indicators,
        _relationship(group, malware, "uses"),
        _relationship(malware, technique, "uses"),
        _relationship(malware, vulnerability, "targets"),
        report,
    ]


def _copy(item: dict) -> dict:
    return {**item}


@router.get("/v2/inthreat/collections/{collection}/objects")
async def collection_objects(collection: str) -> dict:  # noqa: ARG001
    """One page of the collection; its cursor is the date the next page starts at."""
    items = _intel_batch()
    cursor = base64.b64encode(_now().encode()).decode()
    return {"items": [_copy(item) for item in items], "next_cursor": cursor}


@router.get("/v2/inthreat/objects/{ids}/relationships")
async def object_relationships(ids: str) -> dict:
    return {"items": [dict(link) for link in RELATED.get(ids, [])]}


@router.get("/v2/inthreat/objects/{ids}/files/{file_hash}")
async def object_file(ids: str, file_hash: str) -> Response:  # noqa: ARG001
    return Response(content=FILE_CONTENT, media_type="application/pdf")


def _lookup(item_id: str) -> dict | None:
    if item_id in STORE:
        return _copy(STORE[item_id])
    if item_id.startswith("identity--"):
        return _identity(item_id, fake.company())
    if item_id.startswith("marking-definition--"):
        return _marking(item_id)
    return None


@router.get("/v2/inthreat/objects/{ids}")
@router.get("/v2/inthreat/relationships/{ids}")
async def objects_by_id(ids: str) -> Response:
    """One object under ``data``, several under ``items``."""
    found = [item for item in map(_lookup, ids.split(",")) if item]
    if not found:
        return Response(status_code=404)
    if "," not in ids:
        return JSONResponse({"data": found[0]})
    return JSONResponse({"items": found})


@router.get("/v2/inthreat/collections/{collection}")
async def collection(collection: str) -> dict:
    return {"uuid": collection, "name": "OpenCTI IOC collection", "type": "ioc"}


@router.post("/v2/inthreat/collections/{collection}/indicators/text")
async def import_indicators(collection: str, request: Request) -> dict:  # noqa: ARG001
    body = await request.json()
    values = [line for line in body.get("indicators", "").split("\n") if line]
    return {
        "items": [
            {"id": f"indicator--{uuid.uuid4()}", "name": value, "revoked": False}
            for value in values
        ]
    }


@router.get("/v2/inthreat/collections/{collection}/indicators")
async def search_indicators(collection: str, term: str = "") -> dict:  # noqa: ARG001
    return {
        "items": [
            {
                "id": f"indicator--{uuid.uuid4()}",
                "name": term,
                "revoked": False,
            }
        ]
    }


@router.delete("/v2/inthreat/collections/{collection}/indicators/{indicator_id}")
async def delete_indicator(collection: str, indicator_id: str) -> dict:  # noqa: ARG001
    return {"id": indicator_id, "revoked": True}
