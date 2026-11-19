"""CTM360 ThreatCover: a TAXII 2.1 server with one "Observables" collection, read by
the OpenCTI ctm360-threatcover connector through taxii2-client (discovery, API root,
collections, objects)."""

import json
from uuid import uuid4

from fastapi import APIRouter, Response

from app.fake import fake

HOST = "threatcover.ctm360.com"
HOSTS = [HOST]
router = APIRouter(prefix="/ctm360-threatcover", tags=["CTM360 ThreatCover"])

TAXII_TYPE = "application/taxii+json;version=2.1"
COLLECTION_ID = "6c1c0a64-3a3b-4f0e-9d58-8d2a5b3f7e11"


def _taxii(content: dict) -> Response:
    return Response(json.dumps(content), media_type=TAXII_TYPE)


def _observables() -> list[dict]:
    """Indicators and the observables they are based on, as the feed publishes them."""
    now = fake.date_time_this_month().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    observables = [
        ("ipv4-addr", {"value": fake.ipv4_public()}, "ipv4-addr:value"),
        ("domain-name", {"value": fake.domain_name()}, "domain-name:value"),
        ("url", {"value": fake.url()}, "url:value"),
        ("file", {"hashes": {"SHA-256": fake.sha256()}}, "file:hashes.'SHA-256'"),
    ]
    objects = []
    for kind, properties, path in observables:
        observable = {"type": kind, "spec_version": "2.1", "id": f"{kind}--{uuid4()}"}
        observable.update(properties)
        value = properties.get("value") or properties["hashes"]["SHA-256"]
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid4()}",
            "created": now,
            "modified": now,
            "name": value,
            "pattern": f"[{path} = '{value}']",
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
            "confidence": 80,
        }
        relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "based-on",
            "source_ref": indicator["id"],
            "target_ref": observable["id"],
        }
        objects += [observable, indicator, relationship]
    return objects


@router.get("/taxii2/")
async def discovery() -> Response:
    return _taxii(
        {
            "title": "CTM360 ThreatCover",
            "description": "ThreatCover TAXII 2.1 server",
            "default": f"https://{HOST}/api1/",
            "api_roots": [f"https://{HOST}/api1/"],
        }
    )


@router.get("/api1/")
async def api_root() -> Response:
    return _taxii(
        {
            "title": "ThreatCover",
            "description": "ThreatCover API root",
            "versions": [TAXII_TYPE],
            "max_content_length": 104857600,
        }
    )


def _collection() -> dict:
    return {
        "id": COLLECTION_ID,
        "title": "Observables",
        "description": "ThreatCover observables and indicators",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    }


@router.get("/api1/collections/")
async def collections() -> Response:
    return _taxii({"collections": [_collection()]})


@router.get("/api1/collections/{collection_id}/")
async def collection(collection_id: str) -> Response:  # noqa: ARG001
    return _taxii(_collection())


@router.get("/api1/collections/{collection_id}/objects/")
async def objects(collection_id: str) -> Response:  # noqa: ARG001
    """The whole envelope in one page (``more`` is false)."""
    return _taxii({"more": False, "objects": _observables()})
