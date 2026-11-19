"""Maltiverse: the TAXII 2.1 server (basic auth) with its feed collections, read by the
OpenCTI maltiverse connector (``taxii2-client``)."""

import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["api.maltiverse.com"]
router = APIRouter(prefix="/maltiverse", tags=["Maltiverse"])

TAXII = "application/taxii+json;version=2.1"
STIX = "application/stix+json;version=2.1"
ROOT = "https://api.maltiverse.com/taxii2/maltiverse/"
# the feed the connector's docker-compose.yml selects, and another one it must skip
COLLECTIONS = {
    "VdhZV34B4jHUXfKt_gDi": "Malicious IPv4 addresses",
    "AbCdEfGh1234567890_x": "Phishing URLs",
}


def taxii(body: dict) -> Response:
    return Response(json.dumps(body), media_type=TAXII)


@router.get("/taxii2/")
async def discovery() -> Response:
    return taxii(
        {
            "title": "Maltiverse TAXII 2.1 server",
            "description": "Maltiverse threat intelligence feeds",
            "default": ROOT,
            "api_roots": [ROOT],
        }
    )


@router.get("/taxii2/maltiverse/")
async def api_root() -> Response:
    return taxii(
        {
            "title": "Maltiverse",
            "description": "Maltiverse feeds",
            "versions": [TAXII],
            "max_content_length": 104857600,
        }
    )


@router.get("/taxii2/maltiverse/collections/")
async def collections() -> Response:
    return taxii(
        {
            "collections": [
                {
                    "id": collection_id,
                    "title": title,
                    "can_read": True,
                    "can_write": False,
                    "media_types": [STIX],
                }
                for collection_id, title in COLLECTIONS.items()
            ]
        }
    )


@router.get("/taxii2/maltiverse/collections/{collection_id}/objects/")
async def objects(collection_id: str) -> Response:
    """An envelope of indicators for malicious addresses, domains, URLs and hashes."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    patterns = [
        f"[ipv4-addr:value = '{fake.ipv4_public()}']",
        f"[ipv4-addr:value = '{fake.ipv4_public()}']",
        f"[domain-name:value = '{fake.domain_name()}']",
        f"[url:value = '{fake.url()}']",
        f"[file:hashes.'SHA-256' = '{fake.sha256()}']",
    ]
    items = [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": pattern.split("'")[1],
            "description": f"Seen in {COLLECTIONS.get(collection_id, 'a feed')}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
        }
        for pattern in patterns
    ]
    return taxii({"more": False, "objects": items})
