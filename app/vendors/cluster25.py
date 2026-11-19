"""Cluster25 intelligence platform: token and STIX 2.1 indicators export, read by the
OpenCTI cluster25 connector."""

import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request

from app.fake import fake

HOSTS = ["api.intelligence.cluster25.io"]
router = APIRouter(prefix="/cluster25", tags=["Cluster25"])

# the connector's indicator types -> (observable type, STIX pattern of a fresh value)
PATTERNS = {
    "ipv4": ("IPv4-Addr", lambda: f"[ipv4-addr:value = '{fake.ipv4_public()}']"),
    "ipv6": ("IPv6-Addr", lambda: f"[ipv6-addr:value = '{fake.ipv6()}']"),
    "domain": ("Domain-Name", lambda: f"[domain-name:value = '{fake.domain_name()}']"),
    "url": ("Url", lambda: f"[url:value = '{fake.url()}']"),
    "email": ("Email-Addr", lambda: f"[email-addr:value = '{fake.email()}']"),
    "md5": ("StixFile", lambda: f"[file:hashes.MD5 = '{fake.md5()}']"),
    "sha1": ("StixFile", lambda: f"[file:hashes.'SHA-1' = '{fake.sha1()}']"),
    "sha256": ("StixFile", lambda: f"[file:hashes.'SHA-256' = '{fake.sha256()}']"),
    "filename": ("StixFile", lambda: f"[file:name = '{fake.file_name()}']"),
}


OPENCTI_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _indicator_id(pattern: str) -> str:
    """The id OpenCTI gives an indicator (the one relationships point to)."""
    key = json.dumps({"pattern": pattern.strip()}, separators=(",", ":"))
    return f"indicator--{uuid.uuid5(OPENCTI_NAMESPACE, key)}"


@router.post("/api/v1/token")
async def token(request: Request) -> dict:
    body = await request.json()
    if not body.get("client_id") or not body.get("client_secret"):
        raise HTTPException(401, "invalid credentials")
    return {"data": {"token": fake.pystr(64, 64)}}


@router.get("/api/v1/export/indicators")
async def export_indicators(request: Request) -> dict:
    """A STIX 2.1 bundle: an indicator per requested type (repeated ``types``), with the
    malware it relates to (``include_info``)."""
    types = request.query_params.getlist("types")
    recent = (datetime.now(UTC) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    malware = fake.stix_malware(created=recent, modified=recent)
    objects = [malware]
    for kind in types or list(PATTERNS):
        if kind not in PATTERNS:
            continue
        main_type, pattern = PATTERNS[kind]
        indicator = fake.stix_indicator(
            pattern=pattern(),
            x_opencti_main_observable_type=main_type,
            object_marking_refs=[],
        )
        indicator["name"] = indicator["pattern"]
        indicator["id"] = _indicator_id(indicator["pattern"])
        indicator["created"] = indicator["modified"] = indicator["valid_from"] = recent
        objects.append(indicator)
        objects.append(
            fake.stix_relationship(indicator["id"], malware["id"], "indicates")
        )
    return fake.stix_bundle(objects=objects)
