"""Vulners: the STIX bundle of a CVE (``GET /api/v4/stix/bundle``), read through the
Vulners SDK by the OpenCTI vulners enrichment connector (the SDK ignores proxy
variables: the connector is pointed at ofapi through its base URL setting)."""

import json

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["vulners.com"]
router = APIRouter(prefix="/vulners", tags=["Vulners"])


@router.get("/api/v4/stix/bundle")
async def stix_bundle(id: str, opencti_id: str | None = None) -> dict:  # noqa: A002
    """A bundle built server-side: the vulnerability (under the OpenCTI id when the
    caller gives it), a malware exploiting it and the relationship."""
    vulnerability = fake.stix_vulnerability()
    vulnerability["name"] = id
    vulnerability["description"] = fake.paragraph()
    vulnerability["external_references"] = [
        {
            "source_name": "vulners",
            "external_id": id,
            "url": f"https://vulners.com/cve/{id}",
        }
    ]
    if opencti_id:
        vulnerability["id"] = opencti_id
    malware = fake.stix_malware()
    bundle = fake.stix_bundle(
        objects=[
            vulnerability,
            malware,
            fake.stix_relationship(malware["id"], vulnerability["id"], "exploits"),
        ]
    )
    # the SDK hands `result` over as is and the connector decodes it: a JSON string
    return {"result": json.dumps(bundle)}
