"""DISINFOX: the STIX export of a self-hosted installation, read by the OpenCTI disinfox
connector (its DISINFOX_URL setting is the export endpoint itself)."""

from datetime import UTC, datetime

from fastapi import APIRouter, Header, HTTPException

from app.fake import fake

HOSTS = ["disinfox.staticfire.test"]
router = APIRouter(prefix="/disinfox", tags=["DISINFOX"])


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


@router.get("/api/stix")
async def stix_export(authorization: str = Header(default="")) -> dict:
    """The disinformation threat actors, campaigns and techniques as STIX objects."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing API key")
    actors = [fake.stix_intrusion_set() for _ in range(3)]
    campaigns = []
    for actor in actors:
        name = f"{actor['name']} narrative campaign"
        campaigns.append(
            {
                "type": "campaign",
                "spec_version": "2.1",
                "id": fake.stix_id("campaign", name=name.lower()),
                "created": _now(),
                "modified": _now(),
                "name": name,
                "description": fake.paragraph(),
                "first_seen": _now(),
            }
        )
    techniques = [fake.stix_attack_pattern() for _ in range(3)]
    tools = [fake.stix_tool() for _ in range(2)]
    locations = [fake.stix_location() for _ in range(2)]
    relationships = []
    for index, actor in enumerate(actors):
        relationships.append(
            fake.stix_relationship(actor["id"], campaigns[index]["id"], "attributed-to")
        )
        relationships.append(
            fake.stix_relationship(actor["id"], techniques[index]["id"], "uses")
        )
        relationships.append(
            fake.stix_relationship(actor["id"], tools[index % 2]["id"], "uses")
        )
        relationships.append(
            fake.stix_relationship(
                actor["id"], locations[index % 2]["id"], "originates-from"
            )
        )
    objects = [*actors, *campaigns, *techniques, *tools, *locations, *relationships]
    return {"type": "bundle", "id": fake.stix_id("bundle"), "objects": objects}
