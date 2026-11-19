"""CYFIRMA: the DeCYFIR STIX 2.1 feeds (indicators, vulnerabilities, threat actors),
read by the OpenCTI cyfirma connector."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["api.cyfirma.com"]
router = APIRouter(prefix="/cyfirma", tags=["Cyfirma"])

BASE = "/api/ex/v3/da/stix/2.1"
INDICATOR_EXTENSION = "extension-definition--4e9c7b2d-8a3f-4c1e-9d6b-5f2a8e7c1b40"
VULNERABILITY_EXTENSION = "extension-definition--1f9c5b3e-8a2d-4e7b-9c6a-d1f5e3b2a470"
ACTORS = ["APT-Phantom Crane", "Silent Lynx"]
MALWARE = {
    "type": "malware",
    "spec_version": "2.1",
    "id": "malware--5a2a1c3e-4e55-4d2b-8a4f-1d3b0a2e7c11",
    "created": "2025-01-10T00:00:00.000Z",
    "modified": "2025-01-10T00:00:00.000Z",
    "name": "ShadowPad Loader",
    "is_family": True,
    "malware_types": ["backdoor"],
}


def _stamp() -> str:
    moment = datetime.now(UTC) - timedelta(hours=fake.random_int(1, 48))
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _relationship(kind: str, source: str, target: str) -> dict:
    stamp = _stamp()
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{fake.uuid4()}",
        "created": stamp,
        "modified": stamp,
        "relationship_type": kind,
        "source_ref": source,
        "target_ref": target,
    }


@router.get(f"{BASE}/indicators/tailored")
@router.get(f"{BASE}/indicators/all")
async def indicators(page: int = 0) -> dict:
    """One page of indicators (with the malware they indicate), then empty pages."""
    if page > 0:
        return {"objects": []}
    objects = [MALWARE]
    for stix_type in ("ipv4-addr", "domain-name", "url", "file"):
        indicator = fake.stix_indicator(stix_type=stix_type)
        stamp = _stamp()
        indicator.update(created=stamp, modified=stamp, valid_from=stamp)
        indicator["extensions"] = {
            INDICATOR_EXTENSION: {
                "extension_type": "property-extension",
                "threat_actors": ", ".join(ACTORS),
            }
        }
        objects += [
            indicator,
            _relationship("indicates", indicator["id"], MALWARE["id"]),
        ]
    return {"objects": objects}


@router.get(f"{BASE}/threat-actors/search")
async def threat_actors(values: Annotated[list[str] | None, Query()] = None) -> dict:
    """The threat actors asked by name, with what they use."""
    objects = []
    for name in values or []:
        stamp = _stamp()
        actor = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{fake.uuid4()}",
            "created": stamp,
            "modified": stamp,
            "name": name,
            "threat_actor_types": ["crime-syndicate"],
            "aliases": [fake.intrusion_set()],
        }
        objects += [actor, _relationship("uses", actor["id"], MALWARE["id"])]
    return {"objects": objects}


@router.get(f"{BASE}/vulnerabilities/tailored")
@router.get(f"{BASE}/vulnerabilities/all")
async def vulnerabilities(page: int = 0) -> dict:
    """One page of CVEs with CYFIRMA's own CVSS extension, then empty pages."""
    if page > 0:
        return {"objects": []}
    objects = []
    for version in ("3.1", "3.1", "2.0"):
        # CVSS v2 impacts are NONE, PARTIAL or COMPLETE
        impact = "HIGH" if version == "3.1" else "PARTIAL"
        cve = fake.cve_id()
        stamp = _stamp()
        objects.append(
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{fake.uuid4()}",
                "created": stamp,
                "modified": stamp,
                "name": cve,
                "description": f"{cve}: remote code execution in a popular product.",
                "external_references": [
                    {
                        "source_name": "cve",
                        "external_id": cve,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    }
                ],
                "extensions": {
                    VULNERABILITY_EXTENSION: {
                        "extension_type": "property-extension",
                        "cvss_version": version,
                        "cvss_base_score": "9.8" if version == "3.1" else "7.5",
                        "severity": "CRITICAL" if version == "3.1" else "HIGH",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        if version == "3.1"
                        else "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        "attack_vector": "NETWORK",
                        "attack_complexity": "LOW",
                        "privileges_required": "NONE",
                        "user_interaction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentiality_impact": impact,
                        "integrity_impact": impact,
                        "availability_impact": impact,
                    }
                },
            }
        )
    return {"objects": objects}
