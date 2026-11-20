"""ThreatMatch: OAuth2 token, profile and alert STIX objects and the TAXII indicator
feed, read by the OpenCTI threatmatch connector."""

import time
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["eu.threatmatch.com"]
router = APIRouter(prefix="/threatmatch", tags=["ThreatMatch"])

GROUP_ID = "5f1c6a3e-9b0d-4a43-8f55-2f6a4e0d7c11"
PROFILE_IDS = [1201, 1202]
ALERT_IDS = [3301, 3302]


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sdo(kind: str, **fields) -> dict:
    now = _now()
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        **fields,
    }


def _rel(source: dict, relationship: str, target: dict) -> dict:
    return _sdo(
        "relationship",
        relationship_type=relationship,
        source_ref=source["id"],
        target_ref=target["id"],
    )


def _indicator() -> dict:
    kind = fake.random_element(["ipv4-addr", "domain-name", "file"])
    if kind == "ipv4-addr":
        value = fake.ipv4_public()
        pattern = f"[ipv4-addr:value = '{value}']"
    elif kind == "domain-name":
        value = fake.domain_name()
        pattern = f"[domain-name:value = '{value}']"
    else:
        value = fake.sha256()
        pattern = f"[file:hashes.'SHA-256' = '{value}']"
    return _sdo(
        "indicator",
        name=value,
        pattern=pattern,
        pattern_type="stix",
        valid_from=_now(),
        indicator_types=["malicious-activity"],
        labels=["threatmatch"],
    )


def _bundle_objects(report_name: str) -> list[dict]:
    """A report about an actor using a malware and a technique, with indicators."""
    actor = _sdo(
        "threat-actor",
        name=fake.intrusion_set(),
        description=f"<p>{fake.sentence()}</p><b>{fake.sentence()}</b>",
        threat_actor_types=["nation-state"],
    )
    malware = _sdo(
        "malware",
        name=fake.malware_family(),
        is_family=True,
        malware_types=["backdoor"],
    )
    mitre = fake.mitre_attack_technique()
    technique = _sdo(
        "attack-pattern",
        name=mitre["name"],
        external_references=[
            {"source_name": "mitre-attack", "external_id": mitre["external_id"]}
        ],
    )
    indicator = _indicator()
    objects = [actor, malware, technique, indicator]
    relationships = [
        _rel(actor, "uses", malware),
        _rel(actor, "uses", technique),
        _rel(indicator, "indicates", malware),
        _rel(technique, "associated_content", malware),
    ]
    report = _sdo(
        "report",
        name=report_name,
        description=f"<p>{fake.paragraph()}</p>",
        published=_now(),
        report_types=["threat-report"],
        object_refs=[o["id"] for o in objects],
        labels=["threatmatch"],
    )
    return [*objects, report, *relationships]


@router.post("/api/developers-platform/token")
async def token() -> dict:
    """An OAuth2 client-credentials token with its expiry as a Unix timestamp."""
    return {
        "access_token": uuid.uuid4().hex,
        "token_type": "Bearer",
        "expires_at": int(time.time()) + 3600,
    }


@router.get("/api/profiles/all")
async def profiles_all() -> dict:
    return {"list": PROFILE_IDS}


@router.get("/api/alerts/all")
async def alerts_all() -> dict:
    return {"list": ALERT_IDS}


@router.get("/api/stix/profiles/{profile_id}")
async def stix_profile(profile_id: int) -> dict:
    return {"objects": _bundle_objects(f"Profile {profile_id}: {fake.catch_phrase()}")}


@router.get("/api/stix/alerts/{alert_id}")
async def stix_alert(alert_id: int) -> dict:
    return {"objects": _bundle_objects(f"Alert {alert_id}: {fake.catch_phrase()}")}


@router.get("/api/taxii/groups")
async def taxii_groups() -> list[dict]:
    return [
        {"id": "b3a0f6a4-0f2c-4f4b-8d3a-6a7a3c1d9e02", "name": "Vulnerabilities"},
        {"id": GROUP_ID, "name": "All content"},
    ]


@router.get("/api/taxii/objects")
async def taxii_objects(stix_type_name: str = Query(alias="stixTypeName")) -> dict:
    """Indicators of the group, in a single page (``more`` is false)."""
    objects = [_indicator() for _ in range(6)] if stix_type_name == "indicator" else []
    return {"objects": objects, "more": False}
