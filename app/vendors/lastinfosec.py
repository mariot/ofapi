"""LastInfoSec: the STIX 2.1 CTI, CVE and tactic feeds and the observable search, read
by the OpenCTI lastinfosec-feed (import) and lastinfosec-enrichment connectors."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter
from pydantic import BaseModel

from app.fake import fake

HOSTS = ["api.client.lastinfosec.com"]
router = APIRouter(prefix="/lastinfosec", tags=["LastInfoSec"])

TLP_WHITE = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"


def _now(minutes_ago: int = 0) -> str:
    moment = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sdo(kind: str, **properties) -> dict:
    created = _now(fake.random_int(1, 25))
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        **properties,
    }


def _bundle(objects: list[dict]) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _author() -> dict:
    return _sdo("identity", name="LastInfoSec", identity_class="organization")


def _relationship(source: dict, target: dict, kind: str, author: dict) -> dict:
    return _sdo(
        "relationship",
        relationship_type=kind,
        source_ref=source["id"],
        target_ref=target["id"],
        created_by_ref=author["id"],
    )


def _indicator(author: dict, path: str, value: str, minutes: int = 25) -> dict:
    return _sdo(
        "indicator",
        name=value,
        pattern=f"[{path} = '{value}']",
        pattern_type="stix",
        valid_from=_now(fake.random_int(1, max(minutes, 1))),
        indicator_types=["malicious-activity"],
        labels=["botnet"],
        confidence=fake.random_int(40, 90),
        created_by_ref=author["id"],
        object_marking_refs=[TLP_WHITE],
        x_opencti_score=fake.random_int(40, 90),
    )


def _cti_bundle(minutes: int) -> dict:
    author = _author()
    malware = _sdo(
        "malware",
        name=fake.malware_family(),
        is_family=True,
        malware_types=["trojan"],
        created_by_ref=author["id"],
        object_marking_refs=[TLP_WHITE],
    )
    sha256 = fake.sha256()
    indicators = [
        _indicator(author, "domain-name:value", fake.domain_name(), minutes),
        _indicator(author, "ipv4-addr:value", fake.ipv4_public(), minutes),
        _indicator(author, "url:value", fake.url(), minutes),
        _indicator(author, "file:hashes.'SHA-256'", sha256, minutes),
    ]
    relationships = [_relationship(i, malware, "indicates", author) for i in indicators]
    return _bundle([author, malware, *indicators, *relationships])


def _cve_bundle() -> dict:
    author = _author()
    vulnerabilities = [
        _sdo(
            "vulnerability",
            name=cve,
            description=fake.paragraph(),
            created_by_ref=author["id"],
            object_marking_refs=[TLP_WHITE],
            external_references=[{"source_name": "cve", "external_id": cve}],
            x_opencti_cvss_base_score=fake.pyfloat(
                min_value=4, max_value=10, right_digits=1
            ),
        )
        for cve in (fake.cve_id() for _ in range(4))
    ]
    return _bundle([author, *vulnerabilities])


def _tactic_bundle() -> dict:
    author = _author()
    group = _sdo(
        "intrusion-set",
        name=fake.intrusion_set(),
        created_by_ref=author["id"],
        object_marking_refs=[TLP_WHITE],
    )
    techniques = [fake.mitre_attack_technique() for _ in range(3)]
    patterns = [
        _sdo(
            "attack-pattern",
            name=technique["name"],
            created_by_ref=author["id"],
            object_marking_refs=[TLP_WHITE],
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": technique["external_id"],
                    "url": technique["url"],
                }
            ],
            kill_chain_phases=[
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": technique["phase_name"],
                }
            ],
        )
        for technique in techniques
    ]
    uses = [_relationship(group, pattern, "uses", author) for pattern in patterns]
    return _bundle([author, group, *patterns, *uses])


@router.get("/v2/stix21/getbyminutes/{minutes}")
async def cti_feed(minutes: int) -> list[dict]:
    """The IOCs of the last ``minutes`` minutes, one STIX bundle per list item."""
    return [_cti_bundle(minutes)]


@router.get("/v2/stix21/vulnerabilities/getlasthour")
async def cve_feed() -> list[dict]:
    return [_cve_bundle()]


@router.get("/v2/stix21/tactic/getlast24hour")
async def tactic_feed() -> list[dict]:
    return [_tactic_bundle()]


class Search(BaseModel):
    value: str


@router.post("/v2/stix21/search/")
async def search(body: Search) -> dict:
    """What is known of an observable: its indicator, the malware it indicates."""
    author = _author()
    malware = _sdo(
        "malware",
        name=fake.malware_family(),
        is_family=True,
        malware_types=["trojan"],
        created_by_ref=author["id"],
        object_marking_refs=[TLP_WHITE],
    )
    indicator = _indicator(author, "domain-name:value", body.value)
    relationship = _relationship(indicator, malware, "indicates", author)
    return {"message": [_bundle([author, malware, indicator, relationship])]}
