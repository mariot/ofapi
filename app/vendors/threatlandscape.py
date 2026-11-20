"""Threat Landscape: the PostgREST feeds of STIX bundles (intelligence) and of
actionable IOCs, cursor-paginated by ``seq_id``, read by the OpenCTI threatlandscape
connector."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["api.threatlandscape.io"]
router = APIRouter(prefix="/threatlandscape", tags=["Threat Landscape"])

NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
AUTHOR = f"identity--{uuid.uuid5(NAMESPACE, 'threatlandscape.io')}"
TLP_GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
FIRST_SEQ_ID = 1000
BUNDLES = 7

# rows of the intelligence and IOC feeds, renewed by every request without a cursor
_rows: dict[str, list[dict]] = {}


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sdo(kind: str, **fields) -> dict:
    stamp = _stamp()
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid4()}",
        "created": stamp,
        "modified": stamp,
        "created_by_ref": AUTHOR,
        "object_marking_refs": [TLP_GREEN],
        **fields,
    }


def _link(kind: str, source: dict, target: dict) -> dict:
    return _sdo(
        "relationship",
        relationship_type=kind,
        source_ref=source["id"],
        target_ref=target["id"],
    )


def _preamble() -> list[dict]:
    """The author and the TLP marking every bundle carries."""
    stamp = _stamp()
    return [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": AUTHOR,
            "created": stamp,
            "modified": stamp,
            "name": "threatlandscape.io",
            "identity_class": "organization",
        },
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": TLP_GREEN,
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": "TLP:GREEN",
            "definition": {"tlp": "green"},
        },
    ]


def _indicator() -> tuple[dict, dict]:
    ip = fake.ipv4_public()
    indicator = _sdo(
        "indicator",
        name=ip,
        pattern=f"[ipv4-addr:value = '{ip}']",
        pattern_type="stix",
        valid_from=_stamp(),
        indicator_types=["malicious-activity"],
        x_opencti_main_observable_type="IPv4-Addr",
    )
    observable = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": f"ipv4-addr--{uuid.uuid5(NAMESPACE, ip)}",
        "value": ip,
        "object_marking_refs": [TLP_GREEN],
    }
    return indicator, observable


def _intelligence() -> dict:
    """A report on an actor, its campaign, malware, technique, vulnerability and victim
    country, with an indicator."""
    actor = _sdo(
        "threat-actor",
        name=fake.intrusion_set(),
        threat_actor_types=["crime-syndicate"],
    )
    group = _sdo("intrusion-set", name=fake.intrusion_set())
    campaign = _sdo("campaign", name=f"{fake.malware_family()} campaign")
    malware = _sdo("malware", name=fake.malware_family(), is_family=True)
    attack = fake.mitre_attack_technique()
    technique = _sdo(
        "attack-pattern",
        name=attack["name"],
        external_references=[
            {"source_name": "mitre-attack", "external_id": attack["external_id"]}
        ],
    )
    cve = fake.cve_id()
    vulnerability = _sdo(
        "vulnerability",
        name=cve,
        external_references=[{"source_name": "cve", "external_id": cve}],
    )
    country = _sdo("location", name="France", country="FR", region="europe")
    victim = _sdo("identity", name=fake.company(), identity_class="organization")
    indicator, observable = _indicator()
    objects = [
        actor,
        group,
        campaign,
        malware,
        technique,
        vulnerability,
        country,
        victim,
        indicator,
        observable,
        _link("attributed-to", campaign, actor),
        _link("uses", actor, malware),
        _link("uses", group, technique),
        _link("targets", campaign, country),
        _link("targets", campaign, victim),
        _link("exploits", malware, vulnerability),
        _link("indicates", indicator, malware),
    ]
    report = _sdo(
        "report",
        name=f"{actor['name']} activity",
        published=_stamp(),
        report_types=["threat-report"],
        object_refs=[o["id"] for o in objects[:10]],
    )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [*_preamble(), *objects, report],
    }


def _ioc_bundle() -> dict:
    """Indicators on addresses with their observable and malware."""
    malware = _sdo("malware", name=fake.malware_family(), is_family=True)
    objects = [malware]
    for _ in range(2):
        indicator, observable = _indicator()
        objects += [indicator, observable, _link("indicates", indicator, malware)]
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [*_preamble(), *objects],
    }


def _page(feed: str, request: Request, make) -> list[dict]:
    query = request.query_params
    after = query.get("seq_id")
    if after is None or feed not in _rows:
        _rows[feed] = [
            {"seq_id": FIRST_SEQ_ID + n, "stix_bundle": make()} for n in range(BUNDLES)
        ]
    floor = int(after.removeprefix("gt.")) if after else 0
    rows = [r for r in _rows[feed] if r["seq_id"] > floor]
    return rows[: int(query.get("limit", 100))]


@router.get("/rest/v1/stix_bundles")
async def stix_bundles(request: Request) -> list[dict]:
    """The next bundles after the cursor (``seq_id=gt.N``) or the start date."""
    return _page("intelligence", request, _intelligence)


@router.get("/rest/v1/actionable_iocs")
async def actionable_iocs(request: Request) -> list[dict]:
    return _page("iocs", request, _ioc_bundle)
