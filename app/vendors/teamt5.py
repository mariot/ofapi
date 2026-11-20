"""TeamT5 ThreatVision: OAuth token, paginated report and IOC bundle listings and the
STIX bundle of each, read by the OpenCTI teamt5 connector."""

import time
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["api.threatvision.org"]
router = APIRouter(prefix="/teamt5", tags=["TeamT5"])

BASE = "https://api.threatvision.org"
PAGE_SIZE = 3
COUNT = 5

# listing of each kind, renewed by every request at offset 0
_listings: dict[str, list[dict]] = {}


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
        **fields,
    }


def _link(kind: str, source: dict, target: dict) -> dict:
    return _sdo(
        "relationship",
        relationship_type=kind,
        source_ref=source["id"],
        target_ref=target["id"],
    )


def _indicator(kind: str, value: str, pattern: str) -> tuple[dict, dict | None]:
    indicator = _sdo(
        "indicator",
        name=value,
        pattern=pattern,
        pattern_type="stix",
        valid_from=_stamp(),
        indicator_types=["malicious-activity"],
    )
    observable = None
    if kind != "file":
        observable = {
            "type": kind,
            "spec_version": "2.1",
            "id": f"{kind}--{uuid.uuid4()}",
            "value": value,
        }
    return indicator, observable


def _ioc_bundle() -> dict:
    """Indicators of an address, a domain, a URL and a hash with their observables."""
    ip, domain, url, sha256 = (
        fake.ipv4_public(),
        fake.domain_name(),
        fake.url(),
        fake.sha256(),
    )
    pairs = [
        _indicator("ipv4-addr", ip, f"[ipv4-addr:value = '{ip}']"),
        _indicator("domain-name", domain, f"[domain-name:value = '{domain}']"),
        _indicator("url", url, f"[url:value = '{url}']"),
        _indicator("file", sha256, f"[file:hashes.'SHA-256' = '{sha256}']"),
    ]
    malware = _sdo("malware", name=fake.malware_family(), is_family=True)
    objects = [malware]
    for indicator, observable in pairs:
        objects.append(indicator)
        objects.append(_link("indicates", indicator, malware))
        if observable:
            objects.append(observable)
            objects.append(_link("based-on", indicator, observable))
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _report_bundle() -> dict:
    """The actor, malware, technique and vulnerability a report is about."""
    actor = _sdo("intrusion-set", name=fake.intrusion_set())
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
    ip = fake.ipv4_public()
    indicator, observable = _indicator("ipv4-addr", ip, f"[ipv4-addr:value = '{ip}']")
    objects = [
        actor,
        malware,
        technique,
        vulnerability,
        indicator,
        observable,
        _link("uses", actor, malware),
        _link("uses", actor, technique),
        _link("targets", actor, vulnerability),
        _link("indicates", indicator, malware),
    ]
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _page(kind: str, offset: int, make) -> list[dict]:
    if offset == 0 or kind not in _listings:
        _listings[kind] = [make() for _ in range(COUNT)]
    return _listings[kind][offset : offset + PAGE_SIZE]


@router.post("/oauth/token")
async def token() -> dict:
    """A bearer token for the client credentials grant."""
    return {
        "access_token": uuid.uuid4().hex,
        "token_type": "Bearer",
        "expires_in": 3600,
        "created_at": int(time.time()),
    }


@router.get("/api/v2/reports")
async def reports(request: Request) -> dict:
    """A page of report references (the last page is empty)."""
    offset = int(request.query_params.get("offset", 0))

    def make() -> dict:
        alias = f"{fake.slug()}-{uuid.uuid4().hex[:6]}"
        return {
            "alias": alias,
            "title": f"{fake.intrusion_set()} targets {fake.industry_sector()}",
            "digest": fake.paragraph(),
            "date": int(time.time()) - fake.random_int(3600, 86400 * 5),
            "type_name": fake.random_element(["Campaign", "Alert", "Analysis"]),
        }

    return {"success": True, "reports": _page("reports", offset, make)}


@router.get("/api/v2/ioc_bundles")
async def ioc_bundles(request: Request) -> dict:
    """A page of IOC bundle references (the last page is empty)."""
    offset = int(request.query_params.get("offset", 0))

    def make() -> dict:
        bundle_id = uuid.uuid4().hex
        return {
            "id": bundle_id,
            "created_at": int(time.time()) - fake.random_int(3600, 86400 * 5),
            "stix_url": f"{BASE}/api/v2/ioc_bundles/{bundle_id}.stix",
        }

    return {"success": True, "ioc_bundles": _page("ioc", offset, make)}


@router.get("/api/v2/reports/{alias}.stix")
async def report_stix(alias: str) -> dict:  # noqa: ARG001
    return _report_bundle()


@router.get("/api/v2/ioc_bundles/{bundle_id}.stix")
async def ioc_stix(bundle_id: str) -> dict:  # noqa: ARG001
    return _ioc_bundle()
