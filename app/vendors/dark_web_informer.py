"""Dark Web Informer: the prebuilt STIX 2.1 bundles (feed, ransomware, iocs), read by
the OpenCTI dark-web-informer connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Header, HTTPException

from app.fake import fake

HOSTS = ["api.darkwebinformer.com"]
router = APIRouter(prefix="/dark-web-informer", tags=["Dark Web Informer"])

AUTHOR = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--7d1d5b8e-6f0b-5c58-9d0e-2a5f3b1c4e90",
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Dark Web Informer",
    "identity_class": "organization",
}


def _stamp(hours: int | None = None) -> str:
    moment = datetime.now(UTC) - timedelta(hours=hours or fake.random_int(1, 40))
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _sdo(kind: str, **fields) -> dict:
    stamp = _stamp()
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{fake.uuid4()}",
        "created": stamp,
        "modified": stamp,
        "created_by_ref": AUTHOR["id"],
        **fields,
    }


def _link(kind: str, source: dict, target: dict) -> dict:
    return _sdo(
        "relationship",
        relationship_type=kind,
        source_ref=source["id"],
        target_ref=target["id"],
    )


def _bundle(objects: list[dict]) -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{fake.uuid4()}",
        "objects": [AUTHOR, *objects],
    }


def _check(x_api_key: str | None, x_nonce: str | None) -> None:
    if not x_api_key or not x_nonce or ":" not in x_nonce:
        raise HTTPException(401, "missing X-API-Key or X-Nonce")


def _feed() -> dict:
    """Ransomware leak-site posts: a report on a victim organization and its actor."""
    actor, victim = _sdo("intrusion-set", name=fake.intrusion_set()), None
    victim = _sdo("identity", name=fake.company(), identity_class="organization")
    country = fake.stix_location()
    report = _sdo(
        "report",
        name=f"{actor['name']} claims {victim['name']}",
        description="A new leak-site post.",
        published=_stamp(),
        report_types=["threat-report"],
        object_refs=[actor["id"], victim["id"]],
        external_references=[
            {
                "source_name": "dwi-screenshot",
                "url": "https://darkwebinformer.com/s.png",
            },
            {
                "source_name": "Dark Web Informer",
                "url": "https://darkwebinformer.com/p/1",
            },
        ],
    )
    return _bundle(
        [
            actor,
            victim,
            country,
            report,
            _link("targets", actor, victim),
            _link("located-at", victim, country),
        ]
    )


def _ransomware() -> dict:
    """Ransomware groups, their malware and the sectors they hit."""
    actor = _sdo("intrusion-set", name=fake.intrusion_set(), aliases=[fake.word()])
    malware = _sdo("malware", name=fake.malware_family(), is_family=True)
    sector = _sdo("identity", name=fake.industry_sector(), identity_class="class")
    return _bundle(
        [
            actor,
            malware,
            sector,
            _link("uses", actor, malware),
            _link("targets", actor, sector),
        ]
    )


def _iocs() -> dict:
    """Indicators with their observables, tied to a malware."""
    malware = _sdo("malware", name=fake.malware_family(), is_family=True)
    objects = [malware]
    for kind in ("ipv4-addr", "domain-name", "url", "file"):
        observable = fake.stix_observable(stix_type=kind)
        indicator = fake.stix_indicator(stix_type=kind)
        stamp = _stamp()
        indicator.update(created=stamp, modified=stamp, valid_from=stamp)
        indicator["created_by_ref"] = AUTHOR["id"]
        indicator["id"] = f"indicator--{fake.uuid4()}"
        objects += [
            observable,
            indicator,
            _link("based-on", indicator, observable),
            _link("indicates", indicator, malware),
        ]
    return _bundle(objects)


@router.get("/api/stix/export_feed.json")
async def export_feed(
    x_api_key: str | None = Header(None), x_nonce: str | None = Header(None)
) -> dict:
    _check(x_api_key, x_nonce)
    return _feed()


@router.get("/api/stix/export_ransomware.json")
async def export_ransomware(
    x_api_key: str | None = Header(None), x_nonce: str | None = Header(None)
) -> dict:
    _check(x_api_key, x_nonce)
    return _ransomware()


@router.get("/api/stix/export_iocs.json")
async def export_iocs(
    x_api_key: str | None = Header(None), x_nonce: str | None = Header(None)
) -> dict:
    _check(x_api_key, x_nonce)
    return _iocs()


@router.get("/api/stix/export.json")
async def export_all(
    x_api_key: str | None = Header(None), x_nonce: str | None = Header(None)
) -> dict:
    _check(x_api_key, x_nonce)
    objects = [o for b in (_feed(), _ransomware(), _iocs()) for o in b["objects"][1:]]
    return _bundle(objects)
