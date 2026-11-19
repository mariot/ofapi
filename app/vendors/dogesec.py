"""dogesec APIs (CTI Butler, CyberThreatExchange, Obstracts, SIEM Rules, Stixify and
Vulmatch), read by the OpenCTI dogesec-* connectors.

They share one shape: Django REST framework lists (``page``, ``page_size``,
``total_results_count`` and the list under a key) of STIX objects, authenticated by an
``API-KEY`` header. Their paths do not overlap, so one prefix serves all six hosts.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException

from app.fake import fake

HOSTS = [
    "api.ctibutler.com",
    "api.cyberthreatexchange.com",
    "api.obstracts.com",
    "api.siemrules.com",
    "api.stixify.com",
    "api.vulmatch.com",
]


def require_api_key(api_key: str = Header(default="", alias="API-KEY")) -> None:
    if not api_key:
        raise HTTPException(
            status_code=401, detail="Authentication credentials missing"
        )


router = APIRouter(
    prefix="/dogesec", tags=["dogesec"], dependencies=[Depends(require_api_key)]
)

# Ids the connectors are configured with (feeds, dossiers, detection packs)
FEED_ID = "6c3bd0e4-7d5c-5a2e-8f0e-2c1d4f5a9b10"
OBSTRACTS_FEED_ID = "a1f6d7c2-0b3e-5d4a-9e7c-3b8a2f1c6d05"
DOSSIER_ID = "3d9e2b7a-5c41-5f8e-b6a0-1e7d4c9f2a38"
DETECTION_PACK_ID = "f2a8c6e1-9b74-5d3c-a1e5-7c0b4d8e3f26"
VULMATCH_AUTHOR_ID = "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"
VULMATCH_MARKING_ID = "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d"


class Paging:
    """The ``page`` and ``page_size`` query parameters of every list."""

    def __init__(self, page: int = 1, page_size: int = 50) -> None:
        self.page = page
        self.page_size = page_size


PagingDep = Annotated[Paging, Depends()]


def _ts(hours_ago: float = 0) -> str:
    moment = datetime.now(UTC) - timedelta(hours=hours_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "/".join(parts)))


def _page(key: str, items: list, paging: Paging) -> dict:
    start = (paging.page - 1) * paging.page_size
    chunk = items[start : start + paging.page_size]
    return {
        "page_size": paging.page_size,
        "page_number": paging.page,
        "page_results_count": len(chunk),
        "total_results_count": len(items),
        key: chunk,
    }


def _author(name: str) -> tuple[dict, dict]:
    """The identity of a dogesec product and the marking its objects carry."""
    identity = fake.stix_identity(name=name, created=_ts(240), modified=_ts(240))
    marking = fake.stix_marking_definition("TLP:CLEAR")
    return identity, marking


def _common(identity: dict, marking: dict) -> dict[str, Any]:
    return {
        "created_by_ref": identity["id"],
        "object_marking_refs": [marking["id"]],
        "created": _ts(48),
        "modified": _ts(2),
    }


def _intel(identity: dict, marking: dict) -> list[dict]:
    """Extracted intelligence: an object of each kind and relationships between them."""
    common = _common(identity, marking)
    malware = fake.stix_malware(**common)
    actor = fake.stix_intrusion_set(**common)
    technique = fake.stix_attack_pattern(**common)
    vulnerability = fake.stix_vulnerability(**common)
    indicators = [
        fake.stix_indicator("ipv4-addr", fake.ipv4_public(), **common),
        fake.stix_indicator("domain-name", fake.domain_name(), **common),
        fake.stix_indicator("url", fake.url(), **common),
    ]
    relationships = [
        fake.stix_relationship(i["id"], malware["id"], "indicates", **common)
        for i in indicators
    ]
    relationships += [
        fake.stix_relationship(actor["id"], malware["id"], "uses", **common),
        fake.stix_relationship(malware["id"], technique["id"], "uses", **common),
        fake.stix_relationship(malware["id"], vulnerability["id"], "targets", **common),
    ]
    return [malware, actor, technique, vulnerability, *indicators, *relationships]


def _report_bundle(identity: dict, marking: dict, report_id: str | None = None) -> list:
    """A report on extracted intelligence, with every object it refers to."""
    objects = _intel(identity, marking)
    report = fake.stix_report(
        [o["id"] for o in objects], published=_ts(24), **_common(identity, marking)
    )
    if report_id:
        report["id"] = f"report--{report_id}"
    return [identity, marking, report, *objects]


# -- CTI Butler: https://api.ctibutler.com --

CAPEC = [
    ("CAPEC-1", "Accessing Functionality Not Properly Constrained by ACLs"),
    ("CAPEC-13", "Subverting Environment Variable Values"),
    ("CAPEC-112", "Brute Force"),
]
TECHNIQUES = ["T1059", "T1566", "T1190"]
COUNTRIES = ["FR", "DE", "JP"]
KNOWLEDGE_BASES = [
    "cwe",
    "capec",
    "location",
    "attack-mobile",
    "attack-ics",
    "attack-enterprise",
    "disarm",
    "atlas",
]


def _kb_objects(kb: str) -> list[dict]:
    """The objects of a knowledge base, with ids that do not change between calls."""
    common = {"created": _ts(2000), "modified": _ts(1000)}
    if kb == "location":
        return [fake.stix_location(code, **common) for code in COUNTRIES]
    if kb == "capec":
        return [
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{_uuid('capec', external_id)}",
                "name": name,
                "description": fake.paragraph(),
                "external_references": [
                    {
                        "source_name": "capec",
                        "external_id": external_id,
                        "url": "https://capec.mitre.org/data/definitions/"
                        f"{external_id.split('-')[1]}.html",
                    }
                ],
                **common,
            }
            for external_id, name in CAPEC
        ]
    return [fake.stix_attack_pattern(tid, **common) for tid in TECHNIQUES]


def _knowledge_base(kb: str) -> None:
    if kb not in KNOWLEDGE_BASES:
        raise HTTPException(status_code=404, detail="Not found.")


# Fixed so that the bundle of a CVE can be rebuilt from its name
CVE_NAMES = ["CVE-2026-20301", "CVE-2026-20302", "CVE-2026-20303"]


@router.get("/v1/cve/objects/")
async def cve_objects(paging: PagingDep) -> dict:
    """Three CVEs modified in the last hours (the filters are not applied)."""
    cves = [
        fake.stix_vulnerability(
            name,
            id=f"vulnerability--{_uuid('cve', name)}",
            created=_ts(30 - 5 * index),
            modified=_ts(20 - 5 * index),
        )
        for index, name in enumerate(CVE_NAMES)
    ]
    return _page("objects", cves, paging)


@router.get("/v1/cve/objects/{name}/bundle/")
async def cve_bundle(name: str, paging: PagingDep) -> dict:
    """A CVE with its CPEs: the vulnerability and its indicator share a UUID, the
    indicator is linked to the grouping of the vulnerable software by
    ``x-cpes-vulnerable`` (custom objects ``weakness`` are included, as in the API)."""
    identity = fake.stix_identity(
        name="dogesec", id=VULMATCH_AUTHOR_ID, created=_ts(500), modified=_ts(500)
    )
    clear = fake.stix_marking_definition("TLP:CLEAR")
    statement = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": VULMATCH_MARKING_ID,
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "Origin: https://github.com/muchdogesec/vulmatch"},
    }
    common = {
        "created_by_ref": identity["id"],
        "object_marking_refs": [clear["id"], statement["id"]],
    }
    vulnerability = fake.stix_vulnerability(
        name,
        id=f"vulnerability--{_uuid('cve', name)}",
        created=_ts(30),
        modified=_ts(20),
        description=fake.paragraph(),
        **common,
    )
    suffix = vulnerability["id"].split("--")[1]
    software = [
        {
            "type": "software",
            "spec_version": "2.1",
            "id": f"software--{_uuid('cpe', name, vendor)}",
            "name": product,
            "cpe": f"cpe:2.3:a:{vendor}:{product}:1.{index}:*:*:*:*:*:*:*",
            "vendor": vendor,
            "version": f"1.{index}",
            "x_opencti_description": f"{vendor} {product}",
        }
        for index, (vendor, product) in enumerate(
            [("acme", "gateway"), ("initech", "portal")]
        )
    ]
    grouping = {
        "type": "grouping",
        "spec_version": "2.1",
        "id": f"grouping--{_uuid('grouping', name)}",
        "context": "suspicious-activity",
        "object_refs": [s["id"] for s in software],
        "created": _ts(30),
        "modified": _ts(20),
        **common,
    }
    pattern = " OR ".join(f"software:cpe = '{s['cpe']}'" for s in software)
    indicator = fake.stix_indicator(
        "ipv4-addr",
        fake.ipv4_public(),
        id=f"indicator--{suffix}",
        name=f"{name} vulnerable CPEs",
        pattern=f"[{pattern}]",
        created=_ts(30),
        modified=_ts(20),
        valid_from=_ts(30),
        x_opencti_main_observable_type="Software",
        **common,
    )
    weakness = {
        "type": "weakness",
        "spec_version": "2.1",
        "id": f"weakness--{_uuid('cwe-79')}",
        "name": "CWE-79",
        "created": _ts(500),
        "modified": _ts(500),
        **common,
    }
    technique = fake.stix_attack_pattern("T1190", created=_ts(500), modified=_ts(500))
    relationships = [
        fake.stix_relationship(
            indicator["id"],
            grouping["id"],
            "x-cpes-vulnerable",
            id=f"relationship--{_uuid('vulnerable', name)}",
            **common,
        ),
        fake.stix_relationship(
            vulnerability["id"], weakness["id"], "related-to", **common
        ),
        fake.stix_relationship(
            technique["id"], vulnerability["id"], "related-to", **common
        ),
    ]
    kev = fake.stix_report(
        [vulnerability["id"]],
        name=f"KEV: {name}",
        published=_ts(20),
        report_types=["vulnerability"],
        **common,
    )
    objects = [
        identity,
        clear,
        statement,
        vulnerability,
        indicator,
        grouping,
        *software,
        weakness,
        technique,
        kev,
        *relationships,
    ]
    return _page("objects", objects, paging)


@router.get("/v1/sbom/")
async def sbom(paging: PagingDep) -> dict:
    """The CPEs of the user's software bill of materials."""
    cpes = [
        {"cpe": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"}
        for vendor, product in [("acme", "gateway"), ("initech", "portal")]
    ]
    return _page("objects", cpes, paging)


@router.get("/v1/{kb}/versions/installed/")
async def kb_versions(kb: str) -> dict:
    _knowledge_base(kb)
    return {"versions": ["v17.1", "v16.1"]}


@router.get("/v1/{kb}/objects/")
async def kb_list(kb: str, paging: PagingDep) -> dict:
    _knowledge_base(kb)
    return _page("objects", _kb_objects(kb), paging)


@router.get("/v1/{kb}/objects/{object_id}/bundle/")
async def kb_bundle(kb: str, object_id: str, paging: PagingDep) -> dict:
    """The object, its author and, for ATT&CK, a group using it."""
    _knowledge_base(kb)
    matching = [o for o in _kb_objects(kb) if o["id"] == object_id]
    if not matching:
        raise HTTPException(status_code=404, detail="Not found.")
    identity, marking = _author("The MITRE Corporation")
    common = {"created_by_ref": identity["id"], "object_marking_refs": [marking["id"]]}
    obj = {**matching[0], **common}
    objects = [identity, marking, obj]
    if kb.startswith("attack-"):
        group = fake.stix_intrusion_set(**common, created=_ts(2000), modified=_ts(1000))
        objects += [
            group,
            fake.stix_relationship(group["id"], obj["id"], "uses", **common),
        ]
    return _page("objects", objects, paging)


# -- CyberThreatExchange: https://api.cyberthreatexchange.com --


@router.get("/v1/subscriptions/")
async def subscriptions(paging: PagingDep) -> dict:
    """The feeds the user subscribed to: the configured one is active."""
    feeds = [
        {
            "feed": {"id": FEED_ID, "name": "Daily malware indicators"},
            "subscription": {"status": "active", "created": _ts(2000)},
        },
        {
            "feed": {"id": _uuid("feed", "other"), "name": "Phishing kits"},
            "subscription": {"status": "inactive", "created": _ts(3000)},
        },
    ]
    return _page("results", feeds, paging)


@router.get("/v1/feeds/{feed_id}/objects/")
async def feed_objects(feed_id: str, added_after: str = "") -> dict:
    """Two pages of indicators: the first one points to the second by a cursor
    (``next``, the value of ``added_after`` to send back), the second one ends."""
    if feed_id != FEED_ID:
        raise HTTPException(status_code=404, detail="Not found.")
    identity, marking = _author("CyberThreatExchange")
    first = [identity, marking, *_intel(identity, marking)]
    second = [identity, marking, *_intel(identity, marking)]
    return {
        "page_size": len(first),
        "page_results_count": len(first),
        "total_results_count": len(first) + len(second),
        "next": None if added_after else _ts(1),
        "objects": second if added_after else first,
    }


# -- Obstracts: http://api.obstracts.com --


@router.get("/v1/feeds/")
async def obstracts_feeds(paging: PagingDep) -> dict:
    feeds = [
        {
            "id": OBSTRACTS_FEED_ID,
            "title": "Threat research blogs",
            "description": fake.sentence(),
            "url": "https://blog.example.com/feed.xml",
            "feed_type": "rss",
            "datetime_added": _ts(5000),
        }
    ]
    return _page("feeds", feeds, paging)


@router.get("/v1/feeds/{feed_id}/posts/")
async def obstracts_posts(feed_id: str, paging: PagingDep) -> dict:
    """Two processed posts, updated in the last day."""
    posts = [
        {
            "id": _uuid("post", feed_id, str(index)),
            "title": fake.sentence(nb_words=6),
            "description": fake.paragraph(),
            "link": fake.url(),
            "pubdate": _ts(30 - index),
            "datetime_added": _ts(26 - index),
            "datetime_updated": _ts(20 - index),
            "job_state": "processed",
        }
        for index in range(2)
    ]
    return _page("posts", posts, paging)


@router.get("/v1/feeds/{feed_id}/posts/{post_id}/objects/")
async def obstracts_post_objects(post_id: str, paging: PagingDep) -> dict:
    """The report of a post and the intelligence extracted from it."""
    identity, marking = _author("Obstracts")
    objects = _report_bundle(identity, marking, post_id)
    return _page("objects", objects, paging)


# -- SIEM Rules: http://api.siemrules.com --


@router.get("/v1/detection-packs/")
async def detection_packs(paging: PagingDep) -> dict:
    packs = [
        {
            "id": DETECTION_PACK_ID,
            "name": "Ransomware detection pack",
            "description": fake.sentence(),
            "created": _ts(900),
        }
    ]
    return _page("results", packs, paging)


@router.get("/v1/detection-packs/{pack_id}/rules/")
async def pack_rules(pack_id: str, paging: PagingDep) -> dict:
    """One base rule and one correlation rule."""
    rules = [
        {
            "rule_type": rule_type,
            "metadata": {
                "id": _uuid("rule", pack_id, rule_type),
                "name": f"{fake.malware_family()} {rule_type} detection",
                "modified": _ts(10 - index),
            },
        }
        for index, rule_type in enumerate(["base", "correlation"])
    ]
    return _page("results", rules, paging)


def _rule_bundle(rule_id: str) -> list[dict]:
    """A Sigma indicator, the technique it detects and the rule's author."""
    identity, marking = _author("SIEM Rules")
    common = _common(identity, marking)
    technique = fake.stix_attack_pattern(**common)
    sigma = (
        f"title: {fake.malware_family()} activity\n"
        f"id: {rule_id}\n"
        "status: experimental\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    Image|endswith: '\\powershell.exe'\n"
        "  condition: selection\n"
    )
    indicator = fake.stix_indicator(
        "domain-name",
        fake.domain_name(),
        id=f"indicator--{rule_id}",
        name=f"Sigma rule {rule_id[:8]}",
        pattern=sigma,
        pattern_type="sigma",
        x_opencti_main_observable_type="Unknown",
        **common,
    )
    relationship = fake.stix_relationship(
        indicator["id"], technique["id"], "indicates", **common
    )
    return [identity, marking, technique, indicator, relationship]


@router.get("/v1/base-rules/{rule_id}/objects/")
async def base_rule_objects(rule_id: str, paging: PagingDep) -> dict:
    return _page("objects", _rule_bundle(rule_id), paging)


@router.get("/v1/correlation-rules/{rule_id}/objects/")
async def correlation_rule_objects(rule_id: str, paging: PagingDep) -> dict:
    return _page("objects", _rule_bundle(rule_id), paging)


# -- Stixify: http://api.stixify.com --


@router.get("/v1/dossiers/")
async def dossiers(paging: PagingDep) -> dict:
    items = [
        {
            "id": DOSSIER_ID,
            "name": "Ransomware reports",
            "description": fake.sentence(),
            "created": _ts(800),
        }
    ]
    return _page("results", items, paging)


@router.get("/v1/dossiers/{dossier_id}/reports/")
async def dossier_reports(dossier_id: str, paging: PagingDep) -> dict:
    """Two reports of the dossier, each with the metadata Stixify adds."""
    reports = [
        {
            "id": _uuid("report", dossier_id, str(index)),
            "stixify_report_metadata": {
                "name": f"{fake.intrusion_set()} report",
                "created": _ts(40),
                "modified": _ts(20),
            },
        }
        for index in range(2)
    ]
    return _page("objects", reports, paging)


@router.get("/v1/reports/{report_id}/objects/")
async def report_objects(report_id: str, paging: PagingDep) -> dict:
    identity, marking = _author("Stixify")
    objects = _report_bundle(identity, marking, report_id)
    return _page("objects", objects, paging)
