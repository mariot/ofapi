"""IBM X-Force Premier Threat Intelligence: the TAXII 2.1 server of reports, indicators
and vulnerabilities, read by the OpenCTI ibm-xti connector (taxii2-client)."""

import json
from datetime import UTC, datetime, timedelta
from itertools import count

from fastapi import APIRouter, Query, Response

from app.fake import fake

HOSTS = ["taxii.xforce.ibmcloud.com"]
router = APIRouter(prefix="/ibm-xti", tags=["IBM X-Force"])

TAXII_MEDIA = "application/taxii+json;version=2.1"
ROOT = "https://taxii.xforce.ibmcloud.com/taxii2/api/"
EXTENSION = "extension-definition--3d9b4c1e-5a2f-4c7e-9d10-6b8f2a4e7c15"
# The connector gives this collection a two years first import window
VULNERABILITIES = "23e33546-486b-415f-851c-250b6a7b0674"
REPORTS = "6f4d2c1a-8b3e-4a57-9c1d-2e5f7a9b0c34"
INDICATORS = "a1b2c3d4-e5f6-4789-8abc-def012345678"
COLLECTIONS = [
    (REPORTS, "reports", "Threat intelligence reports", "report", 3, 2),
    (INDICATORS, "indicators", "Indicators of compromise", "indicator", 5, 3),
    (VULNERABILITIES, "vulnerabilities", "Vulnerabilities", "vulnerability", 4, 2),
]


def _stamp(days_ago: float = 0) -> str:
    when = datetime.now(UTC) - timedelta(days=days_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def _base(kind: str, days_ago: float) -> dict:
    stamp = _stamp(days_ago)
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{fake.uuid4()}",
        "created": stamp,
        "modified": stamp,
    }


def _report() -> list[dict]:
    """A report with the malware and actor it is about, and their relationship."""
    malware = {**_base("malware", 3), "name": fake.malware_family(), "is_family": True}
    actor = {
        **_base("threat-actor", 3),
        "name": fake.intrusion_set(),
        "threat_actor_types": ["crime-syndicate"],
    }
    relationship = {
        **_base("relationship", 3),
        "relationship_type": "uses",
        "source_ref": actor["id"],
        "target_ref": malware["id"],
    }
    report = {
        **_base("report", 1),
        "name": f"{actor['name']} campaign using {malware['name']}",
        "description": (
            f"## Summary\n\n{fake.paragraph()}\n\n| Indicator | Type |\n| --- | --- |\n"
            f"| {fake.domain_name()} | domain |\n"
        ),
        "published": _stamp(1),
        "report_types": ["threat-report"],
        "object_refs": [malware["id"], actor["id"], relationship["id"]],
        "labels": ["int.entitle.premier", "ransomware"],
        "extensions": {
            EXTENSION: {
                "extension_type": "property-extension",
                "summary": fake.sentence(),
            }
        },
    }
    return [report, malware, actor, relationship]


def _indicator() -> list[dict]:
    kind, value = [
        ("ipv4-addr", fake.ipv4_public()),
        ("domain-name", fake.domain_name()),
        ("url", fake.url()),
        ("file", None),
    ][next(_indicators) % 4]
    if kind == "file":
        pattern = f"[file:hashes.'SHA-256' = '{fake.sha256()}']"
    else:
        pattern = f"[{kind}:value = '{value}']"
    return [
        {
            **_base("indicator", 1),
            "name": value or "file hash",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": _stamp(1),
            "indicator_types": ["malicious-activity"],
            "labels": ["malware"],
            "confidence": 80,
        }
    ]


def _vulnerability() -> list[dict]:
    cve = fake.cve_id()
    return [
        {
            **_base("vulnerability", 2),
            "name": f"X-Force vulnerability {fake.random_int(100000, 999999)}",
            "description": fake.paragraph(),
            "external_references": [
                {
                    "source_name": "xfid",
                    "external_id": str(fake.random_int(100000, 999999)),
                },
                {"source_name": "cve", "external_id": cve},
            ],
            "extensions": {
                EXTENSION: {
                    "extension_type": "property-extension",
                    "cvss": [
                        {
                            "string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "base_score": 9.8,
                        }
                    ],
                    "reference": [
                        {
                            "url": fake.url(),
                            "date": _stamp(5),
                            "kev_guidance": "Apply updates per vendor instructions.",
                        }
                    ],
                    "platform": [
                        {
                            "vendor": "acme",
                            "product": fake.word(),
                            "affected": True,
                            "cpe": "cpe:2.3:a:acme:product:1.0:*:*:*:*:*:*:*",
                        },
                        {
                            "vendor": "acme",
                            "product": "other",
                            "affected": False,
                            "cpe": "cpe:2.3:a:acme:other:2.0:*:*:*:*:*:*:*",
                        },
                    ],
                }
            },
        }
    ]


_indicators = count()
MAKERS = {"report": _report, "indicator": _indicator, "vulnerability": _vulnerability}


def _taxii(body: dict) -> Response:
    return Response(json.dumps(body), media_type=TAXII_MEDIA)


@router.get("/taxii2/")
async def discovery() -> Response:
    """The server discovery: one API root."""
    return _taxii(
        {
            "title": "IBM X-Force Premier Threat Intelligence",
            "description": "TAXII 2.1 server",
            "default": ROOT,
            "api_roots": [ROOT],
        }
    )


@router.get("/taxii2/api/")
async def api_root() -> Response:
    """The API root."""
    return _taxii(
        {
            "title": "X-Force",
            "versions": [TAXII_MEDIA],
            "max_content_length": 104857600,
        }
    )


@router.get("/taxii2/api/collections/")
async def collections() -> Response:
    """The readable collections, each with the STIX type of its primary objects."""
    return _taxii(
        {
            "collections": [
                {
                    "id": identifier,
                    "title": title,
                    "alias": alias,
                    "can_read": True,
                    "can_write": False,
                    "media_types": [TAXII_MEDIA],
                    "type": kind,
                }
                for identifier, alias, title, kind, _, _ in COLLECTIONS
            ]
        }
    )


@router.get("/taxii2/api/collections/{collection_id}/objects/")
async def objects(
    collection_id: str, cursor: str | None = Query(None, alias="next")
) -> Response:
    """Objects in pages of whole groups (a report with what it refers to); ``next`` is
    the offset of the following group."""
    spec = next((c for c in COLLECTIONS if c[0] == collection_id), None)
    if spec is None:
        return Response(status_code=404)
    _, _, _, kind, total, per_page = spec
    offset = int(cursor) if cursor else 0
    count = max(min(per_page, total - offset), 0)
    page = [obj for _ in range(count) for obj in MAKERS[kind]()]
    envelope: dict = {"objects": page}
    if offset + count < total:
        envelope.update(more=True, next=str(offset + count))
    else:
        envelope["more"] = False
    return _taxii(envelope)
