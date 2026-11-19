"""Mandiant Advantage threat intelligence API v4 (OAuth2 client credentials), read by
the OpenCTI mandiant connector: actors, malware, campaigns, indicators, vulnerabilities
and reports (JSON detail, STIX bundle and PDF)."""

import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Header, Query, Response

from app.fake import fake

HOSTS = ["api.intelligence.mandiant.com"]
router = APIRouter(prefix="/mandiant", tags=["Mandiant"])

STATEMENT_MARKING = "marking-definition--ad2caa47-58fd-5491-8f67-255377927369"
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
TECHNIQUES = {
    "T1059": "Command and Scripting Interpreter",
    "T1566": "Phishing",
    "T1486": "Data Encrypted for Impact",
}
# an attack pattern id is stable: the campaign detail, its timeline and its attack
# pattern list must agree on it
ATTACK_PATTERNS = {
    tid: f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_URL, tid)}" for tid in TECHNIQUES
}
REPORT_TYPES = [
    "Actor Profile",
    "News Analysis",
    "Vulnerability Report",
    "Threat Activity Alert",
    "Mandiant Internal Notice",
]


def _id(kind: str) -> str:
    return f"{kind}--{uuid.uuid4()}"


def _when(days: int = 5) -> str:
    moment = datetime.now(UTC) - timedelta(
        days=fake.random_int(0, days), hours=fake.random_int(1, 20)
    )
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _association(kind: str, name: str | None = None) -> dict:
    return {"id": _id(kind), "name": name or fake.malware_family()}


@router.post("/token")
async def token() -> dict:
    return {
        "access_token": fake.sha256(),
        "expires_in": 1800,
        "token_type": "Bearer",
    }


@router.get("/v4/actor")
async def actors() -> dict:
    return {
        "threat-actors": [
            _association("threat-actor", fake.intrusion_set()) for _ in range(3)
        ]
    }


@router.get("/v4/actor/{actor_id}")
async def actor(actor_id: str) -> dict:
    """An actor with its sectors, CVEs, malware, tools and countries."""
    scope = {"attribution_scope": "confirmed", "first_seen": _when(400)}
    return {
        "id": actor_id,
        "name": fake.intrusion_set(),
        "description": fake.paragraph(),
        "last_updated": _when(),
        "aliases": [{"name": fake.intrusion_set()}, {"name": "UNC1234 (Mandiant)"}],
        "motivations": [{"name": "Espionage"}, {"name": "Financial Gain"}],
        "industries": [
            {**_association("identity", fake.industry_sector()), **scope},
        ],
        "cve": [{**_association("vulnerability"), "cve_id": fake.cve_id(), **scope}],
        "malware": [{**_association("malware"), **scope} for _ in range(2)],
        "tool": [{**_association("malware", fake.threat_tool()), **scope}],
        "locations": {
            "source": [
                {"country": {**_association("location", "Russia"), **scope}},
            ],
            "destination": [
                {"country": {**_association("location", "France"), **scope}},
            ],
        },
    }


@router.get("/v4/malware")
async def malwares() -> dict:
    return {
        "malware": [
            {
                **_association("malware"),
                "description": fake.paragraph(),
                "last_updated": _when(),
            }
            for _ in range(3)
        ]
    }


@router.get("/v4/malware/{malware_id}")
async def malware(malware_id: str) -> dict:
    scope = {"attribution_scope": "suspected", "first_seen": _when(400)}
    return {
        "id": malware_id,
        "industries": [{**_association("identity", fake.industry_sector()), **scope}],
        "cve": [{**_association("vulnerability"), "cve_id": fake.cve_id(), **scope}],
    }


@router.get("/v4/campaign")
async def campaigns() -> dict:
    return {
        "campaigns": [
            {
                "id": _id("campaign"),
                "name": f"CAMP.22.{fake.random_int(100, 999)}",
                "title": fake.sentence(nb_words=6),
            }
            for _ in range(2)
        ]
    }


@router.get("/v4/campaign/{campaign_id}")
async def campaign(campaign_id: str) -> dict:
    """A campaign whose timeline attributes techniques to its actors."""
    actors_ = [_association("threat-actor", fake.intrusion_set()) for _ in range(2)]
    technique = "T1059"
    mandiant_technique = {"id": _id("mandiant-technique"), "name": "Shell Execution"}
    first, last = _when(60), _when(2)
    timeline = [
        {"event_type": "first_observed", "timestamp": first},
        {
            "event_type": "technique_observed",
            "timestamp": first,
            "mitre_techniques": [
                {"id": ATTACK_PATTERNS[technique], "name": TECHNIQUES[technique]}
            ],
            "mandiant_technique": mandiant_technique,
            "used_by": [
                {"actor": item, "first_observed": first, "last_observed": last}
                for item in actors_
            ],
        },
        {
            "event_type": "key_event",
            "timestamp": last,
            "brief": "Operators changed their loader",
            "analyst_brief": fake.paragraph(),
            "attributions": {"mandiant_techniques": [mandiant_technique]},
        },
    ]
    return {
        "id": campaign_id,
        "name": f"CAMP.22.{fake.random_int(100, 999)}",
        "short_name": f"CAMP.22.{fake.random_int(100, 999)}",
        "description": fake.paragraph(),
        "last_activity_time": last,
        "timeline": timeline,
        "actors": [{**item, "attribution_scope": "confirmed"} for item in actors_],
        "industries": [_association("identity", fake.industry_sector())],
        "vulnerabilities": [{**_association("vulnerability"), "cve_id": fake.cve_id()}],
        "malware": [_association("malware")],
        "tools": [_association("malware", fake.threat_tool())],
        "target_locations": {"countries": [_association("location", "Germany")]},
    }


@router.get("/v4/campaign/{campaign_id}/attack-pattern")
async def campaign_attack_patterns(campaign_id: str) -> dict:  # noqa: ARG001
    return {
        "attack-patterns": {
            tid: {
                "id": ATTACK_PATTERNS[tid],
                "name": name,
                "attack_pattern_identifier": tid,
                "attribution_scope": "confirmed",
            }
            for tid, name in TECHNIQUES.items()
        }
    }


@router.get("/v4/indicator")
async def indicators(next: str | None = Query(None)) -> dict:  # noqa: A002
    """Two pages: the first one announces the second through ``next``."""
    values = {
        "ipv4": fake.ipv4_public,
        "ipv6": fake.ipv6,
        "fqdn": fake.domain_name,
        "url": fake.url,
        "md5": fake.md5,
        "sha1": fake.sha1,
    }
    items = []
    for kind, make in values.items():
        value = make()
        associations = [
            {**_association("malware"), "type": "malware"},
            {
                **_association("threat-actor", fake.intrusion_set()),
                "type": "threat-actor",
            },
        ]
        items.append(
            {
                "id": _id(kind),
                "mscore": fake.random_int(80, 100),
                "type": kind,
                "value": value,
                "first_seen": _when(30),
                "last_seen": _when(),
                "last_updated": _when(),
                "sources": [{"source_name": "Mandiant", "category": ["malware"]}],
                "attributed_associations": associations,
                "campaigns": [
                    {
                        "id": _id("campaign"),
                        "name": f"CAMP.22.{fake.random_int(100, 999)}",
                        "title": fake.sentence(nb_words=5),
                    }
                ],
            }
        )
    body = {"indicators": items[:4] if not next else items[4:]}
    if not next:
        body["next"] = "staticfire-indicators-page-2"
    return body


@router.get("/v4/vulnerability")
async def vulnerabilities() -> dict:
    return {
        "vulnerability": [
            {
                "id": _id("vulnerability"),
                "cve_id": fake.cve_id(),
                "description": fake.paragraph(),
                "publish_date": _when(90),
                "common_vulnerability_scores": {
                    "v3.1": {
                        "base_score": 8.8,
                        "attack_vector": "NETWORK",
                        "integrity_impact": "HIGH",
                        "availability_impact": "HIGH",
                        "confidentiality_impact": "HIGH",
                    }
                },
            }
            for _ in range(3)
        ]
    }


@router.get("/v4/reports")
async def reports() -> dict:
    return {
        "objects": [
            {
                "report_id": f"22-{fake.random_int(10000000, 99999999)}",
                "report_type": report_type,
                "title": fake.sentence(nb_words=7),
                "report_link": f"https://advantage.mandiant.com/reports/{fake.uuid4()}",
            }
            for report_type in REPORT_TYPES
        ]
    }


def _report_bundle(report_id: str) -> dict:
    """The STIX bundle of a report: the objects the connector maps and relates."""
    created = _when(10)
    marking = [STATEMENT_MARKING, TLP_AMBER]
    base = {"spec_version": "2.1", "created": created, "modified": created}
    actor_ = {
        **base,
        "type": "threat-actor",
        "id": _id("threat-actor"),
        "name": fake.intrusion_set(),
        "object_marking_refs": marking,
    }
    malware_ = {
        **base,
        "type": "malware",
        "id": _id("malware"),
        "name": fake.malware_family(),
        "is_family": True,
        "object_marking_refs": marking,
    }
    sector = {
        **base,
        "type": "identity",
        "id": _id("identity"),
        "name": fake.industry_sector(),
        "identity_class": "class",
        "object_marking_refs": marking,
    }
    country = {
        **base,
        "type": "location",
        "id": _id("location"),
        "name": "France",
        "object_marking_refs": marking,
    }
    cve = fake.cve_id()
    vulnerability = {
        **base,
        "type": "vulnerability",
        "id": _id("vulnerability"),
        "name": cve,
        "object_marking_refs": marking,
        "x_mandiant_com_vulnerability_score": [
            {"cvss_version": "3.1", "base_metrics": {"base_score": 7.5}}
        ],
    }
    indicator = {
        **base,
        "type": "indicator",
        "id": _id("indicator"),
        "name": "c2 address",
        "pattern": f"[ipv4-addr:value = '{fake.ipv4_public()}']",
        "pattern_type": "stix",
        "valid_from": created,
        "object_marking_refs": marking,
    }
    ipv4 = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": _id("ipv4-addr"),
        "value": fake.ipv4_public(),
        "object_marking_refs": marking,
    }
    domain = {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": _id("domain-name"),
        "value": fake.domain_name(),
        "object_marking_refs": marking,
    }
    file = {
        "type": "file",
        "spec_version": "2.1",
        "id": _id("file"),
        "hashes": {"SHA-256": fake.sha256()},
        "object_marking_refs": marking,
    }
    software = {
        **base,
        "type": "software",
        "id": _id("software"),
        "name": "Exchange Server",
        "vendor": "Microsoft",
        "object_marking_refs": marking,
    }
    attack_pattern = {
        **base,
        "type": "attack-pattern",
        "id": _id("attack-pattern"),
        "name": "Phishing",
        "object_marking_refs": marking,
    }
    course = {
        **base,
        "type": "course-of-action",
        "id": _id("course-of-action"),
        "name": "Apply the vendor patch",
        "object_marking_refs": marking,
    }
    marking_definition = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": STATEMENT_MARKING,
        "created": "2022-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "Copyright Mandiant. All rights reserved."},
    }
    objects = [
        actor_,
        malware_,
        sector,
        country,
        vulnerability,
        indicator,
        ipv4,
        domain,
        file,
        software,
        attack_pattern,
        course,
    ]
    report = {
        **base,
        "type": "report",
        "id": _id("report"),
        "name": fake.sentence(nb_words=7),
        "description": fake.paragraph(),
        "report_types": ["threat-report"],
        "published": created,
        "object_refs": [item["id"] for item in objects],
        "object_marking_refs": marking,
        "external_references": [{"source_name": "Mandiant", "external_id": report_id}],
        "x_mandiant_com_metadata": {
            "report_type": "Actor Profile",
            "subscriptions": ["Fusion"],
            "risk_rating": "HIGH",
        },
        "x_mandiant_com_tracking_info": {"labels": ["tracked"]},
        "x_mandiant_com_additional_description_sections": {
            "analysis": fake.paragraph(),
            "key_points": [fake.sentence(), fake.sentence()],
        },
    }
    relationship = {
        **base,
        "type": "relationship",
        "id": _id("relationship"),
        "relationship_type": "uses",
        "source_ref": actor_["id"],
        "target_ref": malware_["id"],
        "object_marking_refs": marking,
    }
    return {
        "type": "bundle",
        "id": _id("bundle"),
        "objects": [marking_definition, report, *objects, relationship],
    }


def _pdf(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"
    parts = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        " /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = "%PDF-1.4\n", []
    for number, part in enumerate(parts, 1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n{part}\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(parts) + 1}\n0000000000 65535 f \n"
    out += "".join(f"{offset:010d} 00000 n \n" for offset in offsets)
    out += (
        f"trailer\n<< /Size {len(parts) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    )
    return out.encode()


@router.get("/v4/report/{report_id}")
async def report(report_id: str, accept: str = Header("application/json")) -> Response:
    """The report as JSON detail, a STIX bundle or a PDF, by the Accept header."""
    if "pdf" in accept:
        return Response(
            _pdf(f"Mandiant report {report_id}"), media_type="application/pdf"
        )
    if "stix" in accept:
        return Response(
            json.dumps(_report_bundle(report_id)),
            media_type="application/stix+json;version=2.1",
        )
    return Response(
        json.dumps(
            {
                "report_id": report_id,
                "title": fake.sentence(nb_words=7),
                "fromMedia": f"<p>{fake.paragraph()}</p>",
                "storyLink": fake.url(),
                "outlet": "Example News",
                "isightComment": f"<p>{fake.sentence()}</p>",
                "tags": {
                    "affected_industries": ["Financial Services"],
                    "target_geographies": ["France"],
                    "malware_families": [fake.malware_family()],
                },
            }
        ),
        media_type="application/json",
    )
