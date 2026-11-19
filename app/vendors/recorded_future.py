"""Recorded Future: the Connect, Analyst Notes, Links, Entity Match, Fusion and Threat
Maps APIs (api.recordedfuture.com) and the Attack Surface Intelligence API
(api.securitytrails.com).

Read by the OpenCTI recorded-future (risk lists, analyst notes, threat maps),
recorded-future-asi and recordedfuture-enrichment connectors. Alerts and playbook
alerts are not served.
"""

import csv
import io
import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request, Response

from app.fake import fake

HOSTS = ["api.recordedfuture.com", "api.securitytrails.com"]
router = APIRouter(prefix="/recorded-future", tags=["Recorded Future"])

PDF = (
    b"%PDF-1.1\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
    b"trailer<</Root 1 0 R/Size 4>>\n%%EOF\n"
)
RISK_RULES = [
    ("Recent Reported by Insikt Group", 3),
    ("Historically Reported as a Defanged IP", 1),
    ("Recent C&C Server", 4),
    ("Recently Linked to Malware", 2),
]
THREAT_ACTORS = {f"idn:ta-{i}": fake.intrusion_set() for i in range(3)}


def _now(delta: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) - delta).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _risk(rich: bool = True) -> dict:
    """A risk block as the Connect API returns it for a high risk entity."""
    score = fake.random_int(65, 99)
    evidence = [
        {
            "criticality": criticality,
            "criticalityLabel": "Malicious",
            "rule": rule,
            "evidenceString": fake.sentence(),
            "mitigationString": "",
            "timestamp": _now(timedelta(days=fake.random_int(1, 20))),
        }
        for rule, criticality in RISK_RULES[:3]
    ]
    return {
        "score": score,
        "criticality": 3,
        "criticalityLabel": "Malicious",
        "rules": len(evidence),
        "riskString": f"{len(evidence)}/64",
        "riskSummary": f"{len(evidence)} of 64 Risk Rules currently observed.",
        "evidenceDetails": evidence if rich else [],
    }


def _link(type_: str, name: str, **attributes) -> dict:
    return {
        "id": f"{type_[:3].lower()}:{name}",
        "type": f"type:{type_}",
        "name": name,
        "attributes": [
            {"id": key, "value": value} for key, value in attributes.items()
        ],
    }


def _links() -> list[dict]:
    """The entities linked to an indicator, malware or threat actor."""
    technique = fake.mitre_attack_technique()
    return [
        _link("Malware", fake.malware_family()),
        _link("Organization", fake.intrusion_set(), threat_actor=True),
        _link("Person", fake.name()),
        _link("Company", fake.company()),
        _link("CyberVulnerability", fake.cve_id()),
        _link(
            "MitreAttackIdentifier",
            technique["external_id"],
            display_name=f"{technique['external_id']} ({technique['name']})",
        ),
        _link("Hash", fake.sha256(), risk_score=fake.random_int(70, 95)),
        _link(
            "InternetDomainName", fake.domain_name(), risk_score=fake.random_int(70, 95)
        ),
        _link("IpAddress", fake.ipv4_public(), risk_score=fake.random_int(70, 95)),
        _link("URL", fake.url(), risk_score=fake.random_int(70, 95)),
    ]


# Connect API: risk lists, enrichment and fusion files


@router.get("/v2/fusion/files")
async def fusion_file(path: str) -> Response:
    """The threat actor list and the risk lists (CSV) of the OpenCTI integration."""
    if path.endswith("threat_actors.json"):
        content = json.dumps(
            [{"entity": eid, "name": name} for eid, name in THREAT_ACTORS.items()]
        )
        return Response(content, media_type="application/json")
    vulnerability = "vulnerability" in path
    out = io.StringIO()
    if vulnerability:
        fields = [
            "Name",
            "Risk",
            "RiskString",
            "FirstSeen",
            "LastSeen",
            "EvidenceDetails",
            "Links",
        ]
    else:
        fields = [
            "Name",
            "Risk",
            "RiskString",
            "RuleCriticality",
            "RiskRules",
            "FirstSeen",
            "LastSeen",
            "Links",
        ]
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for index in range(6):
        risk = 80 if index < 5 else 20  # the last one falls under the risk threshold
        row = {
            "Risk": risk,
            "RiskString": "3/64",
            "FirstSeen": _now(timedelta(days=30)),
            "LastSeen": _now(timedelta(hours=index + 1)),
        }
        if vulnerability:
            row["Name"] = fake.cve_id()
            row["EvidenceDetails"] = json.dumps(
                [
                    {
                        "rule": rule,
                        "criticality": criticality,
                        "evidenceString": fake.sentence(),
                        "mitigationString": "",
                    }
                    for rule, criticality in RISK_RULES
                ]
            )
            row["Links"] = json.dumps([{"sections": [_section()]}])
        else:
            row["Name"] = (
                fake.ipv4_public()
                if path.endswith("ip.csv")
                else fake.domain_name()
                if path.endswith("domain.csv")
                else fake.url()
                if path.endswith("url.csv")
                else fake.sha256()
            )
            row["RuleCriticality"] = json.dumps([rule[1] for rule in RISK_RULES[:3]])
            row["RiskRules"] = json.dumps([rule[0] for rule in RISK_RULES[:3]])
            row["Links"] = json.dumps({"hits": [{"sections": [_section()]}]})
        writer.writerow(row)
    return Response(out.getvalue(), media_type="text/csv")


def _section() -> dict:
    """The related entities of a risk list row, by type."""
    technique = fake.mitre_attack_technique()
    return {
        "section_id": {"name": "Indicators and TTP"},
        "lists": [
            {
                "type": {"name": "Malware"},
                "entities": [{"name": fake.malware_family()}],
            },
            {"type": {"name": "Hash"}, "entities": [{"name": fake.sha256()}]},
            {"type": {"name": "URL"}, "entities": [{"name": fake.url()}]},
            {
                "type": {"name": "Threat Actor"},
                "entities": [{"name": fake.intrusion_set()}],
            },
            {
                "type": {"name": "MitreAttackIdentifier"},
                "entities": [{"name": technique["external_id"]}],
            },
        ],
    }


@router.head("/v2/vulnerability/risklist")
async def vulnerability_risklist() -> Response:
    """The entitlement check for the vulnerability module."""
    return Response(status_code=200)


@router.get("/v2/vulnerability/{name:path}")
async def vulnerability(name: str, fields: str = "") -> dict:
    """A CVE with its CVSS, NVD references, CPE and risk."""
    data = {
        "commonNames": [f"{name} alias"],
        "lifecycleStage": "Exploited",
        "intelCard": f"https://app.recordedfuture.com/live/sc/entity/{name}",
        "nvdDescription": fake.paragraph(),
        "nvdReferences": [
            {"url": fake.url(), "tags": ["Vendor Advisory"]} for _ in range(2)
        ],
        "relatedLinks": [fake.url() for _ in range(3)],
        "cvss": {
            "score": 7.5,
            "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "accessVector": "NETWORK",
            "accessComplexity": "LOW",
            "authentication": "NONE",
            "confidentiality": "PARTIAL",
            "integrity": "PARTIAL",
            "availability": "PARTIAL",
            "version": "2.0",
        },
        "cvssv3": {
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "HIGH",
            "exploitabilityScore": 3.9,
            "impactScore": 5.9,
            "version": "3.1",
            "source": "NVD",
        },
        "cvssv4": {
            "baseScore": 9.3,
            "baseSeverity": "CRITICAL",
            "vectorString": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            ),
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "attackRequirements": "NONE",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "vulnerableSystemConfidentiality": "HIGH",
            "vulnerableSystemIntegrity": "HIGH",
            "vulnerableSystemAvailability": "HIGH",
            "subsequentSystemConfidentiality": "NONE",
            "subsequentSystemIntegrity": "NONE",
            "subsequentSystemAvailability": "NONE",
            "version": "4.0",
            "source": "NVD",
        },
    }
    if "aiInsights" in fields:
        data["aiInsights"] = {
            "comment": "AI generated summary",
            "text": fake.paragraph(),
            "numberOfReferences": 4,
        }
    if "cpe" in fields:
        data["cpe"] = [
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            "cpe:2.3:o:linux:linux_kernel:5.4:*:*:*:*:*:*:*",
        ]
    if "risk" in fields:
        data["risk"] = _risk()
    return {"data": data}


@router.post("/links/search")
async def links_search(request: Request) -> dict:
    """The links of the entities of the body, 100 at most."""
    body = await request.json()
    entities = body.get("entities") or []
    return {
        "data": [
            {
                "entity": {
                    "id": entity_id,
                    "name": entity_id.split(":", 1)[-1],
                    "type": "type:Malware",
                },
                "links": _links(),
            }
            for entity_id in entities
        ]
    }


@router.get("/entity-match/entity/{entity_id:path}")
async def entity_match() -> dict:
    """The known aliases of an entity."""
    return {
        "data": {
            "attributes": {
                "common_names": [fake.intrusion_set()],
                "alias": [fake.intrusion_set(), fake.intrusion_set()],
            }
        }
    }


# Threat maps


@router.get("/threat/maps")
async def threat_maps() -> dict:
    """The threat maps of the organization: threat actors and malware."""
    return {
        "data": [
            {"type": "actors", "url": "/threat/map/actors"},
            {"type": "malware", "url": "/threat/map/malware"},
        ]
    }


@router.post("/threat/map/{kind}")
async def threat_map(kind: str) -> dict:
    """The entities of a threat map."""
    return {"data": {"threat_map": [{"id": f"idn:{kind}-{i}"} for i in range(3)]}}


# Analyst notes

NOTE_IDS = ["tYS3Ew", "tYS3Ex", "tYS3Ey", "tYS3Ez"]
LAST_NOTES: dict[str, dict] = {}


def _entity(type_: str, name: str, entity_id: str | None = None) -> dict:
    return {
        "id": entity_id or f"{type_[:3].lower()}:{name}",
        "type": type_,
        "name": name,
    }


def _note(note_id: str) -> dict:
    """An analyst note; the first ones carry the entities each report type maps."""
    index = NOTE_IDS.index(note_id)
    actor_id, actor_name = list(THREAT_ACTORS.items())[index % len(THREAT_ACTORS)]
    topics = [
        ["Informational"],
        ["Actor Profile", "Threat Lead"],
        ["Vulnerability Intelligence"],
        ["TTP Instance"],
    ][index]
    technique = fake.mitre_attack_technique()
    entities = [
        _entity("IpAddress", fake.ipv4_public()),
        _entity("InternetDomainName", fake.domain_name()),
        _entity("URL", fake.url()),
        _entity("Hash", fake.sha256()),
        _entity("Malware", fake.malware_family()),
        _entity("MitreAttackIdentifier", technique["external_id"]),
        _entity("CyberVulnerability", fake.cve_id()),
        _entity("Company", fake.company()),
        _entity("Country", fake.country()),
        _entity("Industry", fake.industry_sector()),
        _entity("EmailAddress", fake.email()),
        _entity("Organization", actor_name, actor_id),
        _entity("Source", fake.url()),
    ]
    attributes = {
        "title": f"{fake.catch_phrase()} ({note_id})",
        "text": fake.paragraph(nb_sentences=6),
        "published": _now(timedelta(hours=index + 1)),
        "topic": [
            {"id": f"t{i}", "name": name, "type": "Topic"}
            for i, name in enumerate(topics)
        ],
        "note_entities": entities,
        "context_entities": [_entity("Malware", fake.malware_family())],
        "validation_urls": [
            {"id": "src1", "name": fake.url(), "type": "InternetDomainName"}
        ],
    }
    if index == 0:
        attributes["attachment"] = f"{note_id}.pdf"
    return {"id": note_id, "attributes": attributes, "actor": actor_name}


@router.post("/analyst-note/search")
async def analyst_note_search() -> dict:
    """The analyst notes published in the window (one page)."""
    notes = [_note(note_id) for note_id in NOTE_IDS]
    # the lookup of a note answers for the entities the search just listed
    LAST_NOTES.update({n["id"]: n for n in notes})
    return {
        "counts": {"returned": len(notes), "total": len(notes)},
        "data": [{"id": n["id"], "attributes": n["attributes"]} for n in notes],
    }


@router.post("/analyst-note/lookup/{note_id}")
async def analyst_note_lookup(note_id: str) -> dict:
    """The events of a note: an attack of its actor, with targets and capabilities."""
    if note_id not in NOTE_IDS:
        return {"attributes": {}}
    note = LAST_NOTES.get(note_id) or _note(note_id)
    entities = {e["type"]: e for e in note["attributes"]["note_entities"]}
    return {
        "attributes": {
            "events": [
                {
                    "type": "CyberAttack",
                    "attributes": {
                        "adversary": [{"type": "Organization", "name": note["actor"]}],
                        "target": [
                            {"type": "Country", "name": entities["Country"]["name"]},
                            {"type": "Sector", "name": entities["Industry"]["name"]},
                            {"type": "Company", "name": entities["Company"]["name"]},
                        ],
                        "capabilities": [
                            {"type": "Malware", "name": entities["Malware"]["name"]},
                            {
                                "type": "MitreAttackIdentifier",
                                "name": entities["MitreAttackIdentifier"]["name"],
                            },
                            {
                                "type": "CyberVulnerability",
                                "name": entities["CyberVulnerability"]["name"],
                            },
                            {"type": "Hash", "name": entities["Hash"]["name"]},
                        ],
                    },
                }
            ]
            if note_id == NOTE_IDS[1]
            else []
        }
    }


@router.get("/analyst-note/attachment/{note_id}")
async def analyst_note_attachment() -> Response:
    """The PDF of a note."""
    return Response(PDF, media_type="application/pdf")


# Attack Surface Intelligence (SecurityTrails)

SEVERITIES = ["critical", "moderate", "informational"]


def _signature(severity: str, detailed: bool = False) -> dict:
    signature = {
        "id": fake.sha1()[:12],
        "name": fake.catch_phrase(),
        "description": fake.paragraph(),
        "severity": severity,
        "added_at": _now(timedelta(days=fake.random_int(1, 20))),
        "references": [fake.url()],
    }
    if detailed:
        signature["vulnerabilities"] = [
            {
                "cve_id": fake.cve_id(),
                "cvss_score": 9.8,
                "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "epss_score": 0.91,
                "references": [fake.url()],
                "cwe_ids": ["79", "CWE-200"],
            }
        ]
    return signature


@router.get("/v2/projects/{project_id}/exposures")
async def asi_exposures() -> dict:
    """The exposures of a project, one page."""
    return {
        "data": [
            {"signature": _signature(severity), "asset_count": fake.random_int(1, 12)}
            for severity in SEVERITIES
        ],
        "meta": {"pagination": {"next_cursor": None}},
    }


@router.get("/v2/projects/{project_id}/exposures/{signature_id}")
async def asi_exposure_assets(signature_id: str) -> dict:
    """The affected assets of an exposure signature, one page."""
    ip = fake.ipv4_public()
    domain = fake.domain_name()
    return {
        "data": {
            "signature": {**_signature("critical", detailed=True), "id": signature_id},
            "asset_exposures": [
                {
                    "asset_id": ip,
                    "instances": [{"port_number": 443}],
                    "details": {
                        "target": f"{ip}:443",
                        "extractions": {"protocol": "tls1.0"},
                    },
                },
                {
                    "asset_id": domain,
                    "instances": [{"port_number": 80}],
                    "details": {
                        "target": f"{domain}:80",
                        "extractions": {"protocol": "http"},
                    },
                },
                {"asset_id": fake.ipv6(), "instances": [], "details": {}},
            ],
        },
        "meta": {"pagination": {"next_cursor": None}},
    }


@router.get("/v1/asi/rules/history/{project_id}/activity")
async def asi_history() -> dict:
    """The exposure rules added and removed since a timestamp."""
    added = {**_signature("critical"), "classification": "high"}
    removed = {**_signature("moderate"), "classification": "moderate"}
    return {"data": [{"added_rules": [added], "removed_rules": [removed]}]}


# Declared last: these generic paths would shadow the more specific ones above


@router.get("/v2/{kind}/search")
async def indicator_search() -> dict:
    """High risk entities (the Connect API search)."""
    return {"data": {"results": []}}


@router.get("/v2/{kind}/{value:path}")
async def indicator(kind: str, value: str, fields: str = "") -> dict:
    """An ip, domain, url or hash with its entity block and risk."""
    types = {
        "ip": "IpAddress",
        "domain": "InternetDomainName",
        "url": "URL",
        "hash": "Hash",
    }
    prefixes = {"ip": "ip", "domain": "idn", "url": "url", "hash": "hash"}
    data = {
        "entity": {
            "id": f"{prefixes.get(kind, kind)}:{value}",
            "name": value,
            "type": types.get(kind, kind),
            "description": fake.sentence(),
        },
        "risk": _risk(),
    }
    if "hashAlgorithm" in fields:
        data["hashAlgorithm"] = {"sha256": "SHA-256", "md5": "MD5"}.get("sha256")
    return {"data": data}
