"""Hunter (Cyborg Security, Intel 471): the hunt packages search, read by the
intel471-hunt enrichment connector."""

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["api.hunter.cyborgsecurity.io"]
router = APIRouter(prefix="/hunter", tags=["Hunter"])

SEVERITIES = ["High", "Medium", "Low"]
TACTICS = {
    "T1059.001": ("PowerShell", "Execution"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
}
# Query parameters of the API that filter on a list of the hunt's tags
TAG_FILTERS = {
    "actors",
    "campaigns",
    "threat_names",
    "tools",
    "target_industries",
    "target_countries",
    "source_countries",
    "target_regions",
    "source_regions",
    "exploit_or_vulns",
}


def _sigma(title: str, technique_id: str) -> str:
    return (
        f"title: {title}\n"
        "status: experimental\n"
        f"id: {fake.uuid4()}\n"
        f"description: {fake.sentence()}\n"
        "author: Cyborg Research\n"
        "date: 2026/05/13\n"
        "tags:\n"
        f"  - attack.{technique_id.lower()}\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        "    selection:\n"
        f"        Image|endswith: '\\{fake.word()}.exe'\n"
        f"        CommandLine|contains: '{fake.word()}'\n"
        "    condition: selection\n"
        "level: high\n"
    )


def _hunt(filters: dict[str, list[str]]) -> dict:
    title = f"{fake.malware_family()} {fake.word().capitalize()} Execution"
    hunt_uuid = fake.uuid4()
    created = fake.date_time_between(start_date="-90d", end_date="-30d")
    updated = fake.date_time_between(start_date="-30d", end_date="now")
    technique_id, (technique, tactic) = fake.random_element(list(TACTICS.items()))
    tags = {
        "actors": [fake.intrusion_set()],
        "campaigns": [f"{fake.word().capitalize()} {fake.random_int(2024, 2026)}"],
        "threat_names": [fake.malware_family()],
        "threat_categories": ["Malware"],
        "tools": [fake.threat_tool()],
        "target_industries": [fake.industry_sector()],
        "target_countries": ["France"],
        "source_regions": ["Eastern Europe"],
        "exploit_or_vulns": [fake.cve_id()],
        "attack_surfaces": ["Client"],
        "target_oses": ["Windows"],
        "kill_chains": ["Actions on Objectives"],
        "mitre_technique_ids": [technique_id],
        "mitre_technique_names": [technique],
        "mitre_tactic_names": [tactic],
    }
    for key, values in filters.items():
        if key in TAG_FILTERS:
            tags[key] = list(dict.fromkeys([*values, *tags.get(key, [])]))
    return {
        "index": "cyborg_usecases",
        "id": hunt_uuid,
        "UUID": hunt_uuid,
        "score": 5.0,
        "title": title,
        "status": "Complete",
        "author": "Cyborg Research",
        "created_date": created.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
        "completed_date": created.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
        "last_updated": updated.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00"),
        "source": "Intel",
        "severity": fake.random_element(SEVERITIES),
        "description": fake.paragraph(),
        "hunt_category": "process_creation",
        "sigma": _sigma(title, technique_id),
        "references": {
            "general": [fake.url()],
            "analysis": [fake.url()],
            "deep_dives": [],
            "blog_links": [],
            "malware_samples": [],
        },
        "response_actions": {
            "analyst_runbook": fake.paragraph(),
            "mitigation_recommendations": fake.paragraph(),
        },
        "validation": fake.paragraph(),
        "running_analyst_notes": [
            {
                "analyst_note_date": updated.strftime("%Y-%m-%d"),
                "analyst_note_type": "Additional Context",
                "analyst_note_author": "Cyborg Research",
                "current_analyst_note": fake.paragraph(),
                "analyst_note_summary": fake.sentence(),
                "analyst_note_pivots": f"- {fake.sentence()}",
                "analyst_note_attribution": fake.sentence(),
                "malware_names": tags["threat_names"],
                "adversary_names": tags["actors"],
                "observed_commandlines": [],
                "references": {
                    "titan_references": [],
                    "cyborg_sources": [],
                    "general_references": [
                        {"title": fake.sentence(), "link": fake.url()}
                    ],
                },
            }
        ],
        "mapping": {
            "mitre": {
                "mitre_attack_payload": [
                    {technique_id: {"technique_name": technique, "tactics": [tactic]}}
                ],
                "mitre_attack_tactics": [tactic],
                "mitre_attack_techniques": [technique],
                "mitre_attack_technique_ids": [technique_id],
            },
            "kill_chains": ["Actions on Objectives"],
            "diamond_model": "Capability",
            "exploit_or_vulns": tags["exploit_or_vulns"],
            "cwe_ids": [],
        },
        "tags": tags,
    }


@router.get("/es/query")
async def es_query(request: Request) -> dict:
    """A few hunt packages matching the filters (the values asked are in their tags)."""
    filters: dict[str, list[str]] = {}
    for key, value in request.query_params.multi_items():
        filters.setdefault(key, []).append(value)
    hunts = [_hunt(filters) for _ in range(3)]
    return {"total": len(hunts), "count": len(hunts), "results": hunts}
