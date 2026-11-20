"""MITRE ATT&CK, CAPEC and ATLAS: the public STIX 2.1 bundles served from GitHub
(raw.githubusercontent.com), read by the OpenCTI mitre and mitre-atlas connectors.

The repositories are registered with the GitHub module (``GITHUB_REPOS``): the ATT&CK
Enterprise, Mobile and ICS bundles of ``mitre-attack/attack-stix-data``, the CAPEC
bundle of ``mitre/cti`` and the ATLAS bundle of ``mitre-atlas/atlas-navigator-data``.
The datasets are small but keep what the connectors act on: a collection version (kill
chain order), revoked and deprecated objects (filtered out), the MITRE statement
markings, sub-techniques and every relationship family.

ATLAS reuses the technique and tactic data of the OpenAEV catalog
(``app.api.catalogs``).
"""

import json
import uuid

from app.api.catalogs import atlas_bundle
from app.vendors.github import Repo

CREATED = "2018-04-18T17:59:24.739Z"
MODIFIED = "2026-04-28T14:00:00.000Z"
MITRE = "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
TLP_CLEAR = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
STATEMENT = "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
ATTACK_URL = "https://attack.mitre.org"
NAMESPACE = uuid.UUID("5d2f9c6e-6bd4-4a8b-a0b8-3c5c9f9e1a10")


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, kind + key)}"


def _common(kind: str, key: str, **fields) -> dict:
    return {
        "type": kind,
        "id": _id(kind, key),
        "spec_version": "2.1",
        "created": CREATED,
        "modified": MODIFIED,
        "created_by_ref": MITRE,
        # as in ATT&CK's data: MITRE's statement only (stix2 rejects a TLP:CLEAR id)
        "object_marking_refs": [STATEMENT],
        **fields,
    }


def _reference(source: str, external_id: str, path: str) -> list[dict]:
    return [
        {
            "source_name": source,
            "external_id": external_id,
            "url": f"{ATTACK_URL}/{path}/{external_id.replace('.', '/')}",
        }
    ]


def _relationship(source: dict, target: dict, kind: str, description: str = "") -> dict:
    return _common(
        "relationship",
        f"{source['id']}{kind}{target['id']}",
        relationship_type=kind,
        source_ref=source["id"],
        target_ref=target["id"],
        description=description,
    )


def _boilerplate() -> list[dict]:
    return [
        {
            "type": "identity",
            "id": MITRE,
            "spec_version": "2.1",
            "created": CREATED,
            "modified": CREATED,
            "name": "The MITRE Corporation",
            "identity_class": "organization",
            "object_marking_refs": [STATEMENT],
        },
        {
            "type": "marking-definition",
            "id": STATEMENT,
            "spec_version": "2.1",
            "created": "2017-06-01T00:00:00.000Z",
            "created_by_ref": MITRE,
            "definition_type": "statement",
            "definition": {
                "statement": "Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK "
                "and ATT&CK are registered trademarks of The MITRE Corporation."
            },
        },
    ]


def _attack(
    domain: str,
    source: str,
    path: str,
    chain: str,
    tactics: list[tuple[str, str, str]],
    techniques: list[tuple[str, str, str, str]],
    extras: bool,
) -> dict:
    """A matrix of the ATT&CK knowledge base (``domain`` is the bundle's file name)."""
    objects = _boilerplate()
    collection = _common(
        "x-mitre-collection",
        domain,
        name=f"{domain.replace('-', ' ').title()}",
        description=f"ATT&CK {domain} collection (ofapi dataset)",
        x_mitre_contents=[],
        x_mitre_version="19.0",
        x_mitre_attack_spec_version="3.3.0",
    )
    tactic_objects = [
        _common(
            "x-mitre-tactic",
            f"{domain}{tactic_id}",
            name=name,
            description=f"The adversary is trying to reach the objective: {name}.",
            x_mitre_shortname=short,
            x_mitre_domains=[domain],
            x_mitre_version="1.0",
            external_references=_reference("mitre-attack", tactic_id, "tactics"),
        )
        for tactic_id, name, short in tactics
    ]
    matrix = _common(
        "x-mitre-matrix",
        domain,
        name=domain.replace("-attack", "").title(),
        description=f"The {domain} matrix.",
        tactic_refs=[tactic["id"] for tactic in tactic_objects],
        x_mitre_domains=[domain],
        x_mitre_version="1.0",
        external_references=[
            {"source_name": source, "external_id": domain, "url": ATTACK_URL}
        ],
    )
    patterns = {}
    for external_id, name, phase, _parent in techniques:
        pattern = _common(
            "attack-pattern",
            f"{domain}{external_id}",
            name=name,
            description=f"Adversaries may use {name.lower()} to meet an objective.",
            kill_chain_phases=[{"kill_chain_name": chain, "phase_name": phase}],
            x_mitre_is_subtechnique="." in external_id,
            x_mitre_platforms=["Windows", "Linux", "macOS"],
            x_mitre_detection="Monitor for anomalous behavior.",
            x_mitre_domains=[domain],
            x_mitre_version="1.2",
            external_references=_reference(source, external_id, path),
        )
        patterns[external_id] = pattern
    deprecated = _common(
        "attack-pattern",
        f"{domain}revoked",
        name="Retired Technique",
        description="This technique was merged into another one.",
        revoked=True,
        kill_chain_phases=[{"kill_chain_name": chain, "phase_name": tactics[0][2]}],
        external_references=_reference(source, "T9999", path),
    )
    objects += [collection, *tactic_objects, matrix, *patterns.values(), deprecated]
    for external_id, (_, _, _, parent) in zip(patterns, techniques, strict=True):
        if parent:
            objects.append(
                _relationship(
                    patterns[external_id], patterns[parent], "subtechnique-of"
                )
            )
    objects.append(_relationship(deprecated, patterns[techniques[0][0]], "revoked-by"))
    if extras:
        objects += _enterprise_extras(domain, patterns)
    collection["x_mitre_contents"] = [
        {
            "object_ref": item["id"],
            "object_modified": item.get("modified", MODIFIED),
        }
        for item in objects
        if item["type"].startswith(
            ("attack-pattern", "x-mitre", "intrusion", "malware")
        )
        and item["type"] != "x-mitre-collection"
    ]
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _enterprise_extras(domain: str, patterns: dict) -> list[dict]:
    """Group, software, campaign, mitigation and data source of Enterprise."""
    group = _common(
        "intrusion-set",
        "G0016",
        name="APT29",
        aliases=["APT29", "IRON HEMLOCK", "The Dukes"],
        description="APT29 is threat group that has been attributed to Russia's SVR.",
        external_references=_reference("mitre-attack", "G0016", "groups"),
        x_mitre_domains=[domain],
        x_mitre_version="1.0",
    )
    malware = _common(
        "malware",
        "S0154",
        name="Cobalt Strike",
        is_family=True,
        description="Cobalt Strike is a commercial, full-featured penetration "
        "testing tool.",
        labels=["malware"],
        external_references=_reference("mitre-attack", "S0154", "software"),
        x_mitre_aliases=["Cobalt Strike"],
        x_mitre_platforms=["Windows"],
        x_mitre_domains=[domain],
        x_mitre_version="1.0",
    )
    tool = _common(
        "tool",
        "S0002",
        name="Mimikatz",
        description="Mimikatz is a credential dumper capable of obtaining plaintext "
        "Windows account logins and passwords.",
        labels=["tool"],
        external_references=_reference("mitre-attack", "S0002", "software"),
        x_mitre_aliases=["Mimikatz"],
        x_mitre_platforms=["Windows"],
        x_mitre_domains=[domain],
        x_mitre_version="1.0",
    )
    campaign = _common(
        "campaign",
        "C0024",
        name="SolarWinds Compromise",
        description="The 2020 supply chain compromise of the SolarWinds Orion "
        "platform.",
        aliases=["SolarWinds Compromise"],
        first_seen="2019-09-01T05:00:00.000Z",
        last_seen="2021-01-01T06:00:00.000Z",
        external_references=_reference("mitre-attack", "C0024", "campaigns"),
        x_mitre_first_seen_citation="(Citation: CISA SolarWinds)",
        x_mitre_domains=[domain],
        x_mitre_version="1.2",
    )
    mitigation = _common(
        "course-of-action",
        "M1049",
        name="Antivirus/Antimalware",
        description="Use signatures or heuristics to detect malicious software.",
        external_references=_reference("mitre-attack", "M1049", "mitigations"),
        x_mitre_domains=[domain],
        x_mitre_version="1.1",
    )
    source_data = _common(
        "x-mitre-data-source",
        "DS0009",
        name="Process",
        description="Instances of computer programs that are being executed.",
        x_mitre_platforms=["Windows", "Linux", "macOS"],
        x_mitre_collection_layers=["Host"],
        x_mitre_domains=[domain],
        x_mitre_version="1.0",
        external_references=_reference("mitre-attack", "DS0009", "datasources"),
    )
    component = _common(
        "x-mitre-data-component",
        "DS0009creation",
        name="Process Creation",
        description="The initial construction of a new process.",
        x_mitre_data_source_ref=source_data["id"],
        x_mitre_domains=[domain],
        x_mitre_version="1.1",
    )
    phishing = patterns["T1566"]
    powershell = patterns["T1059.001"]
    lsass = patterns["T1003.001"]
    return [
        group,
        malware,
        tool,
        campaign,
        mitigation,
        source_data,
        component,
        _relationship(group, phishing, "uses", "APT29 has used spearphishing."),
        _relationship(group, powershell, "uses", "APT29 has used PowerShell."),
        _relationship(group, malware, "uses", "APT29 has used Cobalt Strike."),
        _relationship(malware, powershell, "uses"),
        _relationship(tool, lsass, "uses"),
        _relationship(campaign, group, "attributed-to"),
        _relationship(campaign, tool, "uses"),
        _relationship(mitigation, phishing, "mitigates"),
        _relationship(component, powershell, "detects", "Monitor executed commands."),
    ]


def _capec() -> dict:
    """The CAPEC STIX bundle: attack patterns (one deprecated), mitigations, no ATT&CK
    kill chain."""
    objects = _boilerplate()[:1] + [
        {
            "type": "marking-definition",
            "id": TLP_CLEAR,
            "spec_version": "2.1",
            "created": "2022-10-01T00:00:00.000Z",
            "name": "TLP:CLEAR",
            "definition_type": "tlp",
            "definition": {"tlp": "clear"},
        }
    ]

    def pattern(number: int, name: str, status: str = "Stable", **extra) -> dict:
        return {
            "type": "attack-pattern",
            "id": _id("attack-pattern", f"capec{number}"),
            "spec_version": "2.1",
            "created": "2014-06-23T00:00:00.000Z",
            "modified": "2025-09-09T00:00:00.000Z",
            "created_by_ref": MITRE,
            "object_marking_refs": [TLP_CLEAR],
            "name": name,
            "description": f"An adversary exploits weaknesses through {name.lower()}.",
            "external_references": [
                {
                    "source_name": "capec",
                    "external_id": f"CAPEC-{number}",
                    "url": f"https://capec.mitre.org/data/definitions/{number}.html",
                },
                {
                    "source_name": "cwe",
                    "external_id": "CWE-89",
                    "url": "https://cwe.mitre.org/data/definitions/89.html",
                },
            ],
            "x_capec_abstraction": "Standard",
            "x_capec_status": status,
            "x_capec_likelihood_of_attack": "High",
            "x_capec_typical_severity": "High",
            "x_capec_domains": ["Software"],
            **extra,
        }

    parent = pattern(248, "Command Injection")
    sql = pattern(66, "SQL Injection")
    blind = pattern(7, "Blind SQL Injection")
    old = pattern(1000, "Superseded Pattern", status="Deprecated")
    mitigation = {
        "type": "course-of-action",
        "id": _id("course-of-action", "capec-66"),
        "spec_version": "2.1",
        "created": "2014-06-23T00:00:00.000Z",
        "modified": "2025-09-09T00:00:00.000Z",
        "created_by_ref": MITRE,
        "object_marking_refs": [TLP_CLEAR],
        "name": "Use parameterized queries",
        "description": "Strongly typed parameterized queries prevent SQL injection.",
    }
    objects += [parent, sql, blind, old, mitigation]
    for source, target, kind in [
        (sql, parent, "subtechnique-of"),
        (blind, sql, "subtechnique-of"),
        (mitigation, sql, "mitigates"),
    ]:
        objects.append(
            {
                "type": "relationship",
                "id": _id("relationship", f"{source['id']}{target['id']}"),
                "spec_version": "2.1",
                "created": "2014-06-23T00:00:00.000Z",
                "modified": "2025-09-09T00:00:00.000Z",
                "created_by_ref": MITRE,
                "object_marking_refs": [TLP_CLEAR],
                "relationship_type": kind,
                "source_ref": source["id"],
                "target_ref": target["id"],
            }
        )
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _atlas() -> dict:
    """The OpenAEV catalog dataset (without its revoked technique) as a STIX 2.1 bundle
    with its author, a matrix and a mitigation."""
    identity = {
        "type": "identity",
        "id": _id("identity", "atlas"),
        "spec_version": "2.1",
        "created": CREATED,
        "modified": CREATED,
        "name": "MITRE ATLAS",
        "identity_class": "organization",
    }
    objects = [identity]
    for item in atlas_bundle()["objects"]:
        if item.get("revoked"):
            continue
        objects.append(
            {
                **item,
                "spec_version": "2.1",
                "created": CREATED,
                "modified": MODIFIED,
                "created_by_ref": identity["id"],
            }
        )
    tactics = [item for item in objects if item["type"] == "x-mitre-tactic"]
    techniques = [item for item in objects if item["type"] == "attack-pattern"]
    matrix = {
        "type": "x-mitre-matrix",
        "id": _id("x-mitre-matrix", "atlas"),
        "spec_version": "2.1",
        "created": CREATED,
        "modified": MODIFIED,
        "created_by_ref": identity["id"],
        "name": "ATLAS Machine Learning Threat Matrix",
        "description": "Adversarial tactics and techniques against AI systems.",
        "tactic_refs": [tactic["id"] for tactic in tactics],
        "external_references": [
            {
                "source_name": "mitre-atlas",
                "external_id": "ATLAS",
                "url": "https://atlas.mitre.org",
            }
        ],
    }
    mitigation = {
        "type": "course-of-action",
        "id": _id("course-of-action", "atlas-limit-release"),
        "spec_version": "2.1",
        "created": CREATED,
        "modified": MODIFIED,
        "created_by_ref": identity["id"],
        "name": "Limit Public Release of Information",
        "description": "Limit the public release of technical information about "
        "the AI system.",
        "external_references": [
            {
                "source_name": "mitre-atlas",
                "external_id": "AML.M0000",
                "url": "https://atlas.mitre.org/AML.M0000",
            }
        ],
    }
    objects += [matrix, mitigation]
    for index, technique in enumerate(techniques[:2]):
        objects.append(
            {
                "type": "relationship",
                "id": _id("relationship", f"atlas{index}"),
                "spec_version": "2.1",
                "created": CREATED,
                "modified": MODIFIED,
                "created_by_ref": identity["id"],
                "relationship_type": "mitigates",
                "source_ref": mitigation["id"],
                "target_ref": technique["id"],
            }
        )
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


ENTERPRISE_TACTICS = [
    ("TA0001", "Initial Access", "initial-access"),
    ("TA0002", "Execution", "execution"),
    ("TA0003", "Persistence", "persistence"),
    ("TA0005", "Stealth", "stealth"),
    ("TA0006", "Credential Access", "credential-access"),
]
ENTERPRISE_TECHNIQUES = [
    ("T1566", "Phishing", "initial-access", ""),
    ("T1566.001", "Spearphishing Attachment", "initial-access", "T1566"),
    ("T1059", "Command and Scripting Interpreter", "execution", ""),
    ("T1059.001", "PowerShell", "execution", "T1059"),
    ("T1547", "Boot or Logon Autostart Execution", "persistence", ""),
    ("T1027", "Obfuscated Files or Information", "stealth", ""),
    ("T1003", "OS Credential Dumping", "credential-access", ""),
    ("T1003.001", "LSASS Memory", "credential-access", "T1003"),
]
MOBILE_TACTICS = [
    ("TA0027", "Initial Access", "initial-access"),
    ("TA0041", "Execution", "execution"),
    ("TA0032", "Discovery", "discovery"),
]
MOBILE_TECHNIQUES = [
    ("T1456", "Drive-By Compromise", "initial-access", ""),
    ("T1575", "Native API", "execution", ""),
    ("T1426", "System Information Discovery", "discovery", ""),
]
ICS_TACTICS = [
    ("TA0108", "Initial Access", "initial-access"),
    ("TA0104", "Execution", "execution"),
    ("TA0106", "Evasion", "evasion"),
]
ICS_TECHNIQUES = [
    ("T0817", "Drive-by Compromise", "initial-access", ""),
    ("T0807", "Command-Line Interface", "execution", ""),
    ("T0820", "Exploitation for Evasion", "evasion", ""),
]


def _json(bundle: dict) -> bytes:
    return json.dumps(bundle, indent=2).encode()


def _attack_data() -> Repo:
    bundles = {
        "enterprise-attack/enterprise-attack.json": _attack(
            "enterprise-attack",
            "mitre-attack",
            "techniques",
            "mitre-attack",
            ENTERPRISE_TACTICS,
            ENTERPRISE_TECHNIQUES,
            extras=True,
        ),
        "mobile-attack/mobile-attack.json": _attack(
            "mobile-attack",
            "mitre-mobile-attack",
            "techniques",
            "mitre-mobile-attack",
            MOBILE_TACTICS,
            MOBILE_TECHNIQUES,
            extras=False,
        ),
        "ics-attack/ics-attack.json": _attack(
            "ics-attack",
            "mitre-ics-attack",
            "techniques",
            "mitre-ics-attack",
            ICS_TACTICS,
            ICS_TECHNIQUES,
            extras=False,
        ),
    }
    return Repo(
        files={path: _json(bundle) for path, bundle in bundles.items()},
        branch="master",
        description="STIX data for MITRE ATT&CK",
    )


def _cti() -> Repo:
    # The legacy ATT&CK location the OpenAEV mitre-attack collector reads
    # (github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json)
    enterprise = _attack(
        "enterprise-attack",
        "mitre-attack",
        "techniques",
        "mitre-attack",
        ENTERPRISE_TACTICS,
        ENTERPRISE_TECHNIQUES,
        extras=True,
    )
    return Repo(
        files={
            "capec/2.1/stix-capec.json": _json(_capec()),
            "enterprise-attack/enterprise-attack.json": _json(enterprise),
        },
        branch="master",
        description="Cyber Threat Intelligence Repository expressed in STIX",
    )


def _atlas_data() -> Repo:
    return Repo(
        files={"dist/stix-atlas.json": _json(_atlas())},
        branch="main",
        description="MITRE ATLAS Navigator data",
    )


GITHUB_REPOS = {
    "mitre-attack/attack-stix-data": _attack_data,
    "mitre/cti": _cti,
    "mitre-atlas/atlas-navigator-data": _atlas_data,
}
