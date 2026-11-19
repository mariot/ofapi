"""Small public-catalog datasets for the OpenAEV catalog collectors.

Each dataset is tiny but exercises the collector's filters: a revoked technique and a
sub-technique for MITRE ATLAS, a CVE without CVSS v3.1 for NVD, a native and a community
payload for the OpenAEV payload repository.
"""

ATLAS_SOURCE = "mitre-atlas"


def _atlas_ref(external_id: str) -> list[dict]:
    return [
        {
            "source_name": ATLAS_SOURCE,
            "external_id": external_id,
            "url": f"https://atlas.mitre.org/{external_id}",
        }
    ]


def atlas_bundle() -> dict:
    """ATLAS as ATT&CK-compatible STIX: 2 tactics, 3 techniques, 1 revoked."""
    recon = "x-mitre-tactic--0f5b4c4e-0000-4000-8000-000000000001"
    access = "x-mitre-tactic--0f5b4c4e-0000-4000-8000-000000000002"
    parent = "attack-pattern--0f5b4c4e-0000-4000-8000-000000000101"
    sub = "attack-pattern--0f5b4c4e-0000-4000-8000-000000000102"
    other = "attack-pattern--0f5b4c4e-0000-4000-8000-000000000103"
    revoked = "attack-pattern--0f5b4c4e-0000-4000-8000-000000000199"

    def technique(stix_id, external_id, name, phase, **extra):
        return {
            "type": "attack-pattern",
            "id": stix_id,
            "name": name,
            "description": f"{name} (ofapi dataset)",
            "external_references": _atlas_ref(external_id),
            "kill_chain_phases": [
                {"kill_chain_name": ATLAS_SOURCE, "phase_name": phase}
            ],
            **extra,
        }

    return {
        "type": "bundle",
        "id": "bundle--0f5b4c4e-0000-4000-8000-000000000000",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": recon,
                "name": "Reconnaissance",
                "x_mitre_shortname": "reconnaissance",
                "description": "Gather information about the AI system (ofapi dataset)",
                "external_references": _atlas_ref("AML.TA0002"),
            },
            {
                "type": "x-mitre-tactic",
                "id": access,
                "name": "AI Model Access",
                "x_mitre_shortname": "ai-model-access",
                "description": "Gain access to the AI model (ofapi dataset)",
                "external_references": _atlas_ref("AML.TA0000"),
            },
            technique(
                parent, "AML.T0000", "Search Open Technical Databases", "reconnaissance"
            ),
            technique(
                sub,
                "AML.T0000.000",
                "Journals and Conference Proceedings",
                "reconnaissance",
            ),
            technique(
                other, "AML.T0040", "AI Model Inference API Access", "ai-model-access"
            ),
            technique(
                revoked,
                "AML.T9999",
                "Revoked Technique",
                "reconnaissance",
                revoked=True,
            ),
            {
                "type": "relationship",
                "id": "relationship--0f5b4c4e-0000-4000-8000-000000000201",
                "relationship_type": "subtechnique-of",
                "source_ref": sub,
                "target_ref": parent,
            },
        ],
    }


def _nvd_cve(cve_id: str, score: float | None, cwe: str | None) -> dict:
    cve = {
        "id": cve_id,
        "sourceIdentifier": "cve@mitre.org",
        "published": "2026-01-15T10:00:00.000",
        "lastModified": "2026-02-01T10:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": f"{cve_id} (ofapi dataset)"}],
        "metrics": {},
        "references": [{"url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}],
    }
    if score is not None:
        cve["metrics"]["cvssMetricV31"] = [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "baseScore": score,
                    "baseSeverity": "CRITICAL",
                },
            }
        ]
    if cwe:
        cve["weaknesses"] = [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [{"lang": "en", "value": cwe}],
            }
        ]
    return {"cve": cve}


# CVE-2099-*: identifiers that cannot collide with real CVEs a platform may also hold
def nvd_cves(start_index: int = 0, results_per_page: int = 2000) -> dict:
    """NVD CVE API 2.0 page: 2 CVEs with CVSS v3.1 and 1 without (skipped)."""
    vulnerabilities = [
        _nvd_cve("CVE-2099-90001", 9.8, "CWE-79"),
        _nvd_cve("CVE-2099-90002", 7.5, None),
        _nvd_cve("CVE-2099-90003", None, "CWE-89"),
    ]
    page = vulnerabilities[start_index : start_index + results_per_page]
    return {
        "resultsPerPage": len(page),
        "startIndex": start_index,
        "totalResults": len(vulnerabilities),
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-11-19T10:00:00.000",
        "vulnerabilities": page,
    }


def nvd_source(source_identifier: str) -> dict:
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "sources": [
            {"name": "NIST (ofapi dataset)", "sourceIdentifiers": [source_identifier]}
        ],
    }


def _payload(external_id: str, name: str, native: bool) -> dict:
    return {
        "native_collection": native,
        "payload_tags": [],
        "payload_attack_patterns": [],
        "payload_information": {
            "payload_type": "Command",
            "payload_name": name,
            "payload_description": f"{name} (ofapi dataset)",
            "payload_source": "COMMUNITY",
            "payload_status": "VERIFIED",
            "payload_external_id": external_id,
            "payload_platforms": ["Linux"],
            "payload_execution_arch": "ALL_ARCHITECTURES",
            "payload_expectations": ["PREVENTION", "DETECTION"],
            "payload_domains": [],
            "payload_tags": [],
            "payload_attack_patterns": [],
            "command_executor": "sh",
            "command_content": f"echo {external_id}",
        },
    }


def openaev_payloads_manifest() -> list[dict]:
    """Payload repository manifest: one native and one community Command payload."""
    return [
        _payload("ofapi-payload-native-0001", "ofapi native payload", True),
        _payload("ofapi-payload-community-0001", "ofapi community payload", False),
    ]
