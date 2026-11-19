"""NIST NVD: the CVE and CPE match APIs (2.0), read by the OpenCTI cve connector.

The prefix differs from the older ``/nvd`` fake of ``app/main.py`` (reached by URL
settings) whose CVEs are too bare for a connector reading the real API shape.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["services.nvd.nist.gov"]
router = APIRouter(prefix="/nvd-cve-api", tags=["NVD"])

CPE_VERSIONS = ["1.0", "2.4.1", "5.2", "10.0.1"]


def _timestamp(delta_days: int) -> str:
    moment = datetime.now(UTC) - timedelta(days=delta_days)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}"


def _cvss_v31() -> dict:
    return {
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "HIGH",
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL",
        },
        "exploitabilityScore": 3.9,
        "impactScore": 5.9,
    }


def _cvss_v2() -> dict:
    return {
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {
            "version": "2.0",
            "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "accessVector": "NETWORK",
            "accessComplexity": "LOW",
            "authentication": "NONE",
            "confidentialityImpact": "PARTIAL",
            "integrityImpact": "PARTIAL",
            "availabilityImpact": "PARTIAL",
            "baseScore": 7.5,
        },
        "baseSeverity": "HIGH",
        "exploitabilityScore": 10.0,
        "impactScore": 6.4,
        "acInsufInfo": False,
        "obtainAllPrivilege": False,
        "obtainUserPrivilege": False,
        "obtainOtherPrivilege": False,
        "userInteractionRequired": False,
    }


def _cvss_v40() -> dict:
    return {
        "source": "nvd@nist.gov",
        "type": "Secondary",
        "cvssData": {
            "version": "4.0",
            "vectorString": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            ),
            "baseScore": 9.3,
            "baseSeverity": "CRITICAL",
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "attackRequirements": "NONE",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "vulnConfidentialityImpact": "HIGH",
            "vulnIntegrityImpact": "HIGH",
            "vulnAvailabilityImpact": "HIGH",
            "subConfidentialityImpact": "NONE",
            "subIntegrityImpact": "NONE",
            "subAvailabilityImpact": "NONE",
        },
    }


def _vulnerability(index: int) -> dict:
    metrics: dict = {"cvssMetricV31": [_cvss_v31()], "cvssMetricV2": [_cvss_v2()]}
    if index % 2:
        metrics["cvssMetricV40"] = [_cvss_v40()]
    if index == 0:
        metrics["ssvcV203"] = [
            {
                "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                "type": "Secondary",
                "ssvcData": {
                    "options": [
                        {"exploitation": "poc"},
                        {"automatable": "yes"},
                        {"technicalImpact": "total"},
                    ]
                },
            }
        ]
    # An unscored CVE: the connector skips it
    if index == 4:
        metrics = {}
    published = _timestamp(2 + index)
    return {
        "cve": {
            "id": fake.cve_id(),
            "sourceIdentifier": "security@vendor.example",
            "published": published,
            "lastModified": _timestamp(1),
            "vulnStatus": "Analyzed",
            "cveTags": [],
            "descriptions": [
                {"lang": "en", "value": fake.paragraph(nb_sentences=3)},
                {"lang": "es", "value": fake.paragraph(nb_sentences=2)},
            ],
            "metrics": metrics,
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [
                        {"lang": "en", "value": f"CWE-{fake.random_int(20, 900)}"}
                    ],
                }
            ],
            "references": [
                {
                    "url": fake.url(),
                    "source": "security@vendor.example",
                    "tags": ["Vendor Advisory"],
                }
                for _ in range(2)
            ],
        }
    }


@router.get("/rest/json/cves/2.0")
async def cves(startIndex: int = Query(0)) -> dict:  # noqa: N803
    """One page of CVEs, one of them without any metric (the connector skips it)."""
    vulnerabilities = [_vulnerability(i) for i in range(5)] if startIndex == 0 else []
    return {
        "resultsPerPage": len(vulnerabilities),
        "startIndex": startIndex,
        "totalResults": 5,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": _timestamp(0),
        "vulnerabilities": vulnerabilities,
    }


@router.get("/rest/json/cpematch/2.0")
async def cpe_match(startIndex: int = Query(0)) -> dict:  # noqa: N803
    """The CPE names matching a CVE, in one page."""
    vendor, product = fake.word(), fake.word()
    match_strings = []
    if startIndex == 0:
        for version in CPE_VERSIONS[:3]:
            name = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
            match_strings.append(
                {
                    "matchString": {
                        "matchCriteriaId": fake.uuid4().upper(),
                        "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
                        "versionEndExcluding": "10.0.2",
                        "lastModified": _timestamp(1),
                        "cpeLastModified": _timestamp(1),
                        "created": _timestamp(30),
                        "status": "Active",
                        "matches": [
                            {"cpeName": name, "cpeNameId": fake.uuid4().upper()}
                        ],
                    }
                }
            )
    return {
        "resultsPerPage": len(match_strings),
        "startIndex": startIndex,
        "totalResults": len(match_strings),
        "format": "NVD_CPEMatchString",
        "version": "2.0",
        "timestamp": _timestamp(0),
        "matchStrings": match_strings,
    }
