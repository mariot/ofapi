"""ReversingLabs: Spectra Intelligence (TitaniumCloud, data.reversinglabs.com) and a
Spectra Analyze appliance, read by the OpenCTI reversinglabs-malware-presence,
reversinglabs-spectra-intel-submission and reversinglabs-spectra-analyze connectors.

The appliance answers like the older routes of app/main.py (same factories), on its own
host. Appliance and cloud paths do not overlap, so one prefix serves both.
"""

import re
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, File, Form, Query, Request, UploadFile

from app.api.reversinglabs import (
    AnalysisResponseFactory,
    DomainResponseFactory,
    DownloadedFilesResponseFactory,
    HashClassificationFactory,
    ReportIntelligenceResponseFactory,
    ReportResponseFactory,
    ResolutionResponseFactory,
    UploadDetailFactory,
    UrlsResponseFactory,
)
from app.api.utils import remove_private_attributes
from app.fake import fake

HOSTS = ["data.reversinglabs.com", "spectra-analyze.staticfire.test"]
router = APIRouter(prefix="/reversinglabs", tags=["ReversingLabs"])

PLATFORMS = ["Win32", "Win64", "Script-JS", "Android"]
TYPES = ["Trojan", "Downloader", "Ransomware", "Backdoor"]


def _threat_name() -> str:
    family = fake.malware_family().replace(" ", "")
    return f"{fake.random_element(PLATFORMS)}.{fake.random_element(TYPES)}.{family}"


def _iso(delta: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _top_threats() -> list[dict]:
    return [
        {"threat_name": _threat_name(), "threat_level": fake.random_int(3, 5)}
        for _ in range(2)
    ]


# Spectra Intelligence (TitaniumCloud)


@router.get("/api/databrowser/malware_presence/query/{hash_type}/{hash_value}")
async def malware_presence(hash_type: str, hash_value: str) -> dict:
    """The reputation of a hash: always a known malicious sample."""
    family = fake.malware_family().replace(" ", "")
    return {
        "rl": {
            "malware_presence": {
                "status": "MALICIOUS",
                "query_hash": {hash_type: hash_value},
                "threat_level": fake.random_int(3, 5),
                "trust_factor": fake.random_int(3, 5),
                "first_seen": _iso(timedelta(days=90)),
                "last_seen": _iso(timedelta(days=1)),
                "reason": "antivirus",
                "scanner_count": 40,
                "scanner_match": 31,
                "scanner_percent": 77.5,
                "threat_name": f"Win32.Trojan.{family}",
                "classification": {
                    "platform": "Win32",
                    "type": "Trojan",
                    "family_name": family,
                    "is_generic": False,
                },
            }
        }
    }


@router.get("/api/databrowser/rldata/query/{hash_type}/{hash_value}")
async def file_analysis(hash_type: str, hash_value: str) -> dict:
    """The static analysis of a sample: its type, container and interesting strings."""
    # a sample looked up by sha1 is itself the container (no further container)
    sha1 = hash_value if hash_type == "sha1" else fake.sha1()
    containers = [sha1] if hash_type == "sha1" else [sha1, fake.sha1()]
    return {
        "rl": {
            "sample": {
                "sha1": sha1,
                "sample_size": fake.random_int(10000, 900000),
                "sample_type": "PE/Exe",
                "xref": {"sample_type": "PE+/Exe"},
                "relationships": {"container_sample_sha1": containers},
                "analysis": {
                    "entries": [
                        {
                            "tc_report": {
                                "interesting_strings": [
                                    {
                                        "category": "ipv4",
                                        "values": [fake.ipv4_public()],
                                    },
                                    {"category": "url", "values": [fake.url()]},
                                    {
                                        "category": "domain",
                                        "values": [fake.domain_name()],
                                    },
                                    {"category": "registry", "values": ["HKLM"]},
                                ]
                            }
                        }
                    ]
                },
            }
        }
    }


@router.post("/api/networking/reputation/v1/query/json")
async def network_reputation(request: Request) -> dict:
    """The reputation of network locations: malicious, seen by third parties."""
    body = await request.json()
    query = body.get("rl", {}).get("query", {})
    locations = [
        item["network_location"] if isinstance(item, dict) else item
        for item in query.get("network_locations", [])
    ]
    entries = []
    for location in locations:
        if location.startswith(("http://", "https://")):
            kind = "url"
        elif re.fullmatch(r"[0-9.]+", location):
            kind = "ip"
        else:
            kind = "domain"
        entries.append(
            {
                "requested_network_location": location,
                "type": kind,
                "classification": "malicious",
                "associated_malware": True,
                "third_party_reputations": {
                    "total": 20,
                    "malicious": fake.random_int(3, 12),
                    "clean": 5,
                    "undetected": 3,
                },
            }
        )
    return {"rl": {"entries": entries}}


async def _requested(request: Request) -> str:
    body = await request.json()
    query = body.get("rl", {}).get("query", {})
    return str(query.get("url") or query.get("domain") or query.get("ip") or "")


@router.post("/api/networking/url/v1/report/query/json")
async def url_report(request: Request) -> dict:
    """A URL report with its top threats."""
    return {
        "rl": {
            "requested_url": await _requested(request),
            "analysis": {"top_threats": _top_threats(), "statistics": {"malicious": 5}},
        }
    }


@router.post("/api/networking/domain/report/v1/query/json")
async def domain_report(request: Request) -> dict:
    """A domain report with its top threats."""
    return {
        "rl": {
            "requested_domain": await _requested(request),
            "top_threats": _top_threats(),
        }
    }


@router.post("/api/networking/ip/report/v1/query/json")
async def ip_report(request: Request) -> dict:
    """An IP report with its top threats."""
    return {
        "rl": {
            "requested_ip": await _requested(request),
            "top_threats": _top_threats(),
        }
    }


@router.post("/api/dynamic/analysis/analyze/v1/query/json")
async def detonate(request: Request) -> dict:
    """Start a sandbox analysis of a hash or a URL."""
    rl = (await request.json()).get("rl", {})
    analysis_id = fake.sha1()[:12]
    if rl.get("url"):
        sha1 = fake.sha1()
        return {
            "rl": {
                "url": rl["url"],
                "sha1": sha1,
                "analysis_id": analysis_id,
                "status": "analysis started",
            }
        }
    requested = rl.get("sha1") or rl.get("sha256") or rl.get("md5")
    return {
        "rl": {
            "requested_hash": requested,
            "analysis_id": analysis_id,
            "status": "analysis started",
        }
    }


@router.get("/api/dynamic/analysis/report/v1/query/{path:path}")
async def dynamic_report(path: str) -> dict:
    """The sandbox report of a sample (``<hash type>/<hash>/<id>``) or URL
    (``url/sha1/<sha1>/<id>`` or ``url/base64/<url>/<id>``)."""
    parts = path.split("/")
    report = {
        "classification": "MALICIOUS",
        "risk_score": fake.random_int(7, 10),
        "sha256": fake.sha256(),
        "platform": "windows10",
        "configuration": "Windows 10 x64, Office 2016, Adobe Reader",
        "analysis_id": parts[3] if len(parts) > 3 else fake.sha1()[:12],
        "analysis_time": _iso(timedelta(minutes=10)),
        "analysis_duration": fake.random_int(120, 600),
        "threat_names": [{"threat_name": _threat_name()}],
        "signatures": [
            {"description": fake.sentence(), "risk_factor": fake.random_int(1, 10)}
            for _ in range(3)
        ],
        "screenshots": f"https://data.reversinglabs.com/screens/{fake.sha1()[:8]}.zip",
        "dropped_files_url": f"https://data.reversinglabs.com/dropped/{fake.sha1()[:8]}",
        "pcap": f"https://data.reversinglabs.com/pcap/{fake.sha1()[:8]}",
        "memory_strings": f"https://data.reversinglabs.com/mem/{fake.sha1()[:8]}",
        "mitre_attack": {
            "matrix_list": [
                {
                    "tactics": {
                        "tactic_list": [
                            {
                                "id": "TA0002",
                                "name": "Execution",
                                "techniques": {
                                    "technique_list": [
                                        {"id": "T1059.001", "name": "PowerShell"},
                                        {"id": "T1204", "name": "User Execution"},
                                    ]
                                },
                            }
                        ]
                    }
                }
            ]
        },
        "dropped_files": [
            {
                "classification": "MALICIOUS",
                "file_name": fake.file_name(extension="exe"),
                "sha1": fake.sha1(),
                "sha256": fake.sha256(),
            }
        ],
    }
    rl: dict = {"report": report}
    if parts[0] == "url":
        rl["requested_sha1_url"] = parts[2] if len(parts) > 2 else ""
    else:
        rl["requested_hash"] = parts[1] if len(parts) > 1 else ""
    return {"rl": rl}


# Spectra Analyze appliance


@router.get("/api/network-threat-intel/ip/{ip}/downloaded_files/")
async def ip_downloaded_files(ip: str) -> dict:
    """Files downloaded from an address."""
    return asdict(DownloadedFilesResponseFactory(requested_ip=ip))


@router.get("/api/network-threat-intel/ip/{ip}/report/")
async def ip_analyze_report(ip: str) -> dict:
    """The report of an address."""
    return remove_private_attributes(asdict(ReportResponseFactory(requested_ip=ip)))


@router.get("/api/network-threat-intel/ip/{ip}/resolutions/")
async def ip_resolutions(ip: str) -> dict:
    """The domains an address resolves to."""
    return asdict(ResolutionResponseFactory(requested_ip=ip))


@router.get("/api/network-threat-intel/ip/{ip}/urls/")
async def ip_urls(ip: str) -> dict:
    """The URLs hosted on an address."""
    return asdict(UrlsResponseFactory(requested_ip=ip))


@router.get("/api/network-threat-intel/domain/{domain}/")
async def analyze_domain(domain: str) -> dict:
    """The report of a domain."""
    return remove_private_attributes(
        asdict(DomainResponseFactory(requested_domain=domain))
    )


@router.get("/api/network-threat-intel/url/")
async def analyze_url(url: str) -> dict:
    """The report of a URL."""
    return AnalysisResponseFactory(requested_url=url).to_dict()


@router.post("/api/uploads/", status_code=201)
async def upload(
    file: Annotated[UploadFile | None, File()] = None,
    url: Annotated[str | None, Form()] = None,
) -> dict:
    """A file or URL submission."""
    filename = file.filename if file else url
    return {
        "code": 201,
        "message": "Done.",
        "detail": asdict(UploadDetailFactory(filename=filename)),
    }


@router.get("/api/uploads/v2/url-samples/{task_id}")
@router.get("/api/uploads/v2/url-samples/{task_id}/")
async def url_task() -> dict:
    """The status of a submitted URL: processed, with its report."""
    return {
        "processing_status": "complete",
        "message": "Processing complete.",
        "report": remove_private_attributes(
            asdict(ReportIntelligenceResponseFactory())
        ),
    }


@router.get("/api/samples/v3/{hash_value}/classification/")
async def hash_classification(hash_value: str) -> dict:
    """The classification of a sample."""
    return remove_private_attributes(asdict(HashClassificationFactory(sha1=hash_value)))


@router.post("/api/samples/status/")
async def samples_status(request: Request, status: str = Query("processed")) -> dict:
    """The processing status of samples."""
    form = await request.form()
    return {
        "hash_type": "sha1",
        "results": [
            {"hash_value": value, "status": status}
            for value in form.getlist("hash_values")
        ],
    }


@router.post("/api/samples/v2/list/details/")
async def samples_details() -> dict:
    """The detailed report of a sample."""
    return {
        "count": 1,
        "next": None,
        "previous": None,
        "results": [
            remove_private_attributes(asdict(ReportIntelligenceResponseFactory()))
        ],
    }
