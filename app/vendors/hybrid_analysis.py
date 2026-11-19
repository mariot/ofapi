"""Hybrid Analysis (Falcon Sandbox) public API v2: hash search, URL and file submission,
report state and summary, read by the OpenCTI hybrid-analysis-sandbox connector."""

import re
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["hybrid-analysis.com"]
router = APIRouter(prefix="/hybrid-analysis", tags=["Hybrid Analysis"])

ENVIRONMENT_ID = 110
ENVIRONMENT = "Windows 10 64 bit"
TECHNIQUES = [
    ("Process Injection", "T1055"),
    ("Command and Scripting Interpreter", "T1059"),
    ("Query Registry", "T1012"),
]


def _report_id(sha256: str) -> str:
    return f"{sha256}:{ENVIRONMENT_ID}"


def _summary(report_id: str) -> dict:
    """A malicious sample's summary, on the SHA-256 the report id is built on."""
    sha256 = report_id.split(":")[0]
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        sha256 = fake.sha256()
    started = datetime.now(UTC) - timedelta(hours=fake.random_int(1, 48))
    return {
        "job_id": report_id,
        "sha256": sha256,
        "sha1": fake.sha1(),
        "md5": fake.md5(),
        "submit_name": f"{fake.word()}.exe",
        "size": fake.random_int(20_000, 900_000),
        "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
        "type_short": ["peexe", "executable"],
        "environment_id": ENVIRONMENT_ID,
        "environment_description": ENVIRONMENT,
        "verdict": "malicious",
        "threat_score": fake.random_int(60, 100),
        "threat_level": 2,
        "av_detect": fake.random_int(20, 80),
        "analysis_start_time": started.strftime("%Y-%m-%d %H:%M:%S"),
        "domains": [fake.domain_name(), fake.domain_name()],
        "hosts": [fake.ipv4_public(), fake.ipv4_public(), fake.ipv6()],
        "mitre_attcks": [
            {
                "tactic": "Defense Evasion",
                "technique": technique,
                "attck_id": attck_id,
                "malicious_identifiers_count": 1 if index < 2 else 0,
                "suspicious_identifiers_count": 0,
                "informative_identifiers_count": 3,
            }
            for index, (technique, attck_id) in enumerate(TECHNIQUES)
        ],
        "extracted_files": [
            {
                "name": f"{fake.word()}.dll",
                "file_path": "%TEMP%",
                "file_size": 40960,
                "size": 40960,
                "md5": fake.md5(),
                "sha1": fake.sha1(),
                "sha256": fake.sha256(),
                "threat_level": 1,
                "threat_level_readable": "suspicious",
                "type_tags": ["pedll", "executable"],
            },
            {
                "name": "benign.txt",
                "size": 12,
                "md5": fake.md5(),
                "sha1": fake.sha1(),
                "sha256": fake.sha256(),
                "threat_level": 0,
                "type_tags": ["text"],
            },
        ],
    }


@router.get("/api/v2/search/hash")
async def search_hash(hash: str) -> dict:  # noqa: A002
    """The analyses known for a hash."""
    sha256 = hash if len(hash) == 64 else fake.sha256()
    return {
        "sha256s": [sha256],
        "reports": [
            {
                "id": _report_id(sha256),
                "environment_id": ENVIRONMENT_ID,
                "state": "SUCCESS",
                "verdict": "malicious",
            }
        ],
    }


@router.get("/api/v2/report/{report_id}/state")
async def report_state(report_id: str) -> dict:  # noqa: ARG001
    """A finished analysis."""
    return {"state": "SUCCESS"}


@router.get("/api/v2/report/{report_id}/summary")
async def report_summary(report_id: str) -> dict:
    """The summary of an analysis."""
    return _summary(report_id)


@router.post("/api/v2/submit/url")
async def submit_url(request: Request) -> dict:
    """A URL submission starts an analysis."""
    await request.body()
    sha256 = fake.sha256()
    return {
        "job_id": _report_id(sha256),
        "submission_id": fake.sha1()[:24],
        "environment_id": ENVIRONMENT_ID,
        "sha256": sha256,
    }


@router.post("/api/v2/submit/file")
async def submit_file(request: Request) -> dict:
    """A file submission starts an analysis."""
    await request.body()
    sha256 = fake.sha256()
    return {
        "job_id": _report_id(sha256),
        "submission_id": fake.sha1()[:24],
        "environment_id": ENVIRONMENT_ID,
        "sha256": sha256,
    }
