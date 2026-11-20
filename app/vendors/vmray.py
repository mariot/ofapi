"""VMRay Platform REST API (``/rest/...``), read by the OpenCTI vmray-platform import
connector (submissions, samples, IOCs, VTIs, MITRE techniques) and by the vmray-analyzer
enrichment connector (it submits an artifact and downloads the analysis archives)."""

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request, Response

from app.fake import fake
from app.vendors.fixtures import _pdf, _report_text

HOSTS = ["cloud.vmray.com", "*.cloud.vmray.com"]
router = APIRouter(prefix="/vmray", tags=["VMRay"])

# sample id -> (verdict, ids of its child samples)
SAMPLES = {
    1001: ("malicious", [1002]),
    1002: ("malicious", []),
    1003: ("suspicious", []),
    1004: ("clean", []),
}
ANALYSIS_IDS = [5001, 5002]
THREATS = ["Emotet", "AgentTesla", "Lokibot", "Remcos"]


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _ok(data) -> dict:
    return {"result": "ok", "data": data}


def _time(minutes_ago: int) -> str:
    return (_now() - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S")


@router.get("/rest/system_info")
async def system_info() -> dict:
    return _ok({"system_version": "6.0.0", "system_is_cloud": True})


@router.get("/rest/submission")
async def submissions() -> dict:
    return _ok(
        [
            {
                "submission_id": 2000 + sample_id,
                "submission_sample_id": sample_id,
                "submission_verdict": verdict,
                "submission_finished": True,
                "submission_has_errors": False,
                "submission_finish_time": _time(60 - n),
            }
            for n, (sample_id, (verdict, _)) in enumerate(SAMPLES.items())
        ]
    )


@router.get("/rest/submission/sample/{sample_id}")
async def sample_submissions(sample_id: int) -> dict:
    return _ok([_submission(sample_id, finished=True)])


def _submission(sample_id: int, finished: bool = True) -> dict:
    return {
        "submission_id": 2000 + sample_id,
        "submission_sample_id": sample_id,
        "submission_finished": finished,
        "submission_has_errors": False,
        "submission_finish_time": _time(30),
    }


@router.get("/rest/submission/{submission_id}")
async def get_submission(submission_id: int) -> dict:
    return _ok(_submission(submission_id - 2000))


def _sample(sample_id: int) -> dict:
    verdict, children = SAMPLES.get(sample_id, ("malicious", []))
    return {
        "sample_id": sample_id,
        "sample_verdict": verdict,
        "sample_score": 100 if verdict == "malicious" else 60,
        "sample_filename": f"{fake.word()}.exe",
        "sample_created": _time(120),
        "sample_webif_url": f"https://cloud.vmray.com/user/sample/view?id={sample_id}",
        "sample_threat_names": [fake.random_element(THREATS), "Trojan.Generic"],
        "sample_classifications": ["Trojan", "Downloader"],
        "sample_child_sample_ids": children,
        "sample_sha256hash": fake.sha256(),
    }


@router.get("/rest/sample/sha256/{sha256}")
async def sample_by_hash(sha256: str) -> dict:  # noqa: ARG001
    return _ok([_sample(1001)])


@router.get("/rest/sample/{sample_id}")
async def get_sample(sample_id: int) -> dict:
    return _ok(_sample(sample_id))


def _common(verdict: str = "malicious") -> dict:
    return {
        "verdict": verdict,
        "ioc": True,
        "categories": ["Network"],
        "analysis_ids": ANALYSIS_IDS,
        "threat_names": [fake.random_element(THREATS)],
        "classifications": ["Trojan"],
    }


@router.get("/rest/sample/{sample_id}/iocs")
async def sample_iocs(sample_id: int) -> dict:  # noqa: ARG001
    """IOCs of every kind the connector maps, one malicious and one clean domain."""
    country = fake.random_element(["Germany", "Russia", "United States"])
    iocs = {
        "files": [
            {
                **_common(),
                "filename": f"{fake.word()}.dll",
                "file_size": fake.random_int(10000, 900000),
                "mime_type": "application/x-dosexec",
                "hashes": [
                    {
                        "md5_hash": fake.md5(),
                        "sha1_hash": fake.sha1(),
                        "sha256_hash": fake.sha256(),
                    }
                ],
            }
        ],
        "processes": [
            {
                **_common(),
                "cmd_line": f"cmd.exe /c {fake.word()}.bat",
                "process_name": "cmd",
            }
        ],
        "domains": [
            {
                **_common(),
                "domain": fake.domain_name(),
                "protocols": ["DNS", "HTTP"],
                "original_domains": [fake.domain_name()],
                "ip_addresses": [fake.ipv4_public()],
                "countries": [country],
                "country_codes": ["DE"],
            },
            {**_common("clean"), "domain": fake.domain_name()},
        ],
        "urls": [
            {
                **_common(),
                "url": f"http://{fake.domain_name()}/gate.php",
                "original_urls": [fake.url()],
                "ip_addresses": [fake.ipv4_public()],
                "countries": [country],
                "country_codes": ["DE"],
            }
        ],
        "ips": [
            {
                **_common(),
                "ip_address": fake.ipv4_public(),
                "protocols": ["TCP"],
                "domains": [fake.domain_name()],
                "countries": [country],
                "country_codes": ["DE"],
            }
        ],
        "mutexes": [
            {**_common(), "mutex_name": f"Global\\{fake.word()}{fake.random_int()}"}
        ],
        "registry": [
            {
                **_common(),
                "reg_key_name": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\"
                f"CurrentVersion\\Run\\{fake.word()}",
            }
        ],
        "emails": [
            {
                **_common(),
                "subject": fake.sentence(),
                "sender": f"{fake.name()} <{fake.email()}>",
            }
        ],
    }
    return _ok({"iocs": iocs})


@router.get("/rest/sample/{sample_id}/vtis")
async def sample_vtis(sample_id: int) -> dict:  # noqa: ARG001
    return _ok(
        {
            "threat_indicators": [
                {
                    "analysis_ids": ANALYSIS_IDS,
                    "category": "Persistence",
                    "operation": "Installs system startup script or application",
                    "score": 5,
                },
                {
                    "analysis_ids": ANALYSIS_IDS[:1],
                    "category": "Network Connection",
                    "operation": "Connects to a suspicious host",
                    "score": 4,
                },
            ]
        }
    )


@router.get("/rest/sample/{sample_id}/mitre_attack")
async def sample_mitre(sample_id: int) -> dict:  # noqa: ARG001
    return _ok(
        {
            "mitre_attack_techniques": [
                {
                    "analysis_ids": ANALYSIS_IDS,
                    "technique_id": "T1547.001",
                    "technique": "Registry Run Keys / Startup Folder",
                    "tactics": ["Persistence", "Privilege Escalation"],
                    "score": 5,
                },
                {
                    "analysis_ids": ANALYSIS_IDS[:1],
                    "technique_id": "T1071",
                    "technique": "Application Layer Protocol",
                    "tactics": ["Command and Control"],
                    "score": 4,
                },
            ]
        }
    )


@router.post("/rest/sample/submit")
async def submit_sample(request: Request) -> dict:  # noqa: ARG001
    """A sample submitted for analysis (multipart ``sample_file``): finished at once."""
    sample_id = fake.random_int(2000, 9000)
    return _ok(
        {
            "errors": [],
            "samples": [{"sample_id": sample_id}],
            "submissions": [{"submission_id": 2000 + sample_id}],
        }
    )


@router.get("/rest/analysis/submission/{submission_id}")
async def submission_analyses(submission_id: int) -> dict:  # noqa: ARG001
    return _ok([{"analysis_id": analysis_id} for analysis_id in ANALYSIS_IDS])


def _stix_objects() -> dict:
    """The observables of an analysis, as a STIX 2.0 observed-data ``objects`` map."""
    values = [
        ("url", f"http://{fake.domain_name()}/payload.bin"),
        ("domain-name", fake.domain_name()),
        ("ipv4-addr", fake.ipv4_public()),
        ("ipv4-addr", "10.0.2.15"),
    ]
    return {
        str(n): {"type": kind, "value": value} for n, (kind, value) in enumerate(values)
    }


@router.get("/rest/analysis/{analysis_id}/archive")
async def analysis_archive(analysis_id: int) -> Response:  # noqa: ARG001
    """The analysis archive: report PDF, behavior, STIX and malware configurations."""
    stix = {
        "type": "bundle",
        "id": f"bundle--{fake.uuid4()}",
        "objects": [
            {
                "type": "observed-data",
                "id": f"observed-data--{fake.uuid4()}",
                "first_observed": _time(90) + "Z",
                "last_observed": _time(60) + "Z",
                "number_observed": 1,
                "objects": _stix_objects(),
            }
        ],
    }
    config = {
        "family": fake.random_element(THREATS),
        "c2": [fake.domain_name()],
        "key": fake.sha1(),
    }
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("report/report.pdf", _pdf(_report_text()))
        archive.writestr("report/behavior.json", json.dumps({"processes": []}))
        archive.writestr("report/artifacts/stix-1.json", json.dumps(stix))
        archive.writestr("malware_configurations/", "")
        archive.writestr("malware_configurations/config_1.json", json.dumps(config))
    return Response(out.getvalue(), media_type="application/zip")
