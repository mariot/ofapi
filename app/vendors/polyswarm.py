"""PolySwarm: hash search, IOCs, tags, scans, sandbox tasks and reports (v3 API, as the
polyswarm-api SDK calls it), read by the polyswarm-enrichment and polyswarm-sandbox
connectors."""

import hashlib
import itertools
from datetime import UTC, datetime

from fastapi import APIRouter, Request, Response

from app.fake import fake

HOSTS = ["api.polyswarm.network"]
router = APIRouter(prefix="/polyswarm", tags=["PolySwarm"])

BASE = "https://api.polyswarm.network/v3"
ENGINES = [
    "ClamAV",
    "K7",
    "Xcitium",
    "Vir.IT",
    "CrowdStrike",
    "Cyren",
    "Zoner",
    "Ikarus",
]
PROVIDERS = {
    "cape": {
        "slug": "cape",
        "name": "CAPEv2",
        "tool": "cape",
        "vms": {"win-10-build-19041": {"name": "Windows 10", "os": "windows"}},
    },
    "triage": {
        "slug": "triage",
        "name": "Hatching Triage",
        "tool": "triage",
        "vms": {
            "windows11-21h2-x64": {"name": "Windows 11", "os": "windows"},
            "ubuntu-22.04-amd64": {"name": "Ubuntu 22.04", "os": "linux"},
        },
    },
}

_ids = itertools.count(fake.random_int(100000, 900000))
_instances: dict[str, dict] = {}
_tasks: dict[str, dict] = {}
_reports: dict[str, str] = {}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _ok(result) -> dict:
    return {"status": "OK", "result": result}


def _hashes(sha256: str | None = None) -> dict:
    """The other hashes of an artifact follow from its SHA-256, as for a real file."""
    sha256 = sha256 or fake.sha256()
    return {
        "sha256": sha256,
        "sha1": hashlib.sha1(sha256.encode()).hexdigest(),  # noqa: S324
        "md5": hashlib.md5(sha256.encode()).hexdigest(),  # noqa: S324
    }


def _instance(sha256: str | None = None, filename: str | None = None) -> dict:
    """A scanned artifact: engine assertions, PolyScore and the metadata tools."""
    hashes = _hashes(sha256)
    family = fake.malware_family()
    malicious = fake.random_int(4, len(ENGINES))
    assertions = [
        {
            "author": fake.uuid4(),
            "author_name": engine,
            "engine": {"name": engine, "description": f"{engine} antivirus engine"},
            "bid": "1000000000000000000",
            "mask": True,
            "verdict": index < malicious,
            "metadata": {"malware_family": family} if index < malicious else {},
        }
        for index, engine in enumerate(ENGINES)
    ]
    first_seen = fake.date_time_between(start_date="-90d", end_date="-30d")
    return {
        **hashes,
        "id": str(next(_ids)),
        "artifact_id": str(next(_ids)),
        "mimetype": "application/x-dosexec",
        "size": fake.random_int(20000, 900000),
        "extended_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
        "first_seen": first_seen.isoformat() + "+00:00",
        "last_seen": _now(),
        "last_scanned": _now(),
        "created": _now(),
        "upload_url": f"{BASE}/upload/{fake.uuid4()}",
        "filename": filename or fake.file_name(extension="exe"),
        "country": "FR",
        "community": "default",
        "failed": False,
        "failed_reason": None,
        "result": None,
        "type": "FILE",
        "votes": [],
        "window_closed": True,
        "polyscore": round(fake.random_int(80, 99) / 100, 2),
        "detections": {
            "benign": len(ENGINES) - malicious,
            "malicious": malicious,
            "total": len(ENGINES),
        },
        "assertions": assertions,
        "metadata": [
            {
                "tool": "polyunite",
                "tool_metadata": {
                    "malware_family": family,
                    "labels": ["trojan", "backdoor"],
                    "operating_system": ["windows"],
                },
            },
            {
                "tool": "exiftool",
                "tool_metadata": {
                    "filetype": "Win32 EXE",
                    "productname": fake.word(),
                    "companyname": fake.company(),
                    "filedescription": fake.sentence(),
                    "originalfilename": fake.file_name(extension="exe"),
                    "fileversion": "1.0.0.0",
                },
            },
            {
                "tool": "hash",
                "tool_metadata": {
                    **hashes,
                    "sha3_256": fake.sha256(),
                    "sha3_512": fake.sha256() + fake.sha256(),
                    "sha512": fake.sha256() + fake.sha256(),
                    "ssdeep": fake.ssdeep(),
                    "tlsh": fake.tlsh(),
                },
            },
            {
                "tool": "pefile",
                "tool_metadata": {
                    "imphash": fake.md5(),
                    "signed": False,
                    "is_probably_packed": True,
                    "is_exe": True,
                    "is_dll": False,
                    "compile_date": "2024-02-11T08:12:41",
                    "libraries": ["KERNEL32.dll", "ADVAPI32.dll", "WS2_32.dll"],
                    "imported_functions": ["CreateFileW", "RegSetValueExW", "connect"],
                },
            },
        ],
    }


@router.head("/v3/search/hash/{hash_type}")
async def exists_hash(hash_type: str) -> Response:  # noqa: ARG001
    """The artifact is known."""
    return Response(status_code=200)


@router.get("/v3/search/hash/{hash_type}")
async def search_hash(hash_type: str, hash: str = "") -> dict:
    """The latest scan of the artifact matching the hash."""
    instance = _instance(hash if hash_type == "sha256" else None)
    if hash_type in ("md5", "sha1"):
        instance[hash_type] = hash
    return {**_ok([instance]), "has_more": False}


@router.get("/v3/tags/link")
async def tag_link(hash: str = "") -> dict:
    """The curated tags and malware families of the artifact."""
    return _ok(
        {
            "id": str(next(_ids)),
            "sha256": hash,
            "created": _now(),
            "updated": _now(),
            "first_seen": _now(),
            "tags": ["ransomware", "persistence", "feed:polyswarm-emerging"],
            "families": [fake.malware_family()],
            "emerging": None,
        }
    )


@router.get("/v3/ioc/{hash_type}/{hash_value}")
async def iocs_by_hash(hash_type: str, hash_value: str) -> dict:  # noqa: ARG001
    """The network indicators seen when the artifact ran."""
    ips = [fake.ipv4_public() for _ in range(3)] + ["10.0.2.15"]
    urls = [fake.url() for _ in range(3)]
    return _ok(
        {
            "ips": ips,
            "urls": urls,
            "ttps": ["T1055", "T1071.001", "T1547.001"],
            "imphash": fake.md5(),
        }
    )


@router.post("/v3/instance")
async def create_instance(request: Request) -> dict:
    """A scan to come: the artifact is uploaded to the URL answered."""
    body = await request.json()
    instance = _instance(filename=body.get("artifact_name"))
    instance["window_closed"] = False
    _instances[instance["id"]] = instance
    instance["upload_url"] = f"{BASE}/upload/instance/{instance['id']}"
    return _ok(instance)


@router.put("/v3/instance")
async def update_instance(id: str) -> dict:
    """The upload is done: the scan is queued."""
    return _ok(_instances.get(id) or _instance())


@router.put("/v3/upload/{kind}/{item_id}")
async def upload(kind: str, item_id: str, request: Request) -> dict:
    """The artifact content (a file, a sample): its hash becomes the artifact's."""
    digest = hashlib.sha256(await request.body()).hexdigest()
    target = _instances.get(item_id) if kind == "instance" else _tasks.get(item_id)
    if target is not None:
        target["sha256"] = digest
    return {}


@router.get("/v3/consumer/submission/{community}/{instance_id}")
async def lookup(community: str, instance_id: str) -> dict:  # noqa: ARG001
    """The scan has closed its window: engines' verdicts are in."""
    instance = _instances.get(instance_id) or _instance()
    instance["window_closed"] = True
    return _ok(instance)


@router.get("/v3/sandbox/provider/list")
@router.get("/v3/sandbox/provider")
async def providers() -> dict:
    """The sandboxes and their virtual machines."""
    return _ok(PROVIDERS)


def _cape_report() -> dict:
    hosts = [fake.ipv4_public() for _ in range(2)]
    return {
        "malscore": 9.0,
        "malware_family": [fake.malware_family()],
        "signature_names": [
            "injection_runpe",
            "persistence_autorun",
            "network_cnc_http",
        ],
        "signatures": [
            {"name": "injection_runpe", "categories": ["injection", "stealth"]},
            {"name": "persistence_autorun", "categories": ["persistence"]},
        ],
        "ttp": ["T1055", "T1547.001", "T1071.001"],
        "network": {
            "hosts": [{"ip": ip, "hostname": ""} for ip in hosts],
            "dns": [{"request": fake.domain_name(), "answers": [{"data": hosts[0]}]}],
            "domains": [{"domain": fake.domain_name()}],
            "tcp": [{"dst": hosts[1], "dport": 443}],
            "udp": [],
        },
        "suricata_alerts": [
            {
                "category": "A Network Trojan was detected",
                "signature": "ET MALWARE Possible C2 beacon",
                "dstip": hosts[0],
                "dstport": 443,
            }
        ],
    }


def _triage_report() -> dict:
    family = fake.malware_family()
    return {
        "malware_family": [family],
        "ttp": ["T1055", "T1112", "T1082"],
        "targets": [
            {
                "score": 9,
                "tags": ["family:" + family.lower(), "trojan"],
                "signatures": [
                    {"name": "Drops file in System32 directory", "score": 3}
                ],
                "iocs": {
                    "domains": [fake.domain_name()],
                    "ips": [fake.ipv4_public(), fake.ipv4_public()],
                },
            }
        ],
        "extracted": [
            {
                "config": {
                    "family": family,
                    "version": "2.1",
                    "c2": [f"{fake.ipv4_public()}:8443"],
                    "botnet": "campaign01",
                    "mutex": ["Global\\" + fake.md5()[:12]],
                    "keys": [{"key": "rc4", "kind": "key", "value": fake.md5()}],
                    "rule": family + "Config",
                    "attr": {"install_folder": "%AppData%", "delay": "10"},
                }
            }
        ],
        "static": {"signatures": [{"name": "Packed with UPX"}]},
    }


def _task(provider: str, sha256: str | None = None) -> dict:
    task_id = str(next(_ids))
    task = {
        "id": task_id,
        "community": "default",
        "sandbox": provider,
        "created": _now(),
        "expiration": None,
        "status": "SUCCEEDED",
        "account_number": 1,
        "team_account_number": 1,
        "instance_id": str(next(_ids)),
        "sha256": sha256 or fake.sha256(),
        "report": _cape_report() if provider == "cape" else _triage_report(),
        "upload_url": f"{BASE}/upload/task/{task_id}",
        "config": (
            {"cape_malscore": 9, "provider": {"slug": "cape"}}
            if provider == "cape"
            else {
                "traige_analysis_score": 9,
                "triage_static_score": 8,
                "provider": {"slug": "triage"},
            }
        ),
        "artifact": {"id": str(next(_ids))},
        "sandbox_artifacts": [],
    }
    _tasks[task_id] = task
    return task


@router.post("/v3/sandbox/sandboxtask/instance")
async def create_task(request: Request) -> dict:
    """A sandbox run to come: the sample is uploaded to the URL answered."""
    body = await request.json()
    return _ok(_task(body.get("provider_slug", "cape")))


@router.put("/v3/sandbox/sandboxtask/instance")
async def update_task(id: str) -> dict:
    """The upload is done: the detonation is queued."""
    return _ok(_tasks.get(id) or _task("cape"))


@router.get("/v3/sandbox/sandboxtask")
async def task_status(sandbox_task_id: str) -> dict:
    """The detonation is over."""
    return _ok(_tasks.get(sandbox_task_id) or _task("cape"))


@router.post("/v3/reports")
async def create_report(request: Request) -> dict:
    """A PDF report is generated for a scan or a sandbox task."""
    body = await request.json()
    report_id = str(next(_ids))
    _reports[report_id] = body.get("type", "scan")
    return _ok(_report(report_id, "PENDING"))


def _report(report_id: str, state: str) -> dict:
    return {
        "id": report_id,
        "type": _reports.get(report_id, "scan"),
        "format": "pdf",
        "state": state,
        "community": "default",
        "created": _now(),
        "template_id": None,
        "template_metadata": {},
        "sandbox_task_id": None,
        "instance_id": None,
        "url": f"{BASE}/reports/file/{report_id}.pdf" if state == "SUCCEEDED" else None,
    }


@router.get("/v3/reports")
async def get_report(id: str) -> dict:
    """The report is ready."""
    return _ok(_report(id, "SUCCEEDED"))


@router.get("/v3/reports/file/{name}")
async def report_file(name: str) -> Response:  # noqa: ARG001
    """A minimal PDF."""
    pdf = (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )
    return Response(content=pdf, media_type="application/pdf")


@router.post("/v3/reports/llm")
async def create_llm_report() -> dict:
    """An AI summary is generated."""
    return _ok(_llm_report("SUCCEEDED"))


@router.get("/v3/reports/llm")
async def get_llm_report(id: str = "") -> dict:  # noqa: A002, ARG001
    """The AI summary is ready."""
    return _ok(_llm_report("SUCCEEDED"))


def _llm_report(state: str) -> dict:
    return {
        "id": str(next(_ids)),
        "community": "default",
        "created": _now(),
        "cape_sandbox_task_id": None,
        "triage_sandbox_task_id": None,
        "instance_id": None,
        "state": state,
        "url": None,
        "report": {
            "bottom_line": "A malicious loader that persists and beacons out.",
            "observations": ["Injects into a child process", "Writes a Run key"],
            "recommended_actions": ["Isolate the host", "Block the C2 addresses"],
        },
    }
