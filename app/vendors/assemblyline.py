"""AssemblyLine 4: login, submissions search, submit, full and summary results, read
through assemblyline-client by the OpenCTI assemblyline connector."""

import hashlib
import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["assemblyline.staticfire.test"]
router = APIRouter(prefix="/assemblyline", tags=["AssemblyLine"])

# sha256("password"): a file AssemblyLine already analysed
KNOWN_SHA256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
VERSION = "4.6.1.0"

# sha256 -> sid of the files submitted since the module loaded
SUBMITTED: dict[str, str] = {}
SIZES: dict[str, int] = {}


def _ok(payload) -> dict:
    return {
        "api_response": payload,
        "api_error_message": "",
        "api_server_version": VERSION,
        "api_status_code": 200,
    }


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(
        {
            "api_response": "",
            "api_error_message": message,
            "api_server_version": VERSION,
            "api_status_code": status,
        },
        status_code=status,
    )


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@router.get("/api/v3/auth/init/")
async def legacy_init() -> JSONResponse:
    """Absent from version 4: the client takes this 404 as a v4 server."""
    return _error(404, "The requested API does not exist")


@router.post("/api/v4/auth/login/")
async def login() -> dict:
    return _ok({"username": "staticfire", "session_duration": 3600})


@router.get("/api/")
async def api_versions() -> dict:
    return _ok(["v4"])


@router.get("/api/v4/file/info/{sha256}/")
async def file_info(sha256: str):
    if sha256 != KNOWN_SHA256 and sha256 not in SUBMITTED:
        return _error(404, "File not found")
    return _ok(_file_info(sha256))


def _file_info(sha256: str) -> dict:
    return {
        "sha256": sha256,
        "sha1": fake.sha1(),
        "md5": fake.md5(),
        "type": "executable/windows/pe32",
        "size": SIZES.get(sha256, 245760),
    }


@router.post("/api/v4/search/submission/")
async def search_submission(request: Request) -> dict:
    """``state:submitted`` counts the running analyses (none); a hash query finds its
    completed submission when AssemblyLine knows the file."""
    query = (await request.json()).get("query", "")
    if query.startswith("files.sha256:"):
        sha256 = query.split(":", 1)[1]
        sid = SUBMITTED.get(sha256) or (KNOWN_SHA256 == sha256 and _sid(sha256))
        if sid:
            return _ok({"total": 1, "items": [{"sid": sid}], "rows": 1, "offset": 0})
    return _ok({"total": 0, "items": [], "rows": 0, "offset": 0})


def _sid(sha256: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, sha256)).replace("-", "")[:22]


@router.post("/api/v4/submit/")
async def submit(request: Request) -> dict:
    """Records the file by its hash, as AssemblyLine's ingestion would."""
    form = await request.form()
    json_part = form.get("json")
    if hasattr(json_part, "read"):
        json_part = (await json_part.read()).decode()
    name = json.loads(json_part or "{}").get("name", "sample")
    content = await form["bin"].read()
    sha256 = hashlib.sha256(content).hexdigest()
    SUBMITTED[sha256] = sid = _sid(sha256 + str(uuid.uuid4()))
    SIZES[sha256] = len(content)
    return _ok({"sid": sid, "state": "submitted", "files": [{"name": name}]})


def _sha_of(sid: str) -> str:
    for sha256, known in SUBMITTED.items():
        if known == sid:
            return sha256
    return KNOWN_SHA256


@router.get("/api/v4/submission/full/{sid}/")
async def submission_full(sid: str) -> dict:
    sha256 = _sha_of(sid)
    return _ok(
        {
            "sid": sid,
            "state": "completed",
            "max_score": 1500,
            "file_info": _file_info(sha256),
            "times": {"submitted": _now(), "completed": _now()},
            "files": [{"name": "sample.exe", "sha256": sha256}],
            "errors": [],
            "results": [],
        }
    )


@router.get("/api/v4/submission/summary/{sid}/")
async def submission_summary(sid: str) -> dict:  # noqa: ARG001
    """The tags (value, verdict, safelisted, classification) and ATT&CK matrix."""

    def tags(*values: str, verdict: str = "malicious") -> list:
        return [[value, verdict, False, "TLP:C"] for value in values]

    return _ok(
        {
            "map": {},
            "classification": "TLP:C",
            "filtered": False,
            "partial": False,
            "tags": {
                "network": {
                    "network.static.domain": tags(
                        fake.domain_name(), fake.domain_name()
                    ),
                    "network.dynamic.domain": tags(
                        fake.domain_name(), verdict="suspicious"
                    ),
                    "network.static.ip": tags(fake.ipv4_public()),
                    "network.dynamic.ip": tags(fake.ipv4_public()),
                    "network.static.uri": tags(fake.url()),
                },
                "attribution": {
                    "attribution.family": tags(fake.malware_family().upper()),
                },
            },
            "attack_matrix": {
                "defense-evasion": [
                    ["T1027", "Obfuscated Files or Information", "malicious"]
                ],
                "execution": [["T1059.001", "PowerShell", "suspicious"]],
            },
            "heuristics": {"malicious": {}, "suspicious": {}, "info": {}},
        }
    )
