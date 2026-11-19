"""MWDB (CERT Polska's malware database): recent files, files and their static
configurations, read by the OpenCTI mwdb connector (through mwdblib)."""

import hashlib
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["mwdb.cert.pl"]
router = APIRouter(prefix="/mwdb", tags=["MWDB"])

FAMILIES = ["agenttesla", "formbook", "remcos", "lokibot"]
FILES: dict[str, dict] = {}
CONFIGS: dict[str, dict] = {}


def _sample(index: int) -> dict:
    """A file with its tags and, for most, the static config extracted from it."""
    sha256 = fake.sha256()
    family = FAMILIES[index % len(FAMILIES)]
    uploaded = datetime.now(UTC) - timedelta(hours=2 + index * 7)
    tags = [
        {"tag": f"yara:win_{family}_auto"},
        {"tag": "runnable:win32:exe"},
        {"tag": f"ripped:{family}"},
        {"tag": f"family:{family}"},
        {"tag": "bazaar-2026"},
        {"tag": "src:malware-feed"},
    ]
    sample = {
        "id": sha256,
        "type": "file",
        "file_name": f"{fake.file_name(extension='exe')}-{sha256}",
        "file_size": fake.random_int(20000, 900000),
        "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
        "md5": fake.md5(),
        "sha1": fake.sha1(),
        "sha256": sha256,
        "sha512": hashlib.sha512(sha256.encode()).hexdigest(),
        "crc32": f"{fake.random_int(0, 2**32 - 1):08x}",
        "ssdeep": fake.ssdeep(),
        "upload_time": uploaded.isoformat(),
        "tags": tags,
        "parents": [],
        "children": [],
    }
    if index % 4 != 3:
        config_id = hashlib.sha256(sha256.encode()).hexdigest()
        c2 = [f"{fake.ipv4_public()}:{fake.random_int(1024, 65000)}", fake.url()]
        if index % 2:
            c2.append({"host": fake.ipv4_public(), "port": 8080})
        CONFIGS[config_id] = {
            "id": config_id,
            "type": "static_config",
            "family": family,
            "config_type": "static",
            "upload_time": uploaded.isoformat(),
            "cfg": {
                "type": family,
                "c2": c2,
                "attr": {"url4cnc": [fake.url(), "not-a-url"]},
                "version": "3.1",
            },
            "tags": [{"tag": f"ripped:{family}"}],
        }
        sample["latest_config"] = {
            "id": config_id,
            "type": "static_config",
            "family": family,
            "config_type": "static",
        }
    else:
        sample["latest_config"] = None
    return sample


@router.get("/api/file")
async def recent_files(count: int = 100, older_than: str | None = None) -> dict:
    """A page of files, newest first; the page after ``older_than`` is empty."""
    if older_than:
        return {"files": []}
    samples = [_sample(i) for i in range(6)]
    for sample in samples:
        FILES[sample["id"]] = sample
    return {"files": samples[:count]}


@router.get("/api/file/{sha256}")
async def file(sha256: str) -> dict:
    if sha256 not in FILES:
        raise HTTPException(404, "Object not found")
    return FILES[sha256]


@router.get("/api/config/{config_id}")
async def config(config_id: str) -> dict:
    if config_id not in CONFIGS:
        raise HTTPException(404, "Object not found")
    return CONFIGS[config_id]


@router.get("/api/object/{object_id}/tag")
async def tags(object_id: str) -> list[dict]:
    found = FILES.get(object_id) or CONFIGS.get(object_id)
    if found is None:
        raise HTTPException(404, "Object not found")
    return found["tags"]


@router.get("/api/server")
async def server() -> dict:
    return {"server_version": "2.17.0", "is_authenticated": True}
