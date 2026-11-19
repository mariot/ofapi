"""Hatching Triage (tria.ge) sandbox API, read by the OpenCTI hatching-triage-sandbox
connector through the triage Python client: search, submission, analysis events and the
overview report with its extracted configurations."""

import json
from datetime import UTC, datetime

from fastapi import APIRouter, Request, Response

from app.fake import fake

HOSTS = ["tria.ge"]
router = APIRouter(prefix="/hatching-triage", tags=["Hatching Triage"])

TTPS = {
    "Suspicious use of WriteProcessMemory": ["T1055"],
    "Checks computer location settings": ["T1614"],
    "Reads user/profile data of web browsers": ["T1555.003", "T1539"],
}
DUMP = b"MZ\x90\x00" + bytes(range(256))


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sample_id() -> str:
    return f"{datetime.now(UTC).strftime('%y%m%d')}-{fake.pystr(8, 8).lower()}"


@router.get("/api/v0/search")
async def search(query: str, limit: int = 20) -> dict:
    """The newest analysis matching the query, already reported (no further page)."""
    kind = "url" if query.startswith("url:") else "file"
    return {
        "data": [
            {
                "id": _sample_id(),
                "status": "reported",
                "kind": kind,
                "filename": "sample.exe" if kind == "file" else None,
                "url": query.removeprefix("url:") if kind == "url" else None,
                "private": False,
                "tags": ["family:redline"],
                "score": 10,
                "created": _now(),
                "completed": _now(),
            }
        ][:limit],
        "next": None,
    }


@router.post("/api/v0/samples")
async def submit(request: Request) -> dict:
    """A submission (file upload or URL) starts a pending analysis."""
    await request.body()
    return {
        "id": _sample_id(),
        "status": "pending",
        "kind": "url",
        "private": False,
        "submitted": _now(),
    }


@router.get("/api/v0/samples/{sample_id}/events")
async def events(sample_id: str) -> Response:  # noqa: ARG001
    """The event stream of an analysis, one JSON document per line, up to reported."""
    lines = [
        {"status": "pending"},
        {"status": "static_analysis"},
        {"status": "reported"},
    ]
    return Response("\n".join(json.dumps(line) for line in lines) + "\n")


@router.get("/api/v1/samples/{sample_id}/overview.json")
async def overview(sample_id: str) -> dict:
    """The overview report: tags, network IOCs, TTPs, the extracted configuration (C2s,
    credentials) with its dumped file, and a dropper."""
    family = fake.malware_family()
    task = "behavioral1"
    return {
        "version": "0.2.2",
        "sample": {
            "id": sample_id,
            "score": 10,
            "created": _now(),
            "completed": _now(),
            "sha256": fake.sha256(),
        },
        "analysis": {
            "score": 10,
            "tags": [
                f"family:{family.lower()}",
                f"botnet:{fake.word()}",
                f"campaign:{fake.word()}",
                "trojan",
                "stealer",
            ],
        },
        "targets": [
            {
                "tasks": [task],
                "score": 10,
                "target": "sample.exe",
                "iocs": {
                    "domains": [fake.domain_name(), fake.domain_name()],
                    "ips": [fake.ipv4_public(), "8.8.8.8", "10.0.2.15"],
                    "urls": [fake.url()],
                },
            }
        ],
        "signatures": [
            {"name": name, "score": 5, "ttp": ttp, "tags": []}
            for name, ttp in TTPS.items()
        ]
        + [{"name": "Unsigned PE", "score": 1}],
        "extracted": [
            {
                "tasks": [task],
                "dumped_file": f"memory/{fake.random_int(1000, 9999)}-30.dmp",
                "resource": f"{task}/memory/dump.dmp",
                "config": {
                    "rule": family,
                    "family": family.lower(),
                    "version": "1.0",
                    "c2": [f"{fake.ipv4_public()}:{fake.random_int(1024, 65000)}"],
                    "credentials": [
                        {
                            "protocol": "smtp",
                            "host": fake.domain_name(),
                            "port": 587,
                            "username": fake.email(),
                            "password": fake.password(),
                        }
                    ],
                },
            },
            {
                "tasks": [task],
                "dropper": {
                    "family": family.lower(),
                    "urls": [{"type": "download", "url": fake.url()}],
                },
            },
        ],
    }


@router.get("/api/v0/samples/{sample_id}/{task_id}/{filename:path}")
async def task_file(sample_id: str, task_id: str, filename: str) -> Response:  # noqa: ARG001
    """A file of an analysis task (here the dumped configuration of the extractor)."""
    return Response(DUMP, media_type="application/octet-stream")
