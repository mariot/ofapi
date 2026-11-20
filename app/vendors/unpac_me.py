"""UnpacMe: sample upload, status, unpacking results and unpacked file download (API key
auth), read by the OpenCTI unpac-me enrichment connector."""

import re
import time

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["api.unpac.me"]
router = APIRouter(prefix="/unpac-me", tags=["UnpacMe"])


@router.post("/api/v1/private/upload")
async def upload() -> dict:
    return {"id": fake.uuid4()}


@router.get("/api/v1/public/status/{upload_id}")
async def status(upload_id: str) -> dict:  # noqa: ARG001
    return {"status": "complete"}


@router.get("/api/v1/public/results/{upload_id}")
async def results(upload_id: str) -> dict:
    """The submitted file and two unpacked ones, one of them identified as malware."""
    unpacked = [
        {
            "hashes": {"sha256": fake.sha256(), "md5": fake.md5(), "sha1": fake.sha1()},
            "malware_id": [{"name": fake.malware_family(), "match": "yara"}] * (i % 2),
        }
        for i in range(3)
    ]
    return {
        "id": upload_id,
        "sha256": fake.sha256(),
        "status": "complete",
        "created": int(time.time()),
        "results": unpacked,
    }


@router.get("/api/v1/private/download/{sha256}")
async def download(sha256: str) -> Response:
    """A small PE-looking file for any hash asked."""
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        return Response('{"error": "invalid hash"}', status_code=400)
    content = b"MZ\x90\x00" + f" unpacked sample {sha256}".encode() + b"\x00" * 64
    return Response(content, media_type="application/octet-stream")
