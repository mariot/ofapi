"""GLIMPS Malware (GLIMPS Detect lite API v2): submission, results and the STIX export
(glimps-malware enrichment connector, through the gdetect client)."""

import hashlib
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["gmalware.ggp.glimps.re"]
router = APIRouter(prefix="/glimps", tags=["GLIMPS"])

# analysis uuid -> {"sha256", "size", "polls"}; sha256 -> analysis uuid
ANALYSES: dict[str, dict] = {}
BY_SHA256: dict[str, str] = {}

ANTIVIRUS = ["SignatureKaspersky", "SignatureEset", "SignatureClamav"]


def _error(status: int, message: str) -> Response:
    return JSONResponse(
        {"status": False, "error": message, "details": [message]}, status_code=status
    )


def _result(uid: str, done: bool) -> dict:
    analysis = ANALYSES[uid]
    result = {
        "uuid": uid,
        "sha256": analysis["sha256"],
        "sha1": hashlib.sha1(analysis["sha256"].encode()).hexdigest(),  # noqa: S324
        "md5": hashlib.md5(analysis["sha256"].encode()).hexdigest(),  # noqa: S324
        "size": analysis["size"],
        "filetype": "exe",
        "done": done,
        "status": True,
    }
    if done:
        family = analysis["family"]
        result |= {
            "is_malware": True,
            "score": 3000,
            "malwares": [family],
            "sid": uid.replace("-", ""),
            "token": uuid.uuid4().hex,
            "files": [
                {
                    "sha256": analysis["sha256"],
                    "size": analysis["size"],
                    "magic": "PE32 executable",
                    "is_malware": True,
                    "av_results": [
                        {"av": av, "result": f"Trojan.{family}.Gen"} for av in ANTIVIRUS
                    ],
                }
            ],
        }
    return result


@router.get("/api/lite/v2/search/{sha256}")
async def search(sha256: str) -> Response:
    """The result of a file already analysed, else not found."""
    uid = BY_SHA256.get(sha256)
    if uid is None:
        return _error(404, "result not found")
    return JSONResponse(_result(uid, True))


@router.post("/api/lite/v2/submit")
async def submit(request: Request) -> dict:
    """Records the uploaded file; the analysis completes at the second poll."""
    form = await request.form()
    upload = form.get("file")
    if upload is None or not hasattr(upload, "read"):
        raise HTTPException(400, "missing file")
    content = await upload.read()
    sha256 = hashlib.sha256(content).hexdigest()
    uid = str(uuid.uuid4())
    ANALYSES[uid] = {
        "sha256": sha256,
        "size": len(content),
        "polls": 0,
        "family": fake.malware_family().replace(" ", ""),
    }
    BY_SHA256[sha256] = uid
    return {"status": True, "uuid": uid}


@router.get("/api/lite/v2/results/{uid}")
async def results(uid: str) -> Response:
    if uid not in ANALYSES:
        return _error(404, "result not found")
    ANALYSES[uid]["polls"] += 1
    return JSONResponse(_result(uid, ANALYSES[uid]["polls"] > 1))


@router.get("/api/lite/v2/results/{uid}/export")
async def export(uid: str) -> Response:
    """The analysis as a STIX bundle: the file and its malware family."""
    if uid not in ANALYSES:
        return _error(404, "result not found")
    analysis = ANALYSES[uid]
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    sample = f"file--{uuid.uuid5(uuid.NAMESPACE_URL, analysis['sha256'])}"
    malware = f"malware--{uuid.uuid5(uuid.NAMESPACE_URL, analysis['family'])}"
    objects = [
        {
            "type": "file",
            "spec_version": "2.1",
            "id": sample,
            "hashes": {"SHA-256": analysis["sha256"]},
            "size": analysis["size"],
            "mime_type": "application/x-dosexec",
        },
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": malware,
            "created": now,
            "modified": now,
            "name": analysis["family"],
            "is_family": True,
            "malware_types": ["trojan"],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "related-to",
            "source_ref": sample,
            "target_ref": malware,
        },
    ]
    return JSONResponse(
        {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    )
