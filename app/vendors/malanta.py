"""Malanta: the OpenCTI malanta-attribution stream connector calls no vendor, it writes
Intrusion Sets back to OpenCTI. This route only records what its test verified there."""

from fastapi import APIRouter

router = APIRouter(prefix="/malanta", tags=["Malanta"])


@router.post("/verified")
async def verified(body: dict) -> dict:
    """The journal keeps what the test found in OpenCTI (actor, intrusion set)."""
    return {"status": "ok", **body}
