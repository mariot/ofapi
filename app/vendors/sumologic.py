"""Sumo Logic: the threat intelligence datastore (STIX indicators upload and removal),
written by the OpenCTI sumologic-intel stream connector."""

from fastapi import APIRouter, Response

HOSTS = ["api.sumologic.com", "api.*.sumologic.com"]
router = APIRouter(prefix="/sumologic", tags=["Sumo Logic"])


@router.post("/api/v1/threatIntel/datastore/indicators/stix")
async def upload_indicators(payload: dict) -> dict:
    """Accept the STIX indicators of a source: {"source": ..., "indicators": [...]}."""
    return {
        "source": payload.get("source"),
        "count": len(payload.get("indicators", [])),
    }


@router.delete("/api/v1/threatIntel/datastore/indicators")
async def remove_indicators() -> Response:
    """Forget indicators by id."""
    return Response(status_code=204)
