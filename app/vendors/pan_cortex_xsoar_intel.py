"""Palo Alto Cortex XSOAR indicator API (create, edit, batch delete), read by the
OpenCTI pan-cortex-xsoar-intel stream connector. The incident routes of the OpenAEV
collector live elsewhere, under another host and prefix."""

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["xsoar-staticfire.xdr.us.paloaltonetworks.com"]
router = APIRouter(
    prefix="/pan-cortex-xsoar-intel", tags=["Palo Alto Cortex XSOAR IOCs"]
)


@router.post("/xsoar/public/v1/indicator/create")
async def create(request: Request) -> dict:
    """The indicator, as XSOAR stores it."""
    body = await request.json()
    indicator = body["indicator"]
    return {**indicator, "id": str(fake.random_int(1, 10**6)), "version": 1}


@router.post("/xsoar/public/v1/indicator/edit")
async def edit(request: Request) -> dict:
    return {**await request.json(), "version": 2}


@router.post("/xsoar/public/v1/indicators/batchDelete")
async def batch_delete(request: Request) -> dict:
    body = await request.json()
    return {"total": len(body.get("ids", [])), "updatedIds": body.get("ids", [])}
