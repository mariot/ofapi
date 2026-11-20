"""Splunk SOAR (Phantom) REST API: containers (events and cases), artifacts and notes,
read by the OpenCTI splunk-soar-push stream connector."""

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["soar.staticfire.test"]
router = APIRouter(prefix="/splunk-soar", tags=["Splunk SOAR"])


@router.get("/rest/version")
async def version() -> dict:
    return {"version": "6.3.1.178"}


@router.post("/rest/container")
async def create_container(request: Request) -> dict:
    """A container; the answer carries the id and one result per inline artifact."""
    container = await request.json()
    artifacts = container.get("artifacts") or []
    return {
        "success": True,
        "id": fake.random_int(1000, 99999),
        "artifacts": [
            {"success": True, "id": fake.random_int(1000, 99999)} for _ in artifacts
        ],
    }


@router.get("/rest/container")
async def find_containers() -> dict:
    """No container matches an external id: the connector creates a new one."""
    return {"count": 0, "num_pages": 0, "data": []}


@router.post("/rest/container/{container_id}")
async def update_container(container_id: str) -> dict:
    return {"success": True, "id": int(container_id)}


@router.post("/rest/artifact")
async def create_artifact(request: Request) -> list | dict:
    """One artifact, or a list created in bulk."""
    payload = await request.json()
    if isinstance(payload, list):
        return [{"success": True, "id": fake.random_int(1000, 99999)} for _ in payload]
    return {"success": True, "id": fake.random_int(1000, 99999)}


@router.post("/rest/note")
async def create_note() -> dict:
    return {"success": True, "id": fake.random_int(1, 9999)}
