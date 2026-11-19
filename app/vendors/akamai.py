"""Akamai Client Lists: item updates, called by the OpenCTI akamai stream connector."""

from fastapi import APIRouter, Request

HOSTS = ["*.akamaiapis.net"]
router = APIRouter(prefix="/akamai", tags=["Akamai"])


@router.post("/client-list/v1/lists/{list_id}/items")
async def update_items(list_id: str, request: Request) -> dict:
    """Appends or deletes the items given: the API echoes what changed."""
    body = await request.json()
    return {
        "listId": list_id,
        "appended": body.get("append", []),
        "updated": body.get("update", []),
        "deleted": body.get("delete", []),
    }
