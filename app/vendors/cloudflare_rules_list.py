"""Cloudflare Rules Lists API: an IP list replaced by bulk operations, read by the
OpenCTI cloudflare-rules-list stream connector."""

from datetime import UTC, datetime

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["api.cloudflare.com"]
router = APIRouter(prefix="/cloudflare-rules-list", tags=["Cloudflare"])

BASE = "/client/v4/accounts/{account_id}/rules/lists"  # any account

_items: dict[str, list[dict]] = {}


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _envelope(result: object) -> dict:
    return {"success": True, "errors": [], "messages": [], "result": result}


@router.get(BASE + "/bulk_operations/{operation_id}")
async def bulk_operation(operation_id: str) -> dict:
    """Bulk operations complete as soon as they are asked for."""
    return _envelope(
        {"id": operation_id, "status": "completed", "completed": _now()},
    )


@router.get(BASE + "/{list_id}")
async def get_list(list_id: str) -> dict:
    return _envelope(
        {
            "id": list_id,
            "name": "opencti_ips",
            "description": "IPs from OpenCTI",
            "kind": "ip",
            "num_items": len(_items.get(list_id, [])),
            "num_referencing_filters": 0,
            "created_on": _now(),
            "modified_on": _now(),
        }
    )


@router.get(BASE + "/{list_id}/items")
async def get_items(list_id: str) -> dict:
    items = [
        {**item, "id": fake.md5(), "created_on": _now(), "modified_on": _now()}
        for item in _items.get(list_id, [])
    ]
    return {**_envelope(items), "result_info": {"cursors": {"before": "", "after": ""}}}


@router.put(BASE + "/{list_id}/items")
async def replace_items(list_id: str, request: Request) -> dict:
    """Replaces all the items of the list: answers with the bulk operation doing it."""
    _items[list_id] = await request.json()
    return _envelope({"operation_id": fake.uuid4().replace("-", "")})
