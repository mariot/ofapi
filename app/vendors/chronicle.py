"""Google Chronicle (Backstory): reference lists, read by the OpenCTI chronicle stream
connector. The service account's token endpoint is served here too (``/token``).

The connector's httplib2 client ignores proxy variables unless PySocks is installed (it
is not), so the connector is pointed at ofapi directly."""

from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["backstory.googleapis.com"]
router = APIRouter(prefix="/chronicle", tags=["Chronicle"])

_lists: dict[str, dict] = {}


def _reference_list(name: str) -> dict:
    return _lists.setdefault(
        name,
        {
            "name": name,
            "description": "OpenCTI indicators",
            "createTime": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "lines": [fake.domain_name()],
            "contentType": "CONTENT_TYPE_DEFAULT_STRING",
        },
    )


@router.post("/token")
async def token() -> dict:
    """The OAuth2 JWT-bearer grant of the service account."""
    return {
        "access_token": f"ya29.{fake.pystr(60, 60)}",
        "expires_in": 3599,
        "token_type": "Bearer",
    }


@router.get("/v2/lists/{name}")
async def get_list(name: str) -> dict:
    """The reference list, created on first read with one line."""
    return _reference_list(name)


@router.post("/v2/lists")
async def create_list(request: Request) -> dict:
    body = await request.json()
    _lists[body["name"]] = {
        **body,
        "createTime": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }
    return _lists[body["name"]]


@router.patch("/v2/lists")
async def update_list(request: Request) -> JSONResponse:
    """Replaces the lines of the list (``update_mask=list.lines``)."""
    body = await request.json()
    reference = _reference_list(body["name"])
    reference["lines"] = body["lines"]
    return JSONResponse(reference)
