"""A sink accepting any request, for connectors pushing to a URL of their user's choice
(webhooks, generic HTTP outputs): the journal shows what they sent."""

from fastapi import APIRouter, Request

HOSTS = ["sink.staticfire.test", "*.sink.staticfire.test"]
router = APIRouter(prefix="/sink", tags=["Sink"])


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def accept(path: str, request: Request) -> dict:
    return {"status": "ok", "path": path, "method": request.method}
