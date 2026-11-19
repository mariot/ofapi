"""Hunt.io: the C2 feed (gzip JSON lines), read by the OpenCTI hunt-io connector."""

import gzip
import json

from fastapi import APIRouter, Response

from app.api.hunt_io import C2FeedFactory

HOSTS = ["api.hunt.io"]
router = APIRouter(prefix="/hunt-io", tags=["Hunt-IO"])


@router.get("/feeds/c2")
@router.get("/v1/feeds/c2")
async def feeds_c2() -> Response:
    """A gzipped stream of C2 feed entries, one JSON object per line."""
    feed = C2FeedFactory.create_batch(10)
    lines = "\n".join(json.dumps(item.to_dict()) for item in feed)
    return Response(
        content=gzip.compress(lines.encode()),
        media_type="application/gzip",
    )
