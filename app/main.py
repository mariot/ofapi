import gzip
import io
import json
from typing import Annotated

from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse
from app.api.hunt_io import C2FeedFactory
from app.api.feedly import BundleFactory

app = FastAPI()


@app.get("/hunt-io/feeds/c2", tags=["Hunt-IO"], response_class=StreamingResponse)
async def hunt_io_feeds_c2():
    """Hunt-IO C2 Feed Endpoint

    Returns a gzipped stream of C2 feed data in JSON Lines format."""
    c2_feed_batch = C2FeedFactory.create_batch(10)
    json_data = "\n".join([json.dumps(item.to_dict()) for item in c2_feed_batch])
    encoded = json_data.encode("utf-8")
    gzip_buffer = io.BytesIO(gzip.compress(encoded))
    return StreamingResponse(
        gzip_buffer,
        media_type="application/gzip",
        headers={"Content-Type": "application/gzip"},
    )


@app.get("/feedly/v3/enterprise/ioc", tags=["Feedly"])
async def feedly_enterprise_ioc(
    stream_id: Annotated[str, Query(alias="streamId")],
    newer_than: Annotated[str, Query(alias="newerThan")],
    count: int = Query(10, alias="count"),
    continuation: int = Query(0, alias="continuation"),
):
    """Feedly Enterprise IOC Endpoint

    Returns a sample response for Feedly Enterprise IOC."""
    return BundleFactory().to_dict()
