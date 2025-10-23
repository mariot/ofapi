import gzip
import io
import json
from dataclasses import asdict
from typing import Annotated

from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse

from app.api.feedly import BundleFactory
from app.api.hunt_io import C2FeedFactory
from app.api.proofpoint_tap import CampaignDetailFactory, CampaignFactory
from app.api.utils import remove_private_attributes

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
    _: Annotated[str, Query(alias="streamId")],
    __: Annotated[str, Query(alias="newerThan")],
    ___: int = Query(10, alias="count"),
    ____: int = Query(0, alias="continuation"),
):
    """Feedly Enterprise IOC Endpoint

    Returns a sample response for Feedly Enterprise IOC."""
    return BundleFactory().to_dict()


@app.get("/proofpoint-tap/v2/campaign/ids", tags=["Proofpoint TAP"])
async def proofpoint_tap_campaigns():
    """Proofpoint TAP Campaigns Endpoint

    Returns a sample response for Proofpoint TAP campaigns."""

    campaigns = CampaignFactory.create_batch(10)
    return {
        "campaigns": [
            remove_private_attributes(asdict(campaign)) for campaign in campaigns
        ],
    }


@app.get("/proofpoint-tap/v2/campaign/{campaign_id}", tags=["Proofpoint TAP"])
async def proofpoint_tap_campaign_details(campaign_id: str):
    """Proofpoint TAP Campaign Details Endpoint

    Returns a sample response for Proofpoint TAP campaign details."""
    campaign = CampaignDetailFactory.create(id=campaign_id)
    return remove_private_attributes(asdict(campaign))
