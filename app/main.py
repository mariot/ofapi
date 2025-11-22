import gzip
import io
import json
from dataclasses import asdict
from typing import Annotated

import fastapi
from fastapi import FastAPI, File, Form, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.feedly import BundleFactory
from app.api.hunt_io import C2FeedFactory
from app.api.proofpoint_tap import CampaignDetailFactory, CampaignFactory
from app.api.reversinglabs import (
    AnalysisResponseFactory,
    DomainResponseFactory,
    DownloadedFilesResponseFactory,
    HashClassificationFactory,
    ReportIntelligenceResponseFactory,
    ReportResponseFactory,
    ResolutionResponseFactory,
    UploadDetailFactory,
    UrlsResponseFactory,
)
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


@app.get(
    "/reversinglabs-spectra-analyze/api/network-threat-intel/ip/{ip}/downloaded_files/",
    tags=["ReversingLabs Spectra Analyze"],
)
async def reversinglabs_spectra_analyze_ip_downloaded_files(ip: str):
    """ReversingLabs Spectra Analyze Downloaded Files Endpoint"""
    downloaded_files_response = DownloadedFilesResponseFactory(requested_ip=ip)
    return asdict(downloaded_files_response)


@app.get(
    "/reversinglabs-spectra-analyze/api/network-threat-intel/ip/{ip}/report/",
    tags=["ReversingLabs Spectra Analyze"],
)
async def reversinglabs_spectra_analyze_ip_report(ip: str):
    """ReversingLabs Spectra Analyze Report Endpoint"""
    report_response = ReportResponseFactory(requested_ip=ip)
    return remove_private_attributes(asdict(report_response))


@app.get(
    "/reversinglabs-spectra-analyze/api/network-threat-intel/ip/{ip}/resolutions/",
    tags=["ReversingLabs Spectra Analyze"],
)
async def reversinglabs_spectra_analyze_ip_resolutions(ip: str):
    """ReversingLabs Spectra Analyze Resolutions Endpoint"""
    resolution_response = ResolutionResponseFactory(requested_ip=ip)
    return asdict(resolution_response)


@app.get(
    "/reversinglabs-spectra-analyze/api/network-threat-intel/ip/{ip}/urls/",
    tags=["ReversingLabs Spectra Analyze"],
)
async def reversinglabs_spectra_analyze_ip_urls(ip: str):
    """ReversingLabs Spectra Analyze Urls Endpoint"""
    urls_response = UrlsResponseFactory(requested_ip=ip)
    return asdict(urls_response)


@app.get(
    "/reversinglabs-spectra-analyze/api/network-threat-intel/domain/{domain}/",
    tags=["ReversingLabs Spectra Analyze"],
)
async def reversinglabs_spectra_analyze_domain(domain: str):
    """ReversingLabs Spectra Analyze Domain Endpoint"""
    domain_response = DomainResponseFactory(requested_domain=domain)
    return remove_private_attributes(asdict(domain_response))


@app.get(
    "/reversinglabs-spectra-analyze/api/network-threat-intel/url/",
    tags=["ReversingLabs Spectra Analyze"],
)
async def reversinglabs_spectra_analyze_url(url: str):
    """ReversingLabs Spectra Analyze Domain Endpoint"""
    analysis_response = AnalysisResponseFactory(requested_url=url)
    return analysis_response.to_dict()


@app.post(
    "/reversinglabs-spectra-analyze/api/uploads/",
    tags=["ReversingLabs Spectra Analyze"],
    status_code=201,
)
async def reversinglabs_spectra_analyze_upload(
    file: Annotated[UploadFile | None, File()] = None,
    url: Annotated[str, Form()] = None,
):
    """ReversingLabs Spectra Analyze Upload Endpoint"""
    filename = file.filename if file else url
    return {
        "code": 201,
        "message": "Done.",
        "detail": asdict(UploadDetailFactory(filename=filename)),
    }


@app.get(
    "/reversinglabs-spectra-analyze/api/uploads/v2/url-samples/{task_id}/",
    tags=["ReversingLabs Spectra Analyze"],
)
async def reversinglabs_spectra_analyze_check_task(
    task_id: str,  # noqa: ARG001
):
    """Check the processing status of a submitted URL."""
    return {
        "processing_status": "complete",
        "message": "Processing complete.",
        "report": remove_private_attributes(
            asdict(ReportIntelligenceResponseFactory())
        ),
    }


@app.get(
    "/reversinglabs-spectra-analyze/api/samples/v3/{hash}/classification/",
    tags=["ReversingLabs Spectra Analyze"],
)
async def reversinglabs_spectra_analyze_hash_classification(hash: str):
    """Check the processing status of a submitted URL."""
    return remove_private_attributes(asdict(HashClassificationFactory(sha1=hash)))


class Hash(BaseModel):
    hash_values: list[str]


@app.post(
    "/reversinglabs-spectra-analyze/api/samples/status/",
    tags=["ReversingLabs Spectra Analyze"],
)
async def reversinglabs_spectra_analyze_samples_status(
    hash: Hash, _: str = fastapi.Query(default="processed", alias="status")
):
    """Check the processing status of a sample."""
    return {
        "hash_type": "sha1",
        "results": [
            {"hash_value": value, "status": "processed"} for value in hash.hash_values
        ],
    }


class HashDetail(BaseModel):
    hash_values: list[str]
    fields: list[str]
    include_networkthreatintelligence: bool
    skip_reanalysis: bool


@app.post(
    "/reversinglabs-spectra-analyze/api/samples/v2/list/details/",
    tags=["ReversingLabs Spectra Analyze"],
)
async def reversinglabs_spectra_analyze_samples_list_details(
    hash_detail: HashDetail,  # noqa: ARG001
):
    """Details of a sample."""
    return {
        "count": 1,
        "next": None,
        "previous": None,
        "results": [
            remove_private_attributes(asdict(ReportIntelligenceResponseFactory()))
        ],
    }
