import gzip
import io
import json
from dataclasses import asdict
from typing import Annotated

import fastapi
from censys_platform import (
    HostAsset,
    ResponseEnvelopeHostAsset,
)
from fastapi import FastAPI, File, Form, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.censys import HostFactory
from app.api.censys_search import CertificateHitFactory, HostHitFactory
from app.api.feedly import BundleFactory
from app.api.google import GmailMessageFactory, GoogleTokenFactory
from app.api.hunt_io import C2FeedFactory
from app.api.llm import (
    AnthropicMessageFactory,
    ChatCompletionFactory,
    completion_text,
)
from app.api.microsoft import (
    ChatMessageFactory,
    TokenResponseFactory,
    fake_access_token,
    openid_configuration,
)
from app.api.palo_alto_cortex_xdr import (
    AlertFactory,
    GetAlertsResponse,
    GetAlertsResponseItem,
)
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
from app.api.shodan import ApiInfoFactory, MatchFactory
from app.api.slack import PostedMessageFactory
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


@app.get(
    "/censys/v3/global/asset/host/{host_id}",
    tags=["Censys Platform"],
)
async def censys_platform_global_asset_host(host_id: str):
    """Censys Platform Global Asset Host Endpoint

    Returns a sample response for Censys Platform global asset host."""

    class ResponseModel(ResponseEnvelopeHostAsset):
        headers: dict

    host = HostFactory(id=host_id)
    result = ResponseModel(
        headers={},
        result=HostAsset(
            extensions={},
            resource=host,
        ),
    )
    return fastapi.Response(
        content=result.model_dump_json(),
        media_type="application/vnd.censys.api.v3.host.v1+json",
    )


@app.post(
    "/palo-alto-cortex-xdr/public_api/v1/alerts/get_alerts",
    tags=["Palo Alto Cortex XDR"],
)
async def palo_alto_cortex_xdr_get_alerts(implant_id: str = Query("")):
    """Palo Alto Cortex XDR Get Alerts Endpoint

    Returns a sample response for Palo Alto Cortex XDR get alerts."""
    prevented = AlertFactory.create(
        action_pretty="Prevented (Blocked by XDR)",
        actor_process_command_line=f"hello {implant_id}/agent.exe",
    )
    detected = AlertFactory.create(
        action_pretty="Detected (Reported)",
        actor_process_command_line=f"hello {implant_id}/agent.exe",
    )
    return GetAlertsResponse(
        reply=GetAlertsResponseItem(
            total_count=1, result_count=1, alerts=[prevented, detected]
        )
    ).model_dump()


@app.get("/censys/api/v2/hosts/search", tags=["Censys Search"])
async def censys_search_hosts(
    q: str = Query(""),
    per_page: int = Query(50),
    cursor: str = Query(""),  # noqa: ARG001
):
    """Censys Search v2 Hosts Endpoint

    Cursor-paginated host search. A single page is returned, so ``links.next`` is
    always empty and clients following the cursor terminate immediately."""
    hits = HostHitFactory.create_batch(min(per_page, 10))
    return {
        "code": 200,
        "status": "OK",
        "result": {
            "query": q,
            "total": len(hits),
            "duration": 12,
            "hits": [asdict(hit) for hit in hits],
            "links": {"next": "", "prev": ""},
        },
    }


@app.get("/censys/api/v2/certificates/search", tags=["Censys Search"])
async def censys_search_certificates(
    q: str = Query(""),
    per_page: int = Query(50),
    cursor: str = Query(""),  # noqa: ARG001
):
    """Censys Search v2 Certificates Endpoint"""
    hits = CertificateHitFactory.create_batch(min(per_page, 10))
    return {
        "code": 200,
        "status": "OK",
        "result": {
            "query": q,
            "total": len(hits),
            "duration": 12,
            "hits": [asdict(hit) for hit in hits],
            "links": {"next": "", "prev": ""},
        },
    }


@app.get("/shodan/shodan/host/search", tags=["Shodan"])
async def shodan_host_search(
    query: str = Query("", alias="query"),  # noqa: ARG001
    key: str = Query(""),  # noqa: ARG001
):
    """Shodan Host Search Endpoint

    The path is doubled because the injector joins the ``/shodan/host/search``
    endpoint onto a configurable base URL, which here is ``.../shodan/``."""
    matches = MatchFactory.create_batch(5)
    return {
        "matches": [asdict(match) for match in matches],
        "total": len(matches),
    }


@app.get("/shodan/api-info", tags=["Shodan"])
async def shodan_api_info(key: str = Query("")):  # noqa: ARG001
    """Shodan API Plan Information Endpoint"""
    return asdict(ApiInfoFactory())


@app.post("/slack/api/chat.postMessage", tags=["Slack"])
async def slack_chat_post_message(payload: dict):
    """Slack ``chat.postMessage`` Endpoint

    Slack answers HTTP 200 even on failure and signals the outcome through ``ok``."""
    channel = payload.get("channel") or "C0000000000"
    message = PostedMessageFactory(text=payload.get("text") or "")
    return {
        "ok": True,
        "channel": channel,
        "ts": message.ts,
        "message": asdict(message),
    }


@app.get(
    "/microsoft-identity/{tenant_id}/v2.0/.well-known/openid-configuration",
    tags=["Microsoft Identity"],
)
async def microsoft_openid_configuration(tenant_id: str, request: fastapi.Request):
    """Microsoft Identity OIDC Discovery Endpoint

    MSAL resolves the authority through this document before requesting a token."""
    base_url = str(request.base_url).rstrip("/") + "/microsoft-identity"
    return openid_configuration(base_url, tenant_id)


@app.post(
    "/microsoft-identity/{tenant_id}/oauth2/v2.0/token",
    tags=["Microsoft Identity"],
)
async def microsoft_token(tenant_id: str, scope: Annotated[str, Form()] = ""):
    """Microsoft Identity Token Endpoint

    Accepts every grant type (client credentials for ``email-m365``, refresh token
    for ``teams``) and always mints a fresh token."""
    token = TokenResponseFactory(
        scope=scope or "https://graph.microsoft.com/.default",
        access_token=fake_access_token(tenant_id, "https://graph.microsoft.com"),
    )
    return asdict(token)


@app.post(
    "/microsoft-graph/v1.0/users/{user_id}/sendMail",
    tags=["Microsoft Graph"],
    status_code=202,
)
async def microsoft_graph_send_mail(user_id: str, payload: dict):  # noqa: ARG001
    """Microsoft Graph ``sendMail`` Endpoint

    Graph answers ``202 Accepted`` with an empty body."""
    return fastapi.Response(status_code=202)


@app.post(
    "/microsoft-graph/v1.0/teams/{team_id}/channels/{channel_id}/messages",
    tags=["Microsoft Graph"],
    status_code=201,
)
async def microsoft_graph_channel_message(
    team_id: str,
    channel_id: str,
    payload: dict,
):
    """Microsoft Graph Teams Channel Message Endpoint"""
    message = ChatMessageFactory(
        body=payload.get("body") or {"contentType": "html", "content": ""},
    )
    result = message.to_dict()
    result["webUrl"] = (
        f"https://teams.microsoft.com/l/message/{channel_id}/{message.id}"
        f"?groupId={team_id}"
    )
    return result


@app.post(
    "/microsoft-graph/v1.0/chats/{chat_id}/messages",
    tags=["Microsoft Graph"],
    status_code=201,
)
async def microsoft_graph_chat_message(chat_id: str, payload: dict):
    """Microsoft Graph Teams Chat Message Endpoint"""
    message = ChatMessageFactory(
        body=payload.get("body") or {"contentType": "html", "content": ""},
    )
    result = message.to_dict()
    result["webUrl"] = f"https://teams.microsoft.com/l/message/{chat_id}/{message.id}"
    return result


@app.post("/google-oauth2/token", tags=["Google"])
async def google_oauth2_token():
    """Google OAuth2 Token Endpoint

    google-auth posts a signed JWT assertion here when a service account is used.
    The signature is never checked, so any well-formed key works."""
    return asdict(GoogleTokenFactory())


@app.post("/gmail/v1/users/{user_id}/messages/send", tags=["Google"])
async def gmail_messages_send(user_id: str, payload: dict):  # noqa: ARG001
    """Gmail ``messages.send`` Endpoint"""
    return asdict(GmailMessageFactory())


@app.post("/openai/v1/chat/completions", tags=["OpenAI"])
async def openai_chat_completions(
    payload: dict,
    request: fastapi.Request,
    behaviour: str = Query("defended"),
):
    """OpenAI-compatible Chat Completions Endpoint

    Defended by default. Use ``?behaviour=vulnerable`` to make the fake model leak
    the ``X-OAEV-Inject-Marker`` canary, which flips an AI red-team inject to
    ``VULNERABLE``."""
    marker = request.headers.get("X-OAEV-Inject-Marker")
    text = completion_text(marker, behaviour == "vulnerable")
    completion = ChatCompletionFactory(
        model=payload.get("model") or "gpt-4o-mini",
        choices=[
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "logprobs": None,
                "finish_reason": "stop",
            }
        ],
    )
    return asdict(completion)


@app.post("/anthropic/v1/messages", tags=["OpenAI"])
async def anthropic_messages(
    payload: dict,
    request: fastapi.Request,
    behaviour: str = Query("defended"),
):
    """Anthropic Messages Endpoint

    Same defended/vulnerable behaviour as the OpenAI-compatible endpoint."""
    marker = request.headers.get("X-OAEV-Inject-Marker")
    text = completion_text(marker, behaviour == "vulnerable")
    message = AnthropicMessageFactory(
        model=payload.get("model") or "claude-3-5-sonnet-latest",
        content=[{"type": "text", "text": text}],
    )
    return asdict(message)


@app.api_route(
    "/echo",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    tags=["Echo"],
)
async def echo(request: fastapi.Request):
    """Generic Echo Endpoint

    Answers any method with a description of the request it received. Used as a
    harmless destination for the OpenAEV ``http-query`` injector, which can be
    pointed at an arbitrary URL with an arbitrary body."""
    body = (await request.body()).decode(errors="replace")
    return {
        "method": request.method,
        "path": request.url.path,
        "query": dict(request.query_params),
        "headers": dict(request.headers),
        "body": body,
    }
