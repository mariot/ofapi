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
from app.api.crowdstrike import (
    EntitiesAlertsResponse,
    QueryAlertsResponse,
    TokenResponseFactory as CrowdstrikeTokenResponseFactory,
)
from app.api.elastic import SearchResponse as ElasticSearchResponse
from app.api.feedly import BundleFactory
from app.api.google import GmailMessageFactory, GoogleTokenFactory
from app.api.hunt_io import C2FeedFactory
from app.api.llm import (
    AnthropicMessageFactory,
    ChatCompletionFactory,
    completion_text,
)
from app.api.logrhythm import (
    SearchResultResponse as LogRhythmSearchResultResponse,
    SearchTaskResponseFactory as LogRhythmSearchTaskResponseFactory,
)
from app.api.microsoft import (
    ChatMessageFactory,
    TokenResponseFactory,
    fake_access_token,
    openid_configuration,
)
from app.api.netwitness import SdkQueryResponse as NetWitnessSdkQueryResponse
from app.api.palo_alto_cortex_xdr import (
    AlertEvent,
    AlertFactory,
    Alerts,
    FileArtifacts,
    GetAlertsResponse,
    GetAlertsResponseItem,
    GetIncidentExtraDataResponse,
    GetOriginalAlertsResponse,
    Incident,
    IncidentItem,
)
from app.api.palo_alto_cortex_xsoar import XSOARSearchIncidentsResponse
from app.api.proofpoint_tap import CampaignDetailFactory, CampaignFactory
from app.api.qradar import (
    CreateSearchResponseFactory,
    SearchResultsResponse,
    SearchStatusResponse,
)
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
from app.api.sentinelone import (
    DVEventsResponse,
    DVInitQueryData,
    DVInitQueryResponse,
    DVQueryStatusData,
    DVQueryStatusResponse,
    ThreatEventsResponse,
    ThreatsResponse,
)
from app.api.shodan import ApiInfoFactory, MatchFactory
from app.api.slack import PostedMessageFactory
from app.api.splunk_es import SearchJobResponse
from app.api.utils import remove_private_attributes
from app.api.xtm_one import AgentsResponse, AuditLogsResponse

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


@app.post("/crowdstrike/oauth2/token", tags=["CrowdStrike"], status_code=201)
async def crowdstrike_oauth2_token(
    client_id: Annotated[str, Form()] = "",
    client_secret: Annotated[str, Form()] = "",
):
    """CrowdStrike OAuth2 Token Endpoint

    Returns a fake bearer token for the CrowdStrike Falcon API (falconpy SDK)."""
    return CrowdstrikeTokenResponseFactory().model_dump()


@app.get(
    "/crowdstrike/alerts/queries/alerts/v2",
    tags=["CrowdStrike"],
    response_model=QueryAlertsResponse,
)
async def crowdstrike_query_alerts_v2(filter: str = Query("")):  # noqa: A002
    """CrowdStrike Query Alerts Endpoint

    Returns an empty list of matching alert composite ids."""
    return QueryAlertsResponse()


@app.post(
    "/crowdstrike/alerts/entities/alerts/v2",
    tags=["CrowdStrike"],
    response_model=EntitiesAlertsResponse,
)
async def crowdstrike_entities_alerts_v2():
    """CrowdStrike Get Alert Entities Endpoint

    Returns the details for the requested composite alert ids."""
    return EntitiesAlertsResponse()


@app.get("/tanium/plugin/products/threat-response/api/v1/alerts", tags=["Tanium"])
async def tanium_threat_response_alerts():
    """Tanium Threat Response Alerts Endpoint

    Returns an empty list of alerts, matching the ``{"data": [...]}`` shape
    the Tanium Threat Response API returns."""
    return {"data": []}


@app.get(
    "/xtm-one/api/v1/agents", tags=["XTM One"], response_model=AgentsResponse
)
async def xtm_one_agents():
    """XTM One Agents Catalog Endpoint

    Returns the chat-capable agents catalog (empty by default)."""
    return AgentsResponse()


@app.get(
    "/xtm-one/api/v1/audit-logs", tags=["XTM One"], response_model=AuditLogsResponse
)
async def xtm_one_audit_logs():
    """XTM One Audit Logs Endpoint

    Returns the security audit log used to validate prompt-injection detection
    expectations (empty by default)."""
    return AuditLogsResponse()


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


# ---------------------------------------------------------------------------
# ==== Elastic ====
# Collector: collectors/elastic (raw `requests`, no official elasticsearch-py
# client, so there is NO X-Elastic-Product header quirk to satisfy). Only one
# endpoint is ever called: POST {base_url}/{alerts_index}/_search.
# Auth: `Authorization: ApiKey <key>` OR HTTP Basic (username/password) -
# both are accepted unconditionally here (fake server does not enforce auth).
# ---------------------------------------------------------------------------


@app.post(
    "/elastic/{index}/_search",
    tags=["Elastic"],
    response_model=ElasticSearchResponse,
)
async def elastic_search(index: str, body: dict):  # noqa: ARG001
    """Elastic Security Detection Alerts Search Endpoint

    Fakes the Elasticsearch `_search` API used to query the detection alerts
    index (default `.alerts-security.alerts-*`). Returns an empty `hits.hits`
    list, which `ElasticResponse.from_raw_response` parses via defensive
    `dict.get` lookups with no KeyError risk."""
    return ElasticSearchResponse()


# ---------------------------------------------------------------------------
# ==== LogRhythm ====
# Collector: collectors/logrhythm (raw `requests`, no vendor SDK). Two-step
# Search API flow: create a search task, then poll for its result.
# Auth: bearer token or HTTP Basic - accepted unconditionally here.
# QUIRK: the search-result endpoint MUST return `TaskStatus: "Completed"` on
# the very first poll, otherwise the collector busy-polls every
# `poll_interval` until `search_timeout` (default 5 minutes) elapses before
# raising LogRhythmTimeoutError.
# ---------------------------------------------------------------------------


@app.post(
    "/logrhythm/lr-search-api/actions/search-task",
    tags=["LogRhythm"],
)
async def logrhythm_search_task(body: dict):  # noqa: ARG001
    """LogRhythm Search API - Create Search Task Endpoint

    Returns a fake `TaskId`; the collector requires a truthy `TaskId` (or
    `taskId`) or it raises `LogRhythmQueryError`."""
    return LogRhythmSearchTaskResponseFactory().model_dump()


@app.post(
    "/logrhythm/lr-search-api/actions/search-result",
    tags=["LogRhythm"],
    response_model=LogRhythmSearchResultResponse,
)
async def logrhythm_search_result(body: dict):  # noqa: ARG001
    """LogRhythm Search API - Poll Search Result Endpoint

    Returns `TaskStatus: "Completed"` immediately with an empty `Items` list
    so the collector's polling loop exits on the first call instead of
    waiting out the full `search_timeout`."""
    return LogRhythmSearchResultResponse()


# ---------------------------------------------------------------------------
# ==== NetWitness ====
# Collector: collectors/netwitness (raw `requests`, no vendor SDK). Single
# endpoint: GET {base_url}/sdk?msg=query&query=<NWQL>&
# force-content-type=application/json&size=<max_results>.
# Auth: bearer token or HTTP Basic - accepted unconditionally here. No
# login/token endpoint exists on the real API.
# ---------------------------------------------------------------------------


@app.get(
    "/netwitness/sdk",
    tags=["NetWitness"],
    response_model=NetWitnessSdkQueryResponse,
)
async def netwitness_sdk_query(
    msg: str = Query(""),  # noqa: ARG001
    query: str = Query(""),  # noqa: ARG001
    size: int = Query(100),  # noqa: ARG001
    force_content_type: str = Query("", alias="force-content-type"),  # noqa: ARG001
):
    """RSA NetWitness Core SDK Query Endpoint

    Fakes the `msg=query` NWQL query interface. Returns an empty
    `results.fields` list, which `NetWitnessResponse.from_raw_response`
    parses via defensive `dict.get` lookups with no KeyError risk."""
    return NetWitnessSdkQueryResponse()


# ============================================================================
# ==== Palo Alto Cortex XDR (collector) — additional endpoints ====
# The existing `/palo-alto-cortex-xdr/public_api/v1/alerts/get_alerts` route
# fakes the *injector's* endpoint. The palo-alto-cortex-xdr COLLECTOR instead
# calls `get_alerts_multi_events`, `get_original_alerts`, and (unused today,
# but present on the client for future use) `get_incident_extra_data`.
# All three share the same header-based auth as the existing route: either
# STANDARD (`x-xdr-auth-id` + `Authorization: <api_key>`) or ADVANCED
# (adds `x-xdr-timestamp` + `x-xdr-nonce`, `Authorization` becomes an HMAC
# sha256 of api_key+nonce+timestamp). Like the existing route and the
# crowdstrike/oauth2 fake, signatures are NOT validated here — any headers
# are accepted, which is sufficient for the collector's `raise_for_status()`
# happy-path testing.
# ============================================================================


@app.post(
    "/palo-alto-cortex-xdr/public_api/v1/alerts/get_alerts_multi_events",
    tags=["Palo Alto Cortex XDR"],
)
async def palo_alto_cortex_xdr_get_alerts_multi_events(implant_id: str = Query("")):
    """Palo Alto Cortex XDR Get Alerts (Multi Events) Endpoint

    Fakes ``POST https://{fqdn}/public_api/v1/alerts/get_alerts_multi_events``,
    called by ``PaloAltoCortexXDRClientAPI.get_alerts`` (src/services/client_api.py).
    The real collector's ``AlertFetcher`` looks for an implant name directly in
    ``alert.events[].actor_process_image_name`` (matching ``oaev-implant-...``);
    when present it uses the alert immediately, otherwise it falls back to
    ``get_original_alerts`` for enrichment. Returning the implant directly in
    ``events`` here lets a fake collector run skip enrichment fully.
    """
    alert = AlertFactory.create(
        events=[
            AlertEvent(
                actor_process_image_name=f"oaev-implant-{implant_id}-agent-1.exe"
            )
        ],
    )
    return GetAlertsResponse(
        reply=GetAlertsResponseItem(total_count=1, result_count=1, alerts=[alert])
    ).model_dump()


@app.post(
    "/palo-alto-cortex-xdr/public_api/v1/alerts/get_original_alerts",
    tags=["Palo Alto Cortex XDR"],
)
async def palo_alto_cortex_xdr_get_original_alerts():
    """Palo Alto Cortex XDR Get Original Alerts Endpoint

    Fakes ``POST https://{fqdn}/public_api/v1/alerts/get_original_alerts``,
    used by ``AlertFetcher._enrich_alerts`` to enrich alerts that had no
    direct implant reference in their events. Since
    ``get_alerts_multi_events`` above already embeds the implant directly,
    this enrichment path is not exercised in the happy path; return an empty
    list by default (matching ``{"reply": {"alerts": []}}``).
    """
    return GetOriginalAlertsResponse(reply={"alerts": []}).model_dump()


@app.post(
    "/palo-alto-cortex-xdr/public_api/v1/incidents/get_incident_extra_data",
    tags=["Palo Alto Cortex XDR"],
)
async def palo_alto_cortex_xdr_get_incident_extra_data():
    """Palo Alto Cortex XDR Get Incident Extra Data Endpoint

    Fakes ``POST https://{fqdn}/public_api/v1/incidents/get_incident_extra_data``.
    Defined on ``PaloAltoCortexXDRClientAPI.get_incident_extra_data`` but not
    currently called anywhere in ``AlertFetcher``/``collector.py`` — added for
    completeness/future use. Returns an empty incident shell.
    """
    return GetIncidentExtraDataResponse(
        reply=Incident(
            incident=IncidentItem(incident_id=1),
            alerts=Alerts(),
            file_artifacts=FileArtifacts(),
        )
    ).model_dump()


# ============================================================================
# ==== Palo Alto Cortex XSOAR (collector) ====
# Only one endpoint is called by this collector. Auth uses the same
# STANDARD/ADVANCED header scheme as XDR (`x-xdr-auth-id` always present;
# ADVANCED adds `x-xdr-timestamp`/`x-xdr-nonce` and HMACs `Authorization`).
# As with XDR/crowdstrike, no signature validation is performed here.
# ============================================================================


@app.post(
    "/palo-alto-cortex-xsoar/xsoar/public/v1/incidents/search",
    tags=["Palo Alto Cortex XSOAR"],
)
async def palo_alto_cortex_xsoar_search_incidents():
    """Palo Alto Cortex XSOAR Search Incidents Endpoint

    Fakes ``POST {api_url}/xsoar/public/v1/incidents/search``, called by
    ``PaloAltoCortexXSOARClientAPI.search_incidents``
    (src/services/client_api.py). The collector paginates via
    ``filter.page``/``filter.size`` and reads ``CustomFields.xdralerts`` off
    each incident. Returns zero incidents by default so ``AlertFetcher``
    terminates pagination immediately.
    """
    return XSOARSearchIncidentsResponse(total=0, data=[]).model_dump()


# ============================================================================
# ==== SentinelOne (collector) ====
# Auth is a simple static bearer-style header: `Authorization: ApiToken
# {api_key}` set once on the requests.Session (see
# SentinelOneClientAPI._create_session) — no HMAC/signature scheme at all,
# so nothing to validate/skip here beyond accepting any Authorization value.
# ============================================================================


@app.get("/sentinelone/web/api/v2.1/threats", tags=["SentinelOne"])
async def sentinelone_get_threats(
    createdAt__gte: str = Query(""),  # noqa: N803
    createdAt__lt: str = Query(""),  # noqa: N803
    sortOrder: str = Query("desc"),  # noqa: N803
    limit: int = Query(1000),
):
    """SentinelOne Get Threats Endpoint

    Fakes ``GET {base_url}/web/api/v2.1/threats``, called by
    ``FetcherThreat.fetch_threats_for_time_window``
    (src/services/fetcher_threat.py). Returns an empty ``data`` list by
    default; the response shape mirrors the raw vendor payload
    (``threatInfo``/``agentRealtimeInfo``/``mitigationStatus``) consumed by
    ``SentinelOneThreatsResponse.from_raw_response``.
    """
    return ThreatsResponse().model_dump()


@app.get(
    "/sentinelone/web/api/v2.1/threats/{threat_id}/explore/events",
    tags=["SentinelOne"],
)
async def sentinelone_get_threat_events(threat_id: str, limit: int = Query(100)):
    """SentinelOne Get Threat Events Endpoint

    Fakes ``GET {base_url}/web/api/v2.1/threats/{threat_id}/explore/events``,
    called by ``FetcherThreatEvents._fetch_all_events_for_threat``
    (src/services/fetcher_threat_events.py). Returns an empty ``data`` list.
    """
    return ThreatEventsResponse().model_dump()


@app.post("/sentinelone/web/api/v2.1/dv/init-query", tags=["SentinelOne"])
async def sentinelone_dv_init_query():
    """SentinelOne Deep Visibility Init Query Endpoint

    Fakes ``POST {base_url}/web/api/v2.1/dv/init-query``, called by
    ``FetcherDeepVisibility._init_dv_query``
    (src/services/fetcher_deep_visibility.py). Returns a fixed ``queryId`` so
    the collector can immediately proceed to poll query-status.
    """
    return DVInitQueryResponse(
        data=DVInitQueryData(queryId="fake-query-id")
    ).model_dump()


@app.get("/sentinelone/web/api/v2.1/dv/query-status", tags=["SentinelOne"])
async def sentinelone_dv_query_status(queryId: str = Query("")):  # noqa: N803
    """SentinelOne Deep Visibility Query Status Endpoint

    Fakes ``GET {base_url}/web/api/v2.1/dv/query-status``, polled by
    ``FetcherDeepVisibility._wait_for_query_completion``. Always reports
    ``responseState: "FINISHED"`` / ``progressStatus: 100`` immediately so the
    collector's poll loop (up to 30 attempts) exits on the first call.
    """
    return DVQueryStatusResponse(data=DVQueryStatusData()).model_dump()


@app.get("/sentinelone/web/api/v2.1/dv/events", tags=["SentinelOne"])
async def sentinelone_dv_events(queryId: str = Query("")):  # noqa: N803
    """SentinelOne Deep Visibility Events Endpoint

    Fakes ``GET {base_url}/web/api/v2.1/dv/events``, called by
    ``FetcherDeepVisibility._make_real_events_query``. Returns an empty
    ``data`` list.
    """
    return DVEventsResponse().model_dump()


# ============================================================================
# ==== QRadar ====
# ============================================================================
#
# Real collector flow (collectors/qradar/src/services/client_api.py):
#   1. POST {base_url}/api/ariel/searches?query_expression=<AQL>
#        -> creates an Ariel search, response must contain "search_id".
#        Auth: "SEC" header (token) or HTTP Basic. "Version" header sent by
#        client but not required to be validated by the fake.
#   2. GET  {base_url}/api/ariel/searches/{search_id}
#        -> polled until response["status"] == "COMPLETED" (raises on
#        "ERROR"/"CANCELED"). Real IBM QRadar reports "WAIT"/"SORTING"/etc.
#        while running; here we take the simpler approach and report
#        "COMPLETED" on the very first poll. This is fine since we don't need
#        to simulate realistic async delay for test purposes, and it avoids
#        having to keep in-memory per-search poll-count state.
#   3. GET  {base_url}/api/ariel/searches/{search_id}/results
#        (with a "Range: items=0-N" header) -> response is a dict keyed by
#        the Ariel *data source* name (default "events", can be "flows"),
#        e.g. {"events": [...]}. The data source name is embedded in the AQL
#        query text ("FROM <data_source> WHERE ..."), not sent as a separate
#        parameter, so the fake below parses it back out of the AQL that was
#        supplied at search-creation time (stored in an in-memory dict keyed
#        by search_id) to always answer with the right key. Falls back to
#        "events" if parsing fails.
#
# In-memory quirk: a small process-local dict (`_QRADAR_SEARCHES`) maps
# search_id -> data_source, populated in the create-search handler and read
# by the results handler. This is the only piece of state needed since the
# job is always "instantly complete".

_QRADAR_SEARCHES: dict[str, str] = {}


def _qradar_parse_data_source(aql: str) -> str:
    """Best-effort parse of the Ariel data source name out of an AQL string.

    Looks for "FROM <data_source>" (case-insensitive); defaults to "events".
    """
    import re

    match = re.search(r"\bFROM\s+(\w+)", aql or "", re.IGNORECASE)
    return match.group(1) if match else "events"


@app.post(
    "/qradar/api/ariel/searches",
    tags=["QRadar"],
    status_code=201,
)
async def qradar_create_search(query_expression: str = Query("")):
    """QRadar Ariel Create Search Endpoint

    Fakes ``POST /api/ariel/searches``. Records the data source parsed from
    the AQL so the results endpoint can answer with the matching key."""
    search = CreateSearchResponseFactory()
    _QRADAR_SEARCHES[search.search_id] = _qradar_parse_data_source(query_expression)
    return search.model_dump()


@app.get(
    "/qradar/api/ariel/searches/{search_id}",
    tags=["QRadar"],
    response_model=SearchStatusResponse,
)
async def qradar_search_status(search_id: str):
    """QRadar Ariel Search Status Endpoint

    Fakes ``GET /api/ariel/searches/{search_id}``. Always reports the search
    as already "COMPLETED" on the first poll (see module-level note above)."""
    return SearchStatusResponse(search_id=search_id)


@app.get(
    "/qradar/api/ariel/searches/{search_id}/results",
    tags=["QRadar"],
)
async def qradar_search_results(search_id: str):
    """QRadar Ariel Search Results Endpoint

    Fakes ``GET /api/ariel/searches/{search_id}/results``. Returns an empty
    row list keyed by the data source recorded at search-creation time."""
    data_source = _QRADAR_SEARCHES.get(search_id, "events")
    return SearchResultsResponse.for_data_source(data_source)


# ============================================================================
# ==== Splunk ES ====
# ============================================================================
#
# Real collector flow (collectors/splunk-es/src/services/client_api.py):
#   POST {base_url}/services/search/jobs
#     body (form-urlencoded): search=<SPL>, exec_mode=oneshot,
#     output_mode=json, count=0
#     Auth: HTTP Basic (username/password).
#
# Quirk: the collector always passes exec_mode=oneshot, which tells real
# Splunk to run the search synchronously and return the final results in
# this same HTTP response - there is NO separate job-id/status-polling/
# results-fetch sequence for this collector (unlike a normal Splunk search
# job, which would return a "sid" to poll via
# /services/search/jobs/{sid} and /services/search/jobs/{sid}/results).
# So a single stateless route fully satisfies this collector; no in-memory
# job store is needed.


@app.post(
    "/splunk-es/services/search/jobs",
    tags=["Splunk ES"],
)
async def splunk_es_search_jobs_oneshot():
    """Splunk ES Oneshot Search Endpoint

    Fakes ``POST /services/search/jobs`` with ``exec_mode=oneshot``. Returns
    the final (empty) results directly, matching real Splunk's synchronous
    oneshot behavior."""
    return SearchJobResponse().model_dump()


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
