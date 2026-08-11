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
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.censys import HostFactory
from app.api.censys_search import CertificateHitFactory, HostHitFactory
from app.api.cortex_xsoar import delete_indicators as xsoar_delete_indicators
from app.api.cortex_xsoar import upsert_indicator as xsoar_upsert_indicator
from app.api.feedly import BundleFactory
from app.api.google import GmailMessageFactory, GoogleTokenFactory
from app.api.harfanglab import SOURCE_TYPES as HARFANGLAB_SOURCE_TYPES
from app.api.harfanglab import create_rule as harfanglab_create_rule
from app.api.harfanglab import create_source as harfanglab_create_source_list
from app.api.harfanglab import delete_rule as harfanglab_delete_rule
from app.api.harfanglab import list_rules as harfanglab_list_rules
from app.api.harfanglab import list_sources as harfanglab_list_source_lists
from app.api.harfanglab import paginated as harfanglab_paginated
from app.api.harfanglab import update_rule as harfanglab_update_rule
from app.api.hunt_io import C2FeedFactory
from app.api.ismalicious import CheckResultFactory
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
from app.api.misp import MISP_VERSION
from app.api.misp import add_event as misp_create_event
from app.api.misp import delete_event as misp_remove_event
from app.api.misp import describe_types as misp_describe_types_payload
from app.api.misp import edit_event as misp_update_event
from app.api.misp import get_event as misp_read_event
from app.api.misp import search_events as misp_find_events
from app.api.misp import user_me as misp_user_me_payload
from app.api.palo_alto_cortex_xdr import (
    AlertFactory,
    GetAlertsResponse,
    GetAlertsResponseItem,
)
from app.api.proofpoint_tap import CampaignDetailFactory, CampaignFactory
from app.api.qradar import SET_ENTRIES as QRADAR_SET_ENTRIES
from app.api.qradar import SETS as QRADAR_SETS
from app.api.qradar import create_entry as qradar_create_entry
from app.api.qradar import create_set as qradar_create_reference_set
from app.api.qradar import search_entries as qradar_search_entries
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
from app.api.sekoia import delete_indicator as sekoia_remove_indicator
from app.api.sekoia import import_indicators as sekoia_store_indicators
from app.api.sekoia import search_indicators as sekoia_find_indicators
from app.api.shodan import ApiInfoFactory, MatchFactory
from app.api.slack import PostedMessageFactory
from app.api.splunk import collection as splunk_collection
from app.api.splunk import collection_config_entry
from app.api.splunk_soar import SOAR_VERSION
from app.api.splunk_soar import create_artifact as soar_create_artifact
from app.api.splunk_soar import create_container as soar_create_container
from app.api.splunk_soar import create_note as soar_create_note
from app.api.splunk_soar import search_containers as soar_search_containers
from app.api.splunk_soar import update_container as soar_update_container
from app.api.utils import read_form_field, remove_private_attributes

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


@app.get("/ismalicious/check", tags=["isMalicious"])
async def ismalicious_check(
    query: Annotated[str, Query()],
    _: str = Query("standard", alias="enrichment"),
):
    """isMalicious Check Endpoint

    Returns a reputation verdict for a domain, IP or hash. Backs the OpenCTI
    ``ismalicious`` internal-enrichment connector."""
    return asdict(CheckResultFactory(query=query))


@app.post(
    "/splunk/servicesNS/{owner}/{app_name}/storage/collections/config",
    tags=["Splunk"],
)
async def splunk_create_collection(
    request: fastapi.Request,
    owner: str,  # noqa: ARG001 - part of the Splunk URL layout
    app_name: str,  # noqa: ARG001 - part of the Splunk URL layout
):
    """Splunk KV Store Collection Endpoint

    Creates a KV store collection. Called once at startup by the OpenCTI
    ``splunk`` stream connector, which sends a form body while announcing
    ``Content-Type: application/json``. Splunk reads the body as a form
    whatever the header claims, so the name is parsed the same way here."""
    name = await read_form_field(request, "name")
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    splunk_collection(name)
    return collection_config_entry(name)


@app.get(
    "/splunk/servicesNS/{owner}/{app_name}/storage/collections/data/{collection_name}",
    tags=["Splunk"],
)
async def splunk_list_documents(
    owner: str,  # noqa: ARG001 - part of the Splunk URL layout
    app_name: str,  # noqa: ARG001 - part of the Splunk URL layout
    collection_name: str,
):
    """Splunk KV Store Listing Endpoint

    Returns every document of a KV store collection."""
    return splunk_collection(collection_name).values()


@app.post(
    "/splunk/servicesNS/{owner}/{app_name}/storage/collections/data/{collection_name}",
    tags=["Splunk"],
)
async def splunk_create_document(
    owner: str,  # noqa: ARG001 - part of the Splunk URL layout
    app_name: str,  # noqa: ARG001 - part of the Splunk URL layout
    collection_name: str,
    document: dict,
):
    """Splunk KV Store Insertion Endpoint

    Stores a document and answers with its ``_key``, the way Splunk does."""
    store = splunk_collection(collection_name)
    key = document.get("_key") or store.next_id()
    document["_key"] = key
    store.put(key, document)
    return {"_key": key}


@app.put(
    "/splunk/servicesNS/{owner}/{app_name}/storage/collections/data/"
    "{collection_name}/{key}",
    tags=["Splunk"],
)
async def splunk_update_document(
    owner: str,  # noqa: ARG001 - part of the Splunk URL layout
    app_name: str,  # noqa: ARG001 - part of the Splunk URL layout
    collection_name: str,
    key: str,
    document: dict,
):
    """Splunk KV Store Update Endpoint

    Replaces a document. Answers ``404`` for an unknown key, which makes the
    connector fall back to an insertion."""
    store = splunk_collection(collection_name)
    if store.get(key) is None:
        raise HTTPException(status_code=404, detail="Not found")
    document["_key"] = key
    store.put(key, document)
    return {"_key": key}


@app.delete(
    "/splunk/servicesNS/{owner}/{app_name}/storage/collections/data/"
    "{collection_name}/{key}",
    tags=["Splunk"],
)
async def splunk_delete_document(
    owner: str,  # noqa: ARG001 - part of the Splunk URL layout
    app_name: str,  # noqa: ARG001 - part of the Splunk URL layout
    collection_name: str,
    key: str,
):
    """Splunk KV Store Deletion Endpoint

    Removes a document, answering ``404`` when it is already gone."""
    if splunk_collection(collection_name).pop(key) is None:
        raise HTTPException(status_code=404, detail="Not found")
    return {"_key": key}


@app.get("/qradar/api/reference_data_collections/sets", tags=["QRadar"])
async def qradar_list_sets():
    """QRadar Reference Sets Endpoint

    Returns the reference sets as a bare array, the way QRadar does."""
    return QRADAR_SETS.values()


@app.post("/qradar/api/reference_data_collections/sets", tags=["QRadar"])
async def qradar_create_set(reference_set: dict):
    """QRadar Reference Set Creation Endpoint"""
    return qradar_create_reference_set(
        name=reference_set.get("name", ""),
        entry_type=reference_set.get("entry_type", "ALNIC"),
    )


@app.get("/qradar/api/reference_data_collections/set_entries", tags=["QRadar"])
async def qradar_list_set_entries(filter: str | None = Query(None)):  # noqa: A002
    """QRadar Reference Set Entries Endpoint

    Resolves QRadar's ``collection_id=<id> and notes="<uuid>"`` filter, which is
    how the connector finds the entry to update or delete."""
    return qradar_search_entries(filter)


@app.post("/qradar/api/reference_data_collections/set_entries", tags=["QRadar"])
async def qradar_create_set_entry(entry: dict):
    """QRadar Reference Set Entry Creation Endpoint"""
    return qradar_create_entry(
        collection_id=entry.get("collection_id", ""),
        value=entry.get("value", ""),
        source=entry.get("source", "OpenCTI"),
        notes=entry.get("notes", ""),
    )


@app.post(
    "/qradar/api/reference_data_collections/set_entries/{entry_id}", tags=["QRadar"]
)
async def qradar_update_set_entry(entry_id: str, entry: dict):
    """QRadar Reference Set Entry Update Endpoint"""
    stored = QRADAR_SET_ENTRIES.get(entry_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Not found")
    stored.update({key: value for key, value in entry.items() if key != "id"})
    return stored


@app.delete(
    "/qradar/api/reference_data_collections/set_entries/{entry_id}", tags=["QRadar"]
)
async def qradar_delete_set_entry(entry_id: str):
    """QRadar Reference Set Entry Deletion Endpoint"""
    stored = QRADAR_SET_ENTRIES.pop(entry_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Not found")
    return stored


@app.get("/harfanglab/api/data/threat_intelligence/{source_type}", tags=["HarfangLab"])
async def harfanglab_list_sources(
    source_type: str,
    name__exact: str | None = Query(None),
    source_id: str | None = Query(None),
    type: str | None = Query(None),  # noqa: A002 - mirrors the vendor's parameter
    value__exact: str | None = Query(None),
):
    """HarfangLab Threat Intelligence Listing Endpoint

    Serves both the source lists (``IOCSource``, ``SigmaSource``,
    ``YaraSource``) and the ``IOCRule`` lookups the connector performs before an
    update or a deletion."""
    if source_type in HARFANGLAB_SOURCE_TYPES:
        return harfanglab_paginated(
            harfanglab_list_source_lists(source_type, name__exact)
        )
    if source_type == "IOCRule":
        return harfanglab_paginated(
            harfanglab_list_rules(source_id, type, value__exact)
        )
    raise HTTPException(status_code=404, detail="Unknown threat intelligence type")


@app.post("/harfanglab/api/data/threat_intelligence/{source_type}", tags=["HarfangLab"])
@app.post(
    "/harfanglab/api/data/threat_intelligence/{source_type}/",
    tags=["HarfangLab"],
    include_in_schema=False,
)
async def harfanglab_create_source(source_type: str, body: dict):
    """HarfangLab Threat Intelligence Creation Endpoint

    Creates a source list, or an IOC rule when ``source_type`` is ``IOCRule``.
    The trailing slash the connector appends when it writes an IOC rule is
    served directly, so the write is not answered with a redirect."""
    if source_type in HARFANGLAB_SOURCE_TYPES:
        return harfanglab_create_source_list(
            source_type=source_type,
            name=body.get("name", ""),
            description=body.get("description", ""),
            enabled=body.get("enabled", True),
        )
    if source_type == "IOCRule":
        return harfanglab_create_rule(body)
    raise HTTPException(status_code=404, detail="Unknown threat intelligence type")


@app.patch(
    "/harfanglab/api/data/threat_intelligence/IOCRule/{rule_id}", tags=["HarfangLab"]
)
async def harfanglab_patch_ioc_rule(rule_id: str, body: dict):
    """HarfangLab IOC Rule Update Endpoint"""
    stored = harfanglab_update_rule(rule_id, body)
    if stored is None:
        raise HTTPException(status_code=404, detail="Not found")
    return stored


@app.delete(
    "/harfanglab/api/data/threat_intelligence/IOCRule/{rule_id}", tags=["HarfangLab"]
)
async def harfanglab_delete_ioc_rule(rule_id: str):
    """HarfangLab IOC Rule Deletion Endpoint"""
    if harfanglab_delete_rule(rule_id) is None:
        raise HTTPException(status_code=404, detail="Not found")
    return fastapi.Response(status_code=204)


@app.get("/sekoia/{collection_id}", tags=["Sekoia"])
async def sekoia_get_collection(collection_id: str):
    """Sekoia IOC Collection Endpoint

    Confirms that the configured IOC collection exists."""
    return {"id": collection_id, "name": "OpenCTI", "type": "collection"}


@app.post("/sekoia/{collection_id}/indicators/text", tags=["Sekoia"])
async def sekoia_import_indicators(
    collection_id: str,  # noqa: ARG001 - part of the Sekoia URL layout
    body: dict,
):
    """Sekoia IOC Import Endpoint

    Imports newline-separated indicators into the collection."""
    return sekoia_store_indicators(body.get("indicators", ""))


@app.get("/sekoia/{collection_id}/indicators", tags=["Sekoia"])
async def sekoia_search_indicators(
    collection_id: str,  # noqa: ARG001 - part of the Sekoia URL layout
    term: str | None = Query(None),
):
    """Sekoia IOC Search Endpoint

    Resolves the indicators the connector is about to delete."""
    return sekoia_find_indicators(term)


@app.delete("/sekoia/{collection_id}/indicators/{indicator_id}", tags=["Sekoia"])
async def sekoia_delete_indicator(
    collection_id: str,  # noqa: ARG001 - part of the Sekoia URL layout
    indicator_id: str,
):
    """Sekoia IOC Deletion Endpoint"""
    if sekoia_remove_indicator(indicator_id) is None:
        raise HTTPException(status_code=404, detail="Not found")
    return {"id": indicator_id, "deleted": True}


@app.post("/cortex-xsoar/xsoar/public/v1/indicator/create", tags=["Cortex XSOAR"])
async def cortex_xsoar_create_indicator(body: dict):
    """Cortex XSOAR Indicator Creation Endpoint"""
    return xsoar_upsert_indicator(body)


@app.post("/cortex-xsoar/xsoar/public/v1/indicator/edit", tags=["Cortex XSOAR"])
async def cortex_xsoar_edit_indicator(body: dict):
    """Cortex XSOAR Indicator Update Endpoint"""
    return xsoar_upsert_indicator(body)


@app.post("/cortex-xsoar/xsoar/public/v1/indicators/batchDelete", tags=["Cortex XSOAR"])
async def cortex_xsoar_batch_delete_indicators(body: dict):
    """Cortex XSOAR Indicator Batch Deletion Endpoint"""
    return xsoar_delete_indicators(body)


@app.get("/misp/servers/getVersion", tags=["MISP"])
@app.get("/servers/getVersion", tags=["MISP"], include_in_schema=False)
async def misp_get_version():
    """MISP Version Endpoint

    First call PyMISP makes; the permission flags it returns decide which
    features PyMISP enables."""
    return {
        "version": MISP_VERSION,
        "perm_sync": True,
        "perm_sighting": True,
        "perm_galaxy_editor": True,
        "request_encoding": ["gzip"],
    }


@app.get("/misp/servers/getPyMISPVersion.json", tags=["MISP"])
@app.get("/servers/getPyMISPVersion.json", tags=["MISP"], include_in_schema=False)
async def misp_get_pymisp_version():
    """MISP Recommended PyMISP Version Endpoint"""
    return {"version": MISP_VERSION}


@app.get("/misp/users/view/me", tags=["MISP"])
@app.get("/users/view/me", tags=["MISP"], include_in_schema=False)
async def misp_user_me():
    """MISP Current User Endpoint"""
    return misp_user_me_payload()


@app.get("/misp/attributes/describeTypes.json", tags=["MISP"])
@app.get("/attributes/describeTypes.json", tags=["MISP"], include_in_schema=False)
async def misp_describe_types():
    """MISP Attribute Types Endpoint"""
    return misp_describe_types_payload()


@app.post("/misp/events/add", tags=["MISP"])
@app.post("/events/add", tags=["MISP"], include_in_schema=False)
async def misp_add_event(body: dict):
    """MISP Event Creation Endpoint"""
    return misp_create_event(body)


@app.get("/misp/events/view/{event_id}", tags=["MISP"])
@app.get("/events/view/{event_id}", tags=["MISP"], include_in_schema=False)
async def misp_view_event(event_id: str):
    """MISP Event Read Endpoint"""
    stored = misp_read_event(event_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Not found")
    return stored


@app.post("/misp/events/edit/{event_id}", tags=["MISP"])
@app.post("/events/edit/{event_id}", tags=["MISP"], include_in_schema=False)
async def misp_edit_event(event_id: str, body: dict):
    """MISP Event Update Endpoint"""
    stored = misp_update_event(event_id, body)
    if stored is None:
        raise HTTPException(status_code=404, detail="Not found")
    return stored


@app.post("/misp/events/publish/{event_id}", tags=["MISP"])
@app.post("/events/publish/{event_id}", tags=["MISP"], include_in_schema=False)
async def misp_publish_event(event_id: str):
    """MISP Event Publication Endpoint"""
    return {"message": f"Job queued for event {event_id}", "saved": True}


@app.post("/misp/events/delete/{event_id}", tags=["MISP"])
@app.delete("/misp/events/delete/{event_id}", tags=["MISP"], include_in_schema=False)
@app.post("/events/delete/{event_id}", tags=["MISP"], include_in_schema=False)
@app.delete("/events/delete/{event_id}", tags=["MISP"], include_in_schema=False)
async def misp_delete_event_by_id(event_id: str):
    """MISP Event Deletion Endpoint

    PyMISP deletes with POST, so both verbs are accepted."""
    return misp_remove_event(event_id)


@app.post("/misp/eventBlocklists/delete/{event_id}", tags=["MISP"])
@app.post("/eventBlocklists/delete/{event_id}", tags=["MISP"], include_in_schema=False)
async def misp_delete_event_blocklist(event_id: str):
    """MISP Event Blocklist Deletion Endpoint

    PyMISP unblocklists an event right after deleting it, so the connector only
    behaves when this answers even though nothing was ever blocklisted."""
    return {
        "saved": True,
        "success": True,
        "name": f"Blocklist entry {event_id} removed",
        "message": f"Blocklist entry {event_id} removed",
        "url": f"/eventBlocklists/delete/{event_id}",
    }


@app.post("/misp/events/restSearch", tags=["MISP"])
@app.post("/events/restSearch", tags=["MISP"], include_in_schema=False)
async def misp_rest_search(body: dict):
    """MISP Event Search Endpoint"""
    return {"response": misp_find_events(body)}


@app.get("/splunk-soar/rest/version", tags=["Splunk SOAR"])
async def splunk_soar_version():
    """Splunk SOAR Version Endpoint

    Used by the connector as a connection test at startup."""
    return {"version": SOAR_VERSION, "build": "305"}


@app.get("/splunk-soar/rest/container", tags=["Splunk SOAR"])
async def splunk_soar_list_containers(
    external_id: str | None = Query(None, alias="_filter_external_id"),
):
    """Splunk SOAR Container Search Endpoint

    Resolves a container from the OpenCTI id stored in ``external_id``."""
    return soar_search_containers(external_id)


@app.post("/splunk-soar/rest/container", tags=["Splunk SOAR"])
async def splunk_soar_create_container(body: dict):
    """Splunk SOAR Container Creation Endpoint"""
    return soar_create_container(body)


@app.post("/splunk-soar/rest/container/{container_id}", tags=["Splunk SOAR"])
async def splunk_soar_update_container(container_id: str, body: dict):
    """Splunk SOAR Container Update Endpoint"""
    stored = soar_update_container(container_id, body)
    if stored is None:
        raise HTTPException(status_code=404, detail="Not found")
    return stored


@app.post("/splunk-soar/rest/artifact", tags=["Splunk SOAR"])
async def splunk_soar_create_artifact(body: dict):
    """Splunk SOAR Artifact Creation Endpoint"""
    return soar_create_artifact(body)


@app.post("/splunk-soar/rest/note", tags=["Splunk SOAR"])
async def splunk_soar_create_note(body: dict):
    """Splunk SOAR Note Creation Endpoint"""
    return soar_create_note(body)
