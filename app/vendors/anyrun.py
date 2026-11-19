"""ANY.RUN: TI Feeds (TAXII), TI Lookup and Sandbox, read through the anyrun SDK by the
OpenCTI anyrun-feed, anyrun-lookup and anyrun-task connectors."""

import asyncio
import json
from datetime import UTC, datetime
from urllib.parse import quote

from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse

from app.fake import fake

HOSTS = ["api.any.run"]
router = APIRouter(prefix="/anyrun", tags=["ANY.RUN"])

TAXII_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
TASK_UUID = "2c8a4d1e-6f3b-4e7a-9b5d-0a1c3e5f7b92"


def _now() -> str:
    return datetime.now(UTC).strftime(TAXII_DATE_FORMAT)


def _feed_indicator() -> dict:
    kind, value = fake.random_element(
        [
            ("domain-name", fake.domain_name()),
            ("ipv4-addr", fake.ipv4_public()),
            ("url", fake.url()),
        ]
    )
    stamp = fake.date_time_between("-2d", "now", tzinfo=UTC).strftime(TAXII_DATE_FORMAT)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{fake.uuid4()}",
        "created": stamp,
        "modified": stamp,
        "name": value,
        "pattern": f"[{kind}:value = '{value}']",
        "pattern_type": "stix",
        "valid_from": stamp,
        "labels": [fake.malware_family().lower(), "malware"],
        "confidence": fake.random_element([50, 75, 100]),
        "external_references": [
            {
                "source_name": f"ANY.RUN analysis {fake.uuid4()}",
                "url": f"https://app.any.run/tasks/{fake.uuid4()}",
            }
        ],
    }


@router.get("/v1/feeds/taxii2/api1/collections/{collection_id}/objects/")
async def taxii_objects(collection_id: str, response: Response) -> dict:
    """One page of TAXII indicators (no ``next``, so the iterator stops)."""
    response.headers["X-TAXII-Date-Modified-Last"] = _now()
    return {
        "more": False,
        "objects": [_feed_indicator() for _ in range(8)],
        "collection": collection_id,
    }


def _related(count: int, key: str, value) -> list[dict]:
    return [
        {
            key: value(),
            "date": _now(),
            "threatLevel": fake.random_element([0, 1, 2]),
            "threatName": [fake.malware_family().lower()],
            "isMalconf": False,
        }
        for _ in range(count)
    ]


@router.get("/v1/intelligence/keycheck")
async def keycheck() -> dict:
    return {"status": "ok"}


@router.post("/v1/intelligence/api/search")
async def lookup_search(request: Request) -> dict:
    """A malicious lookup summary with related DNS, URLs, IPs, geolocation and tasks."""
    query = (await request.json()).get("query", "")
    return {
        "query": query,
        "summary": {
            "threatLevel": 2,
            "lastSeen": _now(),
            "tags": [fake.malware_family().lower(), "stealer"],
        },
        "destinationPort": [443, 8080],
        "destinationIPgeo": ["fr", "us"],
        "destinationIpAsn": [{"asn": "ovh", "date": _now()}],
        "relatedFiles": [],
        "industries": [],
        "destinationIP": _related(3, "destinationIP", fake.ipv4_public),
        "relatedDNS": _related(3, "domainName", fake.domain_name),
        "relatedURLs": _related(3, "url", fake.url),
        "sourceTasks": [
            {
                "uuid": str(fake.uuid4()),
                "related": f"https://app.any.run/tasks/{fake.uuid4()}",
                "threatLevel": 2,
            }
        ],
    }


@router.get("/v1/analysis")
async def analysis_history() -> dict:
    return {"error": False, "data": {"tasks": []}}


@router.post("/v1/analysis")
async def analysis_submit() -> dict:
    return {"error": False, "data": {"taskid": TASK_UUID}}


@router.get("/v1/analysis/monitor/{task_uuid}")
async def analysis_monitor(task_uuid: str) -> StreamingResponse:
    """The task status as server-sent events, until the task completes."""

    async def events():
        for status, remaining in [(50, 20), (80, 5), (100, 0)]:
            data = json.dumps({"task": {"status": status, "remaining": remaining}})
            yield f"event: status\nid: {task_uuid}\ndata: {data}\n\n"
            await asyncio.sleep(0.1)

    return StreamingResponse(events(), media_type="text/event-stream")


@router.get("/v1/analysis/{task_uuid}")
async def analysis_report(task_uuid: str) -> dict:
    """The JSON report of a malicious URL analysis."""
    return {
        "error": False,
        "data": {
            "analysis": {
                "uuid": task_uuid,
                "tags": [{"tag": "phishing"}, {"tag": fake.malware_family().lower()}],
                "scores": {
                    "verdict": {
                        "score": 100,
                        "threatLevel": 2,
                        "threatLevelText": "Malicious activity",
                    }
                },
                "content": {
                    "mainObject": {
                        "type": "url",
                        "hashes": {
                            "md5": fake.md5(),
                            "sha1": fake.sha1(),
                            "sha256": fake.sha256(),
                        },
                    }
                },
            }
        },
    }


@router.get("/report/{task_uuid}/ioc/json")
async def report_iocs(task_uuid: str) -> list[dict]:  # noqa: ARG001
    """The indicators of compromise: reputation 0 unknown, 1 suspicious, 2 malicious."""
    return [
        {
            "category": "Network",
            "type": kind,
            "ioc": value,
            "reputation": reputation,
            "firstSeen": _now(),
            "lastSeen": _now(),
        }
        for kind, value, reputation in [
            ("ip", fake.ipv4_public(), 0),
            ("domain", fake.domain_name(), 1),
            ("url", fake.url(), 2),
            ("ip", fake.ipv4_public(), 2),
            ("sha256", fake.sha256(), 2),
        ]
    ]


@router.get("/report/{task_uuid}/summary/html")
async def report_html(task_uuid: str) -> Response:
    page = (
        f"<html><body><h1>ANY.RUN report {quote(task_uuid)}</h1>"
        f"<p>{fake.paragraph()}</p></body></html>"
    )
    return Response(page, media_type="application/octet-stream")
