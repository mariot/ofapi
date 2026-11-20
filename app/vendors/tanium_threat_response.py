"""Tanium Threat Response (and Reputation) on a Tanium Cloud instance: alerts and intel
documents, read by the OpenCTI tanium-incidents (import) and tanium-intel (stream)
connectors.

The OpenAEV collector's own alerts route lives in ``app/main.py`` under ``/tanium`` (an
empty list, no host); this module has its own prefix so as to leave it alone.
"""

import json
from datetime import UTC, datetime, timedelta
from itertools import count

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["*.cloud.tanium.com"]
router = APIRouter(prefix="/cti-tanium", tags=["Tanium CTI"])

API = "/plugin/products/threat-response/api/v1"
_ids = count(100)


def _alert(minutes_ago: int, state: str, intel_doc_id: int, with_match: bool) -> dict:
    alerted_at = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    match = {
        "properties": {
            "process": {
                "user": f"CORP\\{fake.user_name()}",
                "file": {
                    "md5": fake.md5(),
                    "sha1": fake.sha1(),
                    "sha256": fake.sha256(),
                },
            }
        }
    }
    return {
        "id": next(_ids),
        "guid": fake.uuid4(),
        "alertedAt": alerted_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "state": state,
        "priority": fake.random_element(["high", "medium", "low"]),
        "type": "detect.match",
        "matchType": "process",
        "intelDocId": intel_doc_id,
        "computerName": fake.hostname(),
        "computerIpAddress": fake.ipv4_public(),
        "details": json.dumps({"match": match if with_match else None}),
    }


@router.get(f"{API}/alerts")
async def alerts() -> dict:
    """Alerts oldest first (sort=+alertedAt): three open, one suppressed."""
    return {
        "data": [
            _alert(300, "unresolved", 11, True),
            _alert(200, "suppressed", 12, True),
            _alert(120, "unresolved", 13, False),
            _alert(30, "inProgress", 14, True),
        ]
    }


@router.get(API + "/intels/{intel_id}")
async def intel(intel_id: str) -> dict:
    """The intel document behind an alert, with its MITRE techniques."""
    injection = intel_id == "14"
    return {
        "data": {
            "id": int(intel_id),
            "name": f"{fake.malware_family()} {fake.word()} detection",
            "type": "processInjection" if injection else "stix",
            "mitreAttack": {
                "techniques": [
                    {"id": "T1566", "name": "Phishing"},
                    {"id": "T1059", "name": "Command and Scripting Interpreter"},
                ]
            },
        }
    }


@router.get(f"{API}/sources")
async def sources() -> dict:
    """No source yet: the connector creates its own."""
    return {"data": []}


@router.post(f"{API}/sources")
async def create_source(payload: dict) -> dict:
    return {"data": {"id": 7, "name": payload.get("name")}}


@router.api_route(f"{API}/sources/{{source_id}}/intels", methods=["POST"])
async def create_intel(request: Request) -> dict:
    """Any intel document (STIX, OpenIOC, YARA or Tanium signal): its new id."""
    await request.body()
    return {"data": {"id": next(_ids), "name": request.headers.get("name", "intel")}}


@router.api_route(API + "/intels/{intel_id}", methods=["PUT"])
async def update_intel(intel_id: str, request: Request) -> dict:
    await request.body()
    return {"data": {"id": int(intel_id)}}


@router.delete(API + "/intels/")
async def delete_intel() -> dict:
    return {"data": {}}


@router.post(f"{API}/intels/quick-add")
async def quick_add(payload: dict) -> dict:
    """An OpenIOC document for a hash or an address/host (an XML string)."""
    document = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<OpenIOC xmlns="http://openioc.org/schemas/OpenIOC_1.1" id="{ioc}">'
        "<short_description>{name}</short_description>"
        '<definition><Indicator operator="OR" id="{group}">'
        '<IndicatorItem id="{item}" condition="is">'
        '<Context document="Network" search="Network/DNS" type="mir"/>'
        '<Content type="string">{text}</Content>'
        "</IndicatorItem></Indicator></definition></OpenIOC>"
    )
    return {
        "data": document.format(
            ioc=fake.uuid4(),
            group=fake.uuid4(),
            item=fake.uuid4(),
            name=payload.get("name"),
            text=payload.get("text"),
        )
    }


@router.post(f"{API}/intel/deploy")
async def deploy() -> dict:
    return {"data": {"status": "deployed"}}


@router.post(f"{API}/on-demand-scans")
async def on_demand_scan(payload: dict) -> dict:
    return {"data": {"id": next(_ids), **payload}}


@router.get(f"{API}/labels")
async def labels() -> dict:
    return {"data": []}


@router.post(f"{API}/labels")
async def create_label(payload: dict) -> dict:
    return {"data": {"id": next(_ids), "name": payload.get("name")}}


@router.put(API + "/intels/{intel_id}/labels")
async def add_label(intel_id: str) -> dict:
    return {"data": {"id": int(intel_id)}}


@router.post("/plugin/products/reputation/v3/reputations/custom/upload")
async def upload_reputation() -> dict:
    return {"data": {"status": "ok"}}


@router.delete("/plugin/products/reputation/v3/reputations/custom/{reputation_id}")
async def delete_reputation() -> dict:
    return {"data": {}}
