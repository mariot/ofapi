"""A source OpenCTI platform's live stream (SSE), read by the OpenCTI opencti-stream
connector, which replicates its events to the platform it is registered with.

The stream sends ``connected``, then the events (``create``, ``update``, ``delete``)
with the STIX object of each as OpenCTI emits it, and a ``heartbeat`` every few seconds
(the helper stops a connector that hears none for 45 s). The connection stays open.
"""

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from app.fake import fake

router = APIRouter(prefix="/opencti-stream", tags=["OpenCTI stream"])

EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
HEARTBEAT_SECONDS = 5
LIFETIME_SECONDS = 900


def _event_id(offset: int) -> str:
    return f"{int(time.time() * 1000) + offset}-0"


def _frame(event: str, data: dict, event_id: str) -> str:
    return f"event: {event}\nid: {event_id}\ndata: {json.dumps(data)}\n\n"


def _stix(kind: str, **fields) -> dict:
    """An object as the stream emits it: STIX 2.1 with the OpenCTI extension."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    return {
        "id": f"{kind}--{uuid.uuid4()}",
        "spec_version": "2.1",
        "type": kind,
        "extensions": {
            EXTENSION: {
                "extension_type": "property-extension",
                "id": str(uuid.uuid4()),
                "type": kind.title(),
                "created_at": now,
                "updated_at": now,
                "is_inferred": False,
            }
        },
        **fields,
    }


def _events() -> list[tuple[str, dict]]:
    """A realistic mix: an organization, a malware, a domain with its indicator, the
    relationship between them, an update and a deletion."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    domain = fake.domain_name()
    pattern = f"[domain-name:value = '{domain}']"
    identity = _stix(
        "identity",
        created=now,
        modified=now,
        name=fake.company(),
        identity_class="organization",
    )
    malware = _stix(
        "malware",
        created=now,
        modified=now,
        name=fake.malware_family(),
        is_family=True,
        created_by_ref=identity["id"],
    )
    indicator = _stix(
        "indicator",
        created=now,
        modified=now,
        name=domain,
        pattern=pattern,
        pattern_type="stix",
        valid_from=now,
        labels=["malicious-activity"],
        confidence=80,
        created_by_ref=identity["id"],
    )
    observable = _stix("domain-name", value=domain)
    relationship = _stix(
        "relationship",
        created=now,
        modified=now,
        relationship_type="indicates",
        source_ref=indicator["id"],
        target_ref=malware["id"],
    )
    updated = {**indicator, "modified": now, "confidence": 90}
    events = [
        ("create", identity, "creates a Organization"),
        ("create", malware, "creates a Malware"),
        ("create", indicator, "creates an Indicator"),
        ("create", observable, "creates a Domain-Name"),
        ("create", relationship, "creates a relationship indicates"),
        ("update", updated, "replaces the confidence"),
        ("delete", observable, "deletes a Domain-Name"),
    ]
    return [
        (
            kind,
            {
                "version": "4",
                "type": kind,
                "scope": "external",
                "message": message,
                "origin": {"socket": "query", "referer": "https://source.example.com"},
                "data": data,
                "context": {},
            },
        )
        for kind, data, message in events
    ]


async def _stream(request: Request) -> AsyncIterator[str]:
    offset = 0
    yield _frame("connected", {"connectionId": str(uuid.uuid4())}, _event_id(offset))
    for kind, payload in _events():
        offset += 1
        yield _frame(kind, payload, _event_id(offset))
    deadline = time.time() + LIFETIME_SECONDS
    while time.time() < deadline and not await request.is_disconnected():
        await asyncio.sleep(HEARTBEAT_SECONDS)
        offset += 1
        yield _frame("heartbeat", {"connectionId": "staticfire"}, _event_id(offset))


@router.get("/stream")
@router.get("/stream/{stream_id}")
async def live_stream(
    request: Request,
    stream_id: str = "live",  # noqa: ARG001
) -> StreamingResponse:
    """The source platform's live stream (``live``, ``raw`` or a collection id)."""
    return StreamingResponse(
        _stream(request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
