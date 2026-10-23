"""Scenario control layer shared by every fake.

The ``/_control`` endpoints are for whoever drives a test, never for the collector or
injector under test:

* **rules** script what a route answers call after call (``responses``), so timelines
  such as "no alert on the first two polls, the real fixture from the third one on" or
  "page 2 answers 429 once" can be expressed without touching a single fake.
* the **journal** records every request the fakes received, so a test can assert on what
  the code under test actually sent.
"""

import asyncio
import itertools
import json
import re
import threading
from collections import deque
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

JOURNAL_SIZE = 5000
BODY_PREVIEW_LIMIT = 10_000
SKIPPED_PREFIXES = ("/_control", "/docs", "/redoc", "/openapi.json")
SENSITIVE_HEADER_PARTS = ("authorization", "cookie", "token", "key", "secret")


class Step(BaseModel):
    """What one call answers. ``passthrough`` hands the call to the real fake."""

    status: int = 200
    body: Any = None
    text: str | None = None
    content_type: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    delay_ms: int = 0
    passthrough: bool = False


class RuleInput(BaseModel):
    path: str = Field(description="Path prefix, or a regex when it starts with '^'")
    method: str | None = None
    responses: list[Step] = Field(min_length=1)
    then: Literal["passthrough", "last"] = Field(
        "passthrough",
        description="Once responses are exhausted: call the real fake, "
        "or keep answering the last step",
    )


class Rule(RuleInput):
    id: int
    calls: int = 0


_lock = threading.Lock()
_rules: list[Rule] = []
_rule_ids = itertools.count(1)
_journal: deque[dict] = deque(maxlen=JOURNAL_SIZE)
_journal_ids = itertools.count(1)


def reset() -> None:
    with _lock:
        _rules.clear()
        _journal.clear()


def _matches(rule: Rule, method: str, path: str) -> bool:
    if rule.method and rule.method.upper() != method:
        return False
    if rule.path.startswith("^"):
        return re.match(rule.path, path) is not None
    return path.startswith(rule.path)


def _next_step(method: str, path: str) -> tuple[Rule | None, Step | None]:
    """Pick the first matching rule and consume one of its steps."""
    with _lock:
        rule = next((r for r in _rules if _matches(r, method, path)), None)
        if rule is None:
            return None, None
        index = rule.calls
        rule.calls += 1
    if index < len(rule.responses):
        return rule, rule.responses[index]
    if rule.then == "last":
        return rule, rule.responses[-1]
    return rule, None


def _redact(headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    redacted = {}
    for raw_name, raw_value in headers:
        name = raw_name.decode("latin-1").lower()
        sensitive = any(part in name for part in SENSITIVE_HEADER_PARTS)
        redacted[name] = "<redacted>" if sensitive else raw_value.decode("latin-1")
    return redacted


def _decode_body(body: bytes) -> Any:
    if not body:
        return None
    text = body.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except ValueError:
        return text[:BODY_PREVIEW_LIMIT]


def _step_response(step: Step) -> Response:
    if step.text is not None:
        return Response(
            content=step.text,
            status_code=step.status,
            headers=step.headers,
            media_type=step.content_type or "text/plain",
        )
    return JSONResponse(
        content=step.body,
        status_code=step.status,
        headers=step.headers,
        media_type=step.content_type or "application/json",
    )


class ControlMiddleware:
    """Pure ASGI middleware applying rules and journaling requests."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or path.startswith(SKIPPED_PREFIXES):
            await self.app(scope, receive, send)
            return

        chunks = []
        while True:
            message = await receive()
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        body = b"".join(chunks)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        status = 500

        async def capture(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        method = scope["method"]
        rule, step = _next_step(method, path)
        try:
            if step and step.delay_ms:
                await asyncio.sleep(step.delay_ms / 1000)
            if step and not step.passthrough:
                await _step_response(step)(scope, replay, capture)
            else:
                await self.app(scope, replay, capture)
        finally:
            query = scope.get("query_string", b"").decode("latin-1")
            entry = {
                "method": method,
                "path": path,
                "query": query,
                "headers": _redact(scope.get("headers", [])),
                "body": _decode_body(body),
                "status": status,
                "rule_id": rule.id if rule else None,
                "served_by": "rule" if step and not step.passthrough else "fake",
                "at": datetime.now(UTC).isoformat(),
            }
            with _lock:
                entry["id"] = next(_journal_ids)
                _journal.append(entry)


router = APIRouter(prefix="/_control", tags=["Control"])


@router.post("/rules", status_code=201)
async def add_rule(rule: RuleInput) -> Rule:
    """Script the next answers of every request matching ``path`` (and ``method``)."""
    with _lock:
        created = Rule(id=next(_rule_ids), **rule.model_dump())
        _rules.append(created)
    return created


@router.get("/rules")
async def list_rules() -> list[Rule]:
    with _lock:
        return list(_rules)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: int) -> None:
    with _lock:
        rule = next((r for r in _rules if r.id == rule_id), None)
        if rule is None:
            raise HTTPException(status_code=404, detail="Unknown rule")
        _rules.remove(rule)


@router.delete("/rules", status_code=204)
async def delete_rules() -> None:
    with _lock:
        _rules.clear()


@router.get("/journal")
async def get_journal(method: str | None = None, path: str = "") -> list[dict]:
    """Recorded requests, filtered by ``method`` and ``path`` prefix."""
    with _lock:
        entries = list(_journal)
    return [
        e
        for e in entries
        if (not method or e["method"] == method.upper()) and e["path"].startswith(path)
    ]


@router.delete("/journal", status_code=204)
async def clear_journal() -> None:
    with _lock:
        _journal.clear()


@router.post("/reset", status_code=204)
async def reset_all() -> None:
    """Forget every rule and the journal."""
    reset()
