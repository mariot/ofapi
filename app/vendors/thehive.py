"""TheHive 5: the query API (cases, alerts and the observables, tasks, comments and
attachments of a case) and the attachment download, read through thehive4py by the
OpenCTI thehive connector."""

import json
import time
import uuid

from fastapi import APIRouter, Request, Response

from app.fake import fake

HOSTS = ["thehive.staticfire.test"]
router = APIRouter(prefix="/thehive", tags=["TheHive"])

CASE_COUNT = 2
ALERT_COUNT = 2
ATTACHMENT = b"staticfire attachment: process list of the infected host\n"

_cases: list[dict] = []


def _now_ms(minutes_ago: int = 0) -> int:
    return int((time.time() - minutes_ago * 60) * 1000)


def _case(number: int) -> dict:
    created = _now_ms(120)
    return {
        "_id": f"~{fake.random_int(10000, 99999) * 4096}",
        "_type": "Case",
        "_createdBy": "analyst@example.com",
        "_createdAt": created,
        "_updatedAt": created + 60000,
        "number": number,
        "title": f"{fake.malware_family()} intrusion on {fake.domain_name()}",
        "description": fake.paragraph(),
        "severity": fake.random_int(1, 4),
        "startDate": created,
        "tags": ["phishing", "staticfire"],
        "flag": False,
        "tlp": fake.random_int(1, 3),
        "pap": 2,
        "status": "InProgress",
        "stage": "InProgress",
        "owner": "analyst@example.com",
        "extraData": {},
    }


def _observable(kind: str, value: str, **extra) -> dict:
    return {
        "_id": f"~{fake.random_int(10000, 99999) * 4096}",
        "_type": "Observable",
        "_createdAt": _now_ms(90),
        "dataType": kind,
        "data": value,
        "message": f"{kind} found during the triage",
        "tags": ["triage"],
        "tlp": 2,
        "ioc": True,
        "sighted": True,
        "startDate": _now_ms(100),
        **extra,
    }


def _observables() -> list[dict]:
    """One observable of each family the connector maps."""
    sha256 = fake.sha256()
    return [
        _observable("ip", fake.ipv4_public()),
        _observable("domain", fake.domain_name()),
        _observable("url", fake.url()),
        _observable("hash", sha256),
        _observable("mail", fake.email()),
        _observable("filename", "invoice.exe"),
        _observable("cve", fake.cve_id()),
        _observable("autonomous-system", str(fake.random_int(1000, 399999))),
        _observable("hostname", fake.domain_name().split(".")[0]),
        _observable(
            "file",
            "invoice.exe",
            attachment={"hashes": [sha256], "names": ["invoice.exe"]},
        ),
    ]


def _alert() -> dict:
    created = _now_ms(60)
    return {
        "_id": f"~{fake.random_int(10000, 99999) * 4096}",
        "_type": "Alert",
        "_createdAt": created,
        "_updatedAt": created + 30000,
        "type": "external",
        "source": "siem",
        "sourceRef": uuid.uuid4().hex[:12],
        "title": f"Suspicious {fake.malware_family()} beaconing",
        "description": fake.paragraph(),
        "severity": fake.random_int(1, 4),
        "date": created,
        "tags": ["beacon"],
        "tlp": 2,
        "pap": 2,
        "status": "New",
        "artifacts": _observables()[:4],
    }


@router.post("/api/v1/query")
async def query(request: Request) -> Response:
    """The query pipeline: the first stage names the listing (``listCase``,
    ``listAlert``, or ``getCase`` followed by what to read in the case)."""
    stages = [stage["_name"] for stage in (await request.json())["query"]]
    if stages[0] == "listCase":
        _cases[:] = [_case(n) for n in range(1, CASE_COUNT + 1)]
        return Response(_json(_cases), media_type="application/json")
    if stages[0] == "listAlert":
        return Response(
            _json([_alert() for _ in range(ALERT_COUNT)]),
            media_type="application/json",
        )
    answers = {
        "observables": _observables,
        "tasks": _tasks,
        "comments": _comments,
        "attachments": _attachments,
    }
    reading = next((stage for stage in stages if stage in answers), None)
    body = answers[reading]() if reading else []
    return Response(_json(body), media_type="application/json")


def _json(body: list[dict]) -> str:
    return json.dumps(body)


def _tasks() -> list[dict]:
    return [
        {
            "_id": f"~{fake.random_int(10000, 99999) * 4096}",
            "_createdAt": _now_ms(100),
            "title": "Isolate the host",
            "description": "Cut the host from the network",
            "status": "Waiting",
            "assignee": "analyst@example.com",
            "dueDate": _now_ms(-600),
        }
    ]


def _comments() -> list[dict]:
    return [
        {
            "_id": f"~{fake.random_int(10000, 99999) * 4096}",
            "_createdAt": _now_ms(80),
            "message": fake.sentence(),
        }
    ]


def _attachments() -> list[dict]:
    return [
        {
            "_id": uuid.uuid4().hex,
            "name": "processes.txt",
            "contentType": "text/plain",
            "size": len(ATTACHMENT),
        }
    ]


@router.get("/api/v1/attachment/{attachment_id}/download")
async def download(attachment_id: str) -> Response:  # noqa: ARG001
    return Response(ATTACHMENT, media_type="text/plain")
