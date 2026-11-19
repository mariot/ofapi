"""Elastic Security (Elasticsearch and Kibana security APIs): detection alerts and cases
(elastic-security-incidents import connector), threat intelligence documents and
detection rules (elastic-security-intel stream connector).

Elasticsearch and Kibana are two hosts of one deployment; both land here."""

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response

from app.fake import fake

HOSTS = ["elastic-security-es.staticfire.test", "elastic-security-kb.staticfire.test"]
router = APIRouter(prefix="/elastic-security", tags=["Elastic Security"])

KIBANA = "https://elastic-security-kb.staticfire.test"
TECHNIQUES = [
    {"id": "T1059", "name": "Command and Scripting Interpreter"},
    {"id": "T1566", "name": "Phishing"},
]


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _alert(number: int) -> dict:
    """A detection alert document, as stored in the alerts index: ECS fields nested,
    kibana.alert.* fields flat."""
    seen = datetime.now(UTC) - timedelta(minutes=10 * number)
    risk = fake.random_int(21, 99)
    return {
        "@timestamp": _iso(seen),
        "host": {"name": f"srv-{fake.random_int(10, 99)}.corp.example.com"},
        "source": {"ip": fake.ipv4_public()},
        "destination": {"ip": fake.ipv4_public(), "domain": fake.domain_name()},
        "url": {"full": f"https://{fake.domain_name()}/payload.bin"},
        "dns": {"question": {"name": fake.domain_name()}},
        "file": {
            "name": "invoice.exe",
            "hash": {"sha256": fake.sha256(), "md5": fake.md5()},
        },
        "process": {"name": "powershell.exe", "executable": "C:\\Windows\\a.exe"},
        "user": {"name": fake.user_name()},
        "email": {"from": {"address": fake.email()}},
        "kibana.alert.uuid": fake.uuid4(),
        "kibana.alert.status": "active",
        "kibana.alert.workflow_status": "open",
        "kibana.alert.original_time": _iso(seen),
        "kibana.alert.last_detected": _iso(seen),
        "kibana.alert.risk_score": risk,
        "kibana.alert.severity": "high" if risk > 70 else "medium",
        "kibana.alert.reason": f"process event with source {fake.ipv4_public()}",
        "kibana.alert.url": f"{KIBANA}/app/security/alerts/redirect/{fake.uuid4()}",
        "kibana.alert.rule.name": f"Suspicious PowerShell execution {number % 2}",
        "kibana.alert.rule.uuid": fake.uuid4(),
        "kibana.alert.rule.rule_id": fake.uuid4(),
        "kibana.alert.rule.description": "Detects encoded PowerShell command lines.",
        "kibana.alert.rule.tags": ["Windows", "Execution"],
        "kibana.alert.rule.references": ["https://attack.mitre.org/techniques/T1059/"],
        "kibana.alert.rule.note": "## Triage\n\nCheck the parent process.",
        "kibana.alert.rule.threat": [
            {
                "framework": "MITRE ATT&CK",
                "tactic": {"id": "TA0002", "name": "Execution"},
                "technique": [
                    {
                        **t,
                        "reference": f"https://attack.mitre.org/techniques/{t['id']}/",
                    }
                    for t in TECHNIQUES
                ],
            }
        ],
    }


# --- Elasticsearch ----------------------------------------------------------------


@router.get("/_cluster/health")
async def cluster_health() -> dict:
    return {"cluster_name": "staticfire", "status": "green", "number_of_nodes": 1}


@router.post("/{index}/_search")
async def search(index: str) -> dict:  # noqa: ARG001
    """The detection alerts of the last hours."""
    hits = [
        {"_index": ".internal.alerts-security.alerts-default-000001", "_id": str(n)}
        | {"_source": _alert(n)}
        for n in range(1, 4)
    ]
    return {
        "took": 3,
        "timed_out": False,
        "hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits},
    }


@router.get("/{index}/_doc/{doc_id}")
async def get_doc(index: str, doc_id: str) -> dict:
    """One alert document, as attached to a case."""
    return {"_index": index, "_id": doc_id, "found": True, "_source": _alert(4)}


@router.post("/{index}/_delete_by_query")
async def delete_by_query(index: str) -> dict:  # noqa: ARG001
    return {"took": 2, "timed_out": False, "deleted": 0, "failures": []}


@router.post("/{index}/_doc")
async def index_doc(index: str, request: Request) -> dict:
    """A document added to the threat intelligence data stream."""
    body = await request.body()
    return {
        "_index": f".ds-{index}-2026.11.19-000001",
        "_id": hashlib.sha1(body).hexdigest()[:20],
        "result": "created",
        "_shards": {"total": 2, "successful": 1, "failed": 0},
        "status": 201,
    }


@router.post("/_bulk")
async def bulk(request: Request) -> dict:
    """One created item per document of the bulk body."""
    lines = (await request.body()).decode().strip().splitlines()
    items = [
        {"create": {"_index": "logs-ti_custom_opencti.indicator", "status": 201}}
        for line in lines[::2]
        if line
    ]
    return {"took": 5, "errors": False, "items": items}


@router.get("/_index_template/{name}")
async def get_template(name: str) -> Response:
    return Response(
        f'{{"error": "index template matching [{name}] not found", "status": 404}}',
        status_code=404,
        media_type="application/json",
    )


@router.put("/_index_template/{name}")
async def put_template(name: str) -> dict:  # noqa: ARG001
    return {"acknowledged": True}


# --- Kibana -----------------------------------------------------------------------


@router.get("/api/status")
async def status() -> dict:
    return {"name": "kibana", "version": {"number": "8.15.0"}}


CASES = [("case-0001", "Ransomware precursor activity", "open", "high", 3)]


def _case(case_id: str, title: str, state: str, severity: str, age: int) -> dict:
    created = datetime.now(UTC) - timedelta(hours=age)
    return {
        "id": case_id,
        "title": title,
        "description": "Investigation of suspicious PowerShell on file servers.",
        "status": state,
        "severity": severity,
        "tags": ["ransomware", "windows"],
        "owner": "securitySolution",
        "assignees": [],
        "created_at": _iso(created),
        "updated_at": _iso(created + timedelta(hours=1)),
        "created_by": {"username": "analyst", "full_name": "SOC Analyst"},
        "totalComment": 1,
        "totalAlerts": 1,
        "observables": [
            {
                "id": fake.uuid4(),
                "typeKey": "observable-ipv4",
                "value": fake.ipv4_public(),
                "description": "seen in the alert",
            }
        ],
        "version": "WzEyMywxXQ==",
    }


@router.get("/api/cases/_find")
async def find_cases(
    page: int = 1, per_page: Annotated[int, Query(alias="perPage")] = 20
):
    """The cases, listed without their comments."""
    cases = [_case(*c) for c in CASES]
    return {
        "cases": cases,
        "page": page,
        "per_page": per_page,
        "total": len(cases),
        "count_open_cases": len(cases),
    }


@router.get("/api/cases/{case_id}")
async def get_case(case_id: str) -> dict:
    known = {c[0]: c for c in CASES}
    return _case(*known.get(case_id, (case_id, "Case", "open", "low", 2)))


@router.get("/api/cases/{case_id}/comments")
async def case_comments(case_id: str) -> list[dict]:  # noqa: ARG001
    return [
        {
            "id": fake.uuid4(),
            "type": "user",
            "comment": "Isolated the host and collected the memory image.",
            "owner": "securitySolution",
            "created_at": _iso(datetime.now(UTC) - timedelta(hours=2)),
            "created_by": {"username": "analyst", "full_name": "SOC Analyst"},
        }
    ]


@router.get("/api/cases/{case_id}/alerts")
async def case_alerts(case_id: str) -> list[dict]:  # noqa: ARG001
    return [
        {
            "id": "alert-0001",
            "index": ".internal.alerts-security.alerts-default-000001",
            "attached_at": _iso(datetime.now(UTC) - timedelta(hours=2)),
        }
    ]


@router.post("/api/detection_engine/rules")
async def create_rule(request: Request) -> dict:
    """The rule Kibana creates from the posted definition."""
    rule = await request.json()
    now = _iso(datetime.now(UTC))
    return {
        **rule,
        "id": fake.uuid4(),
        "enabled": True,
        "created_at": now,
        "updated_at": now,
        "revision": 0,
    }


@router.put("/api/detection_engine/rules")
async def update_rule(request: Request) -> dict:
    return {**(await request.json()), "updated_at": _iso(datetime.now(UTC))}


@router.delete("/api/detection_engine/rules")
async def delete_rule(id: str | None = None) -> dict:
    return {"id": id}


@router.get("/api/detection_engine/rules/_find")
async def find_rules(filter: str | None = None) -> dict:  # noqa: ARG001
    return {"page": 1, "perPage": 20, "total": 0, "data": []}
