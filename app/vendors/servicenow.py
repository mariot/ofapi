"""ServiceNow Security Incident Response: the Table API of an instance, read by the
OpenCTI servicenow connector."""

import re
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["*.service-now.com"]
router = APIRouter(prefix="/servicenow", tags=["ServiceNow"])

# Incidents whose tasks are served, by sys_id
WITH_TASKS: set[str] = set()


def _moment(minutes_ago: int) -> str:
    """A date as the Table API gives it with display values."""
    moment = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def _sys_id() -> str:
    return uuid.uuid4().hex


def _comments(count: int = 2) -> str:
    """Journal entries: a date, an author and a message each, newest first."""
    authors = ["Analyst (Work notes)", "System (Automation activity)"]
    return "\n\n".join(
        f"{_moment(10 * (index + 1))} - {authors[index % 2]}\n{fake.sentence()}"
        for index in range(count)
    )


def _incident(index: int, severity: str, priority: str) -> dict:
    sys_id = _sys_id()
    if index % 2 == 0:
        WITH_TASKS.add(sys_id)
    technique = fake.mitre_attack_technique()
    return {
        "sys_id": sys_id,
        "number": f"SIR{1000 + fake.random_int(1, 8999):07d}",
        "short_description": fake.sentence(nb_words=5),
        "description": fake.paragraph(),
        "state": "Analysis",
        "severity": severity,
        "priority": priority,
        "category": "Malware",
        "subcategory": "Ransomware, Trojan",
        "mitre_technique": f"{technique['external_id']} ({technique['name']})",
        "mitre_tactic": "TA0006 (Credential Access)",
        "mitre_group": f"{fake.intrusion_set().replace(' ', '')} (APT-{index})",
        "mitre_malware": f"{fake.malware_family().replace(' ', '')} (Loader)",
        "mitre_tool": f"{fake.threat_tool().replace(' ', '')} (Post-exploitation)",
        "sys_created_on": _moment(300 + index),
        "sys_updated_on": _moment(30 + index),
        "estimated_end": "",
        "comments_and_work_notes": _comments(),
        "security_tags": "phishing, ransomware",
        "sys_tags": "",
        "contact_type": "Alert",
        "alert_sensor": "SIEM",
    }


def _task(number: int) -> dict:
    return {
        "sys_id": _sys_id(),
        "number": f"SIT{2000 + number:07d}",
        "due_date": _moment(-1440),
        "sys_tags": "",
        "security_tags": "containment",
        "short_description": fake.sentence(nb_words=4),
        "description": fake.sentence(),
        "comments_and_work_notes": _comments(1),
        "sys_created_on": _moment(200),
        "sys_updated_on": _moment(20),
    }


def _observable(kind: str, value: str) -> dict:
    return {
        "observable.sys_id": _sys_id(),
        "observable.security_tags": "c2",
        "observable.sys_tags": "",
        "observable.value": value,
        "observable.type": kind,
        "observable.finding": "Malicious",
        "observable.sys_created_on": _moment(100),
        "observable.sys_updated_on": _moment(50),
        "observable.notes": fake.sentence(),
    }


def _observables() -> list[dict]:
    """One observable of each main kind (the type is the display label of the table)."""
    return [
        _observable("Domain name", fake.domain_name()),
        _observable("IP address (V4)", fake.ipv4_public()),
        _observable("URL", fake.url()),
        _observable("SHA256 hash", fake.sha256()),
        _observable("MD5 hash", fake.md5()),
        _observable("Email address", fake.email()),
        _observable("Host name", f"{fake.word()}-host.{fake.domain_name()}"),
        _observable("Autonomous System Number", fake.asn()),
    ]


def _query(raw: str, key: str) -> str | None:
    found = re.search(rf"(?:^|\^){re.escape(key)}=([^^&]+)", raw)
    return found.group(1) if found else None


@router.get("/api/now/{version}/table/sn_si_incident")
async def security_incidents(version: str) -> dict:  # noqa: ARG001
    """Three security incidents of different severities."""
    levels = [
        ("1 - High", "2 - High"),
        ("2 - Medium", "3 - Moderate"),
        ("3 - Low", "4"),
    ]
    return {"result": [_incident(index, *level) for index, level in enumerate(levels)]}


@router.get("/api/now/{version}/table/sn_si_task")
async def security_tasks(version: str, request: Request) -> dict:  # noqa: ARG001
    parent = _query(request.query_params.get("sysparm_query", ""), "parent")
    if parent not in WITH_TASKS:
        return {"result": []}
    return {"result": [_task(1), _task(2)]}


@router.get("/api/now/{version}/table/sn_ti_m2m_task_observable")
async def task_observables(version: str) -> dict:  # noqa: ARG001
    return {"result": _observables()}


@router.get("/api/now/{version}/table/sys_choice")
async def choices(version: str) -> dict:  # noqa: ARG001
    labels = ["1 - High", "2 - Medium", "3 - Low"]
    return {"result": [{"label": label, "value": label[0]} for label in labels]}
