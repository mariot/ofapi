"""SOC Prime Threat Detection Marketplace: content lists, CCM jobs and rule search
(socprime connector). The ATT&CK data the connector links rules to comes from the
``mitre/cti`` repository of the MITRE module."""

import uuid

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["api.tdm.socprime.com"]
router = APIRouter(prefix="/socprime", tags=["SOC Prime"])

STATUSES = ["stable", "test", "experimental"]


def _sigma_text(rule_id: str, title: str, technique: str) -> str:
    return (
        f"title: {title}\n"
        f"id: {rule_id}\n"
        f"status: {fake.random_element(STATUSES)}\n"
        f"description: Detects {title.lower()}\n"
        "author: SOC Prime Team\n"
        "tags:\n"
        "  - attack.execution\n"
        f"  - attack.{technique.lower()}\n"
        "logsource:\n"
        "  category: process_creation\n"
        "  product: windows\n"
        "detection:\n"
        "  selection:\n"
        f"    Image|endswith: '\\{fake.word()}.exe'\n"
        "  condition: selection\n"
        "level: high\n"
    )


def _rule(siem_type: str, case_id: str | None = None) -> dict:
    case_id = case_id or str(uuid.uuid4())
    title = f"Suspicious {fake.word().title()} Execution"
    link = f"https://tdm.socprime.com/tdm/info/{case_id}"
    text = _sigma_text(case_id, title, "T1059.001")
    if siem_type != "sigma":
        text = (
            f"process_name:*{fake.word()}.exe AND event_id:{fake.random_int(1, 9999)}"
        )
    return {
        "siem_type": siem_type,
        "case": {"id": case_id, "name": title},
        "sigma": {"text": text, "status": fake.random_element(STATUSES)},
        "description": f"Detects {title.lower()} activity on Windows hosts.",
        "release_date": fake.date_time_this_year().strftime("%Y-%m-%d %H:%M:%S"),
        "tags": {
            "author": "SOC Prime Team",
            "tool": ["Mimikatz", "Cobalt Strike"],
            "technique": [{"id": "T1059.001", "name": "PowerShell"}, {"id": "T1566"}],
            "actor": ["APT29"],
            "cve_id": [fake.cve_id()],
        },
        "context_resources": {
            "detection": {"links": [link]},
            "blog": {"links": [f"https://socprime.com/blog/{fake.slug()}/"]},
        },
    }


@router.get("/v1/content-list")
async def content_list(request: Request) -> list[dict]:
    """The rules of a content list, translated for the SIEM type in the headers."""
    siem_type = request.headers.get("siem_type", "sigma")
    return [_rule(siem_type) for _ in range(3)]


@router.get("/v1/ccm/jobs/{job_id}/get-content")
async def job_content(job_id: str) -> list[dict]:  # noqa: ARG001
    """The rules a content management job deployed."""
    return [_rule("sigma") for _ in range(2)]


@router.get("/v1/search-sigmas")
async def search_sigmas(request: Request) -> list[dict]:
    """Rules found by a Lucene query, 100 per page; an empty page ends the search."""
    if request.headers.get("page_number", "1") != "1":
        return []
    return [_rule(request.headers.get("client_siem_type", "sigma"))]
