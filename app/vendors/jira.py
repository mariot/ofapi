"""Atlassian Jira Cloud: the REST API v2 calls of the python ``jira`` client (server
info, issue types, issue creation and reading), read by the OpenCTI jira stream
connector."""

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["staticfire.atlassian.net"]
router = APIRouter(prefix="/jira", tags=["Jira"])

BASE = "https://staticfire.atlassian.net"
ISSUES: dict[str, dict] = {}
ISSUE_TYPES = ["Epic", "Task", "Bug", "Story", "Subtask"]


@router.get("/rest/api/2/serverInfo")
async def server_info() -> dict:
    """The Cloud instance the client talks to."""
    return {
        "baseUrl": BASE,
        "version": "1001.0.0-SNAPSHOT",
        "versionNumbers": [1001, 0, 0],
        "deploymentType": "Cloud",
        "buildNumber": 100300,
        "buildDate": "2026-05-12T10:00:00.000+0000",
        "serverTime": "2026-05-13T09:30:00.000+0000",
        "scmInfo": fake.sha1(),
        "serverTitle": "Staticfire",
    }


@router.get("/rest/api/2/issuetype")
async def issue_types() -> list[dict]:
    """The issue types the client resolves a type name with."""
    return [
        {
            "self": f"{BASE}/rest/api/2/issuetype/{10000 + i}",
            "id": str(10000 + i),
            "description": f"A {name}.",
            "iconUrl": f"{BASE}/images/icons/{name.lower()}.svg",
            "name": name,
            "subtask": name == "Subtask",
            "hierarchyLevel": 1 if name == "Epic" else 0,
        }
        for i, name in enumerate(ISSUE_TYPES)
    ]


@router.post("/rest/api/2/issue")
async def create_issue(request: Request) -> dict:
    """Creates an issue from ``fields`` and answers its id, key and URL."""
    fields = (await request.json())["fields"]
    number = 100 + len(ISSUES)
    key = f"{fields['project']['key']}-{number}"
    issue_id = str(10000 + number)
    ISSUES[key] = {
        "id": issue_id,
        "key": key,
        "self": f"{BASE}/rest/api/2/issue/{issue_id}",
        "fields": {
            **fields,
            "status": {"name": "To Do", "id": "10000"},
            "created": "2026-05-13T09:30:00.000+0000",
        },
    }
    return {"id": issue_id, "key": key, "self": ISSUES[key]["self"]}


@router.get("/rest/api/2/issue/{key}")
async def read_issue(key: str) -> dict:
    """An issue created earlier."""
    return ISSUES[key]
