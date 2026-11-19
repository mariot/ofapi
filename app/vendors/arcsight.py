"""ArcSight ESM Service Layer: login, cases, security events and active lists, read by
the OpenCTI arcsight-incidents (import) and arcsight (stream) connectors."""

import time

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["arcsight.staticfire.test"]
router = APIRouter(prefix="/arcsight", tags=["ArcSight ESM"])

CASE_IDS = ["Rk1BQUFCQUJDRFFBQUE9PQ==", "Rk1CQUFCQUJDRFFBQUE9PQ=="]


def _ms_ago(hours: int) -> int:
    return int((time.time() - hours * 3600) * 1000)


@router.get("/www/core-service/rest/LoginService/login")
async def login() -> dict:
    return {"log.loginResponse": {"log.return": fake.sha256()[:32]}}


@router.get("/www/manager-service/rest/CaseService/findAllIds")
async def find_all_ids() -> dict:
    return {"cas.findAllIdsResponse": {"cas.return": CASE_IDS}}


@router.get("/www/manager-service/rest/CaseService/getResourceById")
async def get_case(resource_id: str = "") -> dict:
    """A case referencing two security events."""
    return {
        "cas.getResourceByIdResponse": {
            "cas.return": {
                "resourceid": resource_id,
                "name": f"Investigation {fake.bothify('??-####').upper()}",
                "description": fake.sentence(),
                "createdTimestamp": _ms_ago(24),
                "modifiedTimestamp": _ms_ago(2),
                "consequenceSeverity": fake.random_int(3, 10),
                "eventIDs": [fake.random_int(10**6, 10**7) for _ in range(2)],
            }
        }
    }


@router.post("/www/manager-service/rest/SecurityEventService/getSecurityEvents")
async def get_security_events(request: Request) -> dict:
    """One event per id asked."""
    ids = (await request.json())["sev.getSecurityEvents"]["sev.ids"]
    return {
        "sev.getSecurityEventsResponse": {
            "sev.return": [
                {
                    "eventId": event_id,
                    "name": fake.random_element(
                        ["Failed login burst", "Malware callback", "Port scan"]
                    ),
                    "message": fake.sentence(),
                    "priority": fake.random_int(2, 10),
                    "startTime": _ms_ago(26),
                    "endTime": _ms_ago(25),
                }
                for event_id in ids
            ]
        }
    }


@router.post("/www/manager-service/rest/ActiveListService/addEntries")
async def add_entries() -> dict:
    return {"act.addEntriesResponse": {}}


@router.post("/www/manager-service/rest/ActiveListService/deleteEntries")
async def delete_entries() -> dict:
    return {"act.deleteEntriesResponse": {}}
