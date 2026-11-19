"""LogRhythm: the Case API (cases and their alarm evidence), read by the OpenCTI
logrhythm-incidents connector, and the Admin API lists, written by the OpenCTI logrhythm
stream connector.

The Search API used by the OpenAEV collector stays in ``app/main.py``.
"""

from fastapi import APIRouter, HTTPException, Request

from app.fake import fake

HOSTS = ["logrhythm.staticfire.test"]
router = APIRouter(prefix="/logrhythm", tags=["LogRhythm"])

CASE_IDS = [fake.uuid4() for _ in range(3)]


def _alarm(case_number: int) -> dict:
    return {
        "alarmId": fake.random_int(100000, 999999),
        "alarmRuleName": f"AIE: {fake.sentence(nb_words=4).rstrip('.')}",
        "alarmDate": fake.date_time_this_month().isoformat() + "Z",
        "riskScore": fake.random_int(10, 100),
        "text": fake.sentence(),
        "caseNumber": case_number,
    }


@router.get("/lr-case-api/cases")
async def cases(count: int = 100) -> list[dict]:
    """The most recent cases; priority is a 1 (low) to 5 (critical) scale."""
    found = []
    for number, case_id in enumerate(CASE_IDS, start=1):
        created = fake.date_time_this_month()
        found.append(
            {
                "id": case_id,
                "number": number,
                "name": f"Investigation {fake.word()} {fake.random_int(1, 999)}",
                "priority": fake.random_int(1, 5),
                "summary": fake.sentence(),
                "dateCreated": created.isoformat() + "Z",
                "dateUpdated": fake.date_time_between(created).isoformat() + "Z",
                "status": {"name": "Created", "number": 1},
            }
        )
    return found[:count]


@router.get("/lr-case-api/cases/{case_id}/evidence/alarms")
async def case_alarms(case_id: str) -> list[dict]:
    number = CASE_IDS.index(case_id) + 1 if case_id in CASE_IDS else 0
    return [_alarm(number) for _ in range(2)]


LISTS: dict[str, str] = {}


@router.get("/lr-admin-api/lists/")
async def get_list(request: Request) -> list[dict]:
    """The list named in the ``name`` header, if it exists."""
    name = request.headers.get("name", "")
    return [{"guid": LISTS[name], "name": name}] if name in LISTS else []


@router.post("/lr-admin-api/lists/")
async def create_list(body: dict) -> list[dict]:
    guid = LISTS.setdefault(body["name"], fake.uuid4())
    return [{"guid": guid, **body}]


@router.post("/lr-admin-api/lists/{guid}/items/")
async def add_items(guid: str, body: dict) -> dict:
    if guid not in LISTS.values():
        raise HTTPException(status_code=404, detail="list not found")
    return {"added": len(body.get("items", []))}
