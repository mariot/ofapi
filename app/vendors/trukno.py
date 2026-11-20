"""TruKno: the breach list (per day, paginated) and breach details with their related
TTPs and malware, read by the OpenCTI trukno connector."""

import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query, Response

from app.fake import fake

HOSTS = ["api.trukno.com"]
router = APIRouter(prefix="/trukno", tags=["TruKno"])


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _breach_date(day: str) -> datetime:
    """Late in the requested day, or just now when the day is today."""
    start = datetime.fromisoformat(day).replace(tzinfo=UTC)
    now = datetime.now(UTC)
    if start.date() >= now.date():
        return now - timedelta(minutes=5)
    return start + timedelta(hours=23)


@router.get("/v2/breaches/list")
async def breaches_list(
    start_date: str,
    page: int = 1,
    has_ttps: str = Query("true", alias="hasTTPs"),
) -> Response:
    """Two pages of one breach per day with TTPs; the API answers 400 and ``[]`` when
    nothing matches (``hasTTPs=false``)."""
    if has_ttps != "true":
        return Response("[]", status_code=400, media_type="application/json")
    breach = {
        "_id": fake.bothify("brc-????-########").lower(),
        "date": _iso(_breach_date(start_date)),
        "title": fake.catch_phrase(),
    }
    return Response(
        json.dumps({"results": [breach], "metadata": {"totalPages": 2, "page": page}}),
        media_type="application/json",
    )


@router.get("/v2/breaches/{breach_id}")
async def breach(breach_id: str) -> dict:
    """A breach with its report fields and the TTPs and malware it relates to."""
    return {
        "_id": breach_id,
        "date": _iso(datetime.now(UTC) - timedelta(hours=1)),
        "title": f"{fake.company()} breach: {fake.catch_phrase()}",
        "description": fake.paragraph(),
        "relatedTTPs": [
            {
                "_id": fake.bothify("ttp-########").lower(),
                "name": fake.mitre_attack_technique()["name"],
            }
            for _ in range(3)
        ],
        "relatedMalware": [
            {"_id": fake.bothify("mal-########").lower(), "name": fake.malware_family()}
            for _ in range(2)
        ],
    }
