"""Swimlane: the records of an application (record search), read by the OpenCTI
swimlane connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["*.swimlane.app"]
router = APIRouter(prefix="/swimlane", tags=["Swimlane"])


def _record(index: int) -> dict:
    created = datetime.now(UTC) - timedelta(hours=fake.random_int(1, 72))
    return {
        "id": fake.uuid4(),
        "trackingId": f"INC-{fake.random_int(1000, 9999)}",
        "trackingFull": f"INC-{index:06d}",
        "createdDate": created.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "modifiedDate": (created + timedelta(minutes=30)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        "values": {fake.bothify("????????"): fake.sentence()},
    }


@router.post("/api/app/{application_id}/record/search")
async def search_records() -> dict:
    """Six records of the application, on the only page."""
    records = [_record(index) for index in range(1, 7)]
    return {"results": records, "count": len(records)}
