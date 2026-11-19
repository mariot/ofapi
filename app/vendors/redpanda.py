"""Redpanda HTTP Proxy (Pandaproxy): the produce endpoint, read by the OpenCTI redpanda
stream connector. The journal holds the records it produced."""

from fastapi import APIRouter, HTTPException, Request

HOSTS = ["redpanda.staticfire.test"]
router = APIRouter(prefix="/redpanda", tags=["Redpanda"])

CONTENT_TYPE = "application/vnd.kafka.json.v2+json"
OFFSETS: dict[str, int] = {}


@router.post("/topics/{topic}")
async def produce(topic: str, request: Request) -> dict:
    """Append JSON records to a topic; answers the partition and offset of each."""
    if request.headers.get("content-type") != CONTENT_TYPE:
        raise HTTPException(415, "Unsupported media type")
    records = (await request.json()).get("records")
    if not isinstance(records, list):
        raise HTTPException(422, "records is required")
    offsets = []
    for _ in records:
        OFFSETS[topic] = OFFSETS.get(topic, -1) + 1
        offsets.append({"partition": 0, "offset": OFFSETS[topic]})
    return {"offsets": offsets}
