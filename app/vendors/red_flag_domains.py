"""Red Flag Domains: the daily list of malicious domains (plain text, one per line),
read by the OpenCTI red-flag-domains connector."""

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["dl.red.flag.domains"]
router = APIRouter(prefix="/red-flag-domains", tags=["Red Flag Domains"])


@router.get("/daily/{day:path}")
async def daily() -> Response:
    """The domains of a day (the connector asks for yesterday's file)."""
    domains = [fake.domain_name() for _ in range(20)]
    return Response("\n".join(domains) + "\n", media_type="text/plain")
