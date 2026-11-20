"""StopForumSpam: the toxic domains list (one domain per line after a short
header), read by the OpenCTI stopforumspam connector."""

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["www.stopforumspam.com"]
router = APIRouter(prefix="/stopforumspam", tags=["StopForumSpam"])


@router.get("/downloads/toxic_domains_whole_filtered_50000.txt")
async def toxic_domains() -> Response:
    """A list of spam domains: the connector skips the first three lines."""
    header = ["# StopForumSpam toxic domains", "# filtered, top 50000", ""]
    domains = [fake.domain_name() for _ in range(8)]
    return Response("\n".join(header + domains) + "\n", media_type="text/plain")
