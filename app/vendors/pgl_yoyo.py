"""Peter Lowe's ad server list (pgl.yoyo.org): plain text lists of tracker and ad
server hostnames and addresses, read by the OpenCTI pgl-yoyo connector."""

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["pgl.yoyo.org"]
router = APIRouter(prefix="/pgl-yoyo", tags=["PGL Yoyo"])


def _text(lines: list[str]) -> Response:
    return Response(content="\n".join(lines) + "\n", media_type="text/plain")


@router.get("/adservers/serverlist.php")
async def serverlist() -> Response:
    """Hostnames, one per line, some with a trailing comment or a malformed value."""
    hosts = [f"ads.{fake.domain_name()}" for _ in range(8)]
    hosts.append(f"{fake.domain_name()} # tracker")
    hosts.append("not a hostname-")
    return _text(hosts)


@router.get("/adservers/iplist.php")
async def iplist() -> Response:
    """Addresses, one per line."""
    return _text([fake.ipv4_public() for _ in range(6)] + ["999.1.1.1"])
