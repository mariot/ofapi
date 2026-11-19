"""Echo CTI IOC feeds (text/plain, one indicator per line), read by the OpenCTI echocti
connector."""

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["api.echocti.com"]
router = APIRouter(prefix="/echocti", tags=["Echo CTI"])


def _line(kind: str | None) -> str:
    if kind == "ip":
        return fake.ipv4_public()
    if kind == "url":
        return f"https://{fake.domain_name()}/{fake.slug()}.php"
    if kind == "hash":
        return fake.random_element([fake.md5, fake.sha1, fake.sha256])()
    if kind == "ip-range":
        return ".".join(fake.ipv4_public().split(".")[:3]) + ".0/24"
    return _line(fake.random_element(["ip", "url", "hash", "ip-range"]))


@router.get("/ioc2/feeds")
async def feeds(
    type: str | None = None,
    max_count: int | None = None,
) -> Response:
    """A few IOCs of the type asked (any type when none): one value per line."""
    count = min(max_count or 5, 5)
    return Response(
        "\n".join(_line(type) for _ in range(count)) + "\n", media_type="text/plain"
    )
