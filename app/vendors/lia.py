"""Loader Insight Agency: the file feed (payloads downloaded by malware loaders), read
by the OpenCTI lia-file-feed connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["loaderinsight.agency"]
router = APIRouter(prefix="/lia", tags=["Loader Insight Agency"])

LOADERS = ["smokeloader", "amadey", "privateloader", "pikabot", "bumblebee"]
PAYLOADS = ["redline", "lumma", "raccoon", "vidar", "unknown"]


def _result() -> dict:
    sha256 = fake.sha256()
    return {
        "sha256": sha256,
        "filetype": fake.random_element(["exe", "dll", "msi"]),
        "first_seen": fake.date_time_this_month().strftime("%Y-%m-%d %H:%M:%S"),
        "source_family": fake.random_element(LOADERS),
        "source_botnet": f"botnet-{fake.random_int(1, 99)}",
        "size": fake.random_int(20000, 900000),
        "source_url": fake.url() + "payload.exe",
        "detected_as": fake.random_element(PAYLOADS),
        "external_link": f"https://loaderinsight.agency/payload/{sha256}",
    }


@router.get("/api/")
@router.get("/api")
async def file_feed() -> dict:
    """The recent payloads (the connector sends ``?ep=filefeed``)."""
    return {"results": [_result() for _ in range(8)]}
