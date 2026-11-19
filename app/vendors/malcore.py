"""Malcore: the IOC, threat and hash feeds (one POST endpoint switched by
``feed_type``), read by the OpenCTI malcore connector."""

from fastapi import APIRouter, Form

from app.fake import fake

HOSTS = ["api.malcore.io"]
router = APIRouter(prefix="/malcore", tags=["Malcore"])


def _ioc() -> dict:
    """An analysed file: the connector reads hashes, EXIF data, size and upload time."""
    sha256 = fake.sha256()
    return {
        sha256: {
            "upload_time": fake.date_time_between("-3d", "now").strftime(
                "%Y-%m-%d_%H-%M-%S"
            ),
            "hashes": {"md5": fake.md5(), "sha1": fake.sha1(), "sha256": sha256},
            "file_sizes": {"raw_byte_size": fake.random_int(4096, 2_000_000)},
            "file_exif_data": {
                "mime_type": "application/x-dosexec",
                "file_information": {"file_extension": ".exe"},
            },
        }
    }


@router.post("/api/feed")
async def feed(feed_type: str = Form(...)) -> dict:
    """``ioc`` lists files, ``threat`` scored hashes and ``hash`` plain hashes."""
    if feed_type == "ioc":
        items = [_ioc() for _ in range(6)]
    elif feed_type == "threat":
        items = [
            {"hash": fake.sha256(), "score": fake.random_int(50, 100)} for _ in range(6)
        ]
    else:
        items = [{"hash": fake.sha256()} for _ in range(6)]
    return {"success": True, "data": {"data": items, "total": len(items)}}
