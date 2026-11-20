"""URLhaus (abuse.ch): the recent URLs CSV feed (urlhaus connector) and the recent
payloads API with the payload download (urlhaus-recent-payloads connector, ``Auth-Key``
header)."""

import io
import zipfile
from datetime import datetime, timedelta

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["urlhaus.abuse.ch", "urlhaus-api.abuse.ch"]
router = APIRouter(prefix="/urlhaus", tags=["URLhaus"])

THREATS = ["malware_download"]
TAG_SETS = ["elf,Mozi", "exe,AgentTesla", "doc,Emotet", "", "js,SocGholish", "zip"]
FILE_TYPES = ["exe", "dll", "docm", "js", "xls"]


@router.get("/downloads/csv_recent/")
async def csv_recent() -> Response:
    """Quoted CSV rows after a commented header, newest first, online and offline."""
    now = datetime.utcnow()
    lines = [
        "################################################################",
        "# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #",
        "################################################################",
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter",
    ]
    for i, tags in enumerate(TAG_SETS):
        entry_id = fake.random_int(3_000_000, 3_900_000)
        added = now - timedelta(minutes=10 * (i + 1))
        online = i % 3 != 2
        url = (
            f"http://{fake.ipv4_public()}:{fake.random_int(80, 9000)}/{fake.word()}.sh"
        )
        if i % 2:
            url = f"https://{fake.domain_name()}/{fake.word()}/{fake.word()}.exe"
        fields = [
            str(entry_id),
            f"{added:%Y-%m-%d %H:%M:%S}",
            url,
            "online" if online else "offline",
            f"{added:%Y-%m-%d %H:%M:%S}" if online else "",
            fake.random_element(THREATS),
            tags,
            f"https://urlhaus.abuse.ch/url/{entry_id}/",
            fake.random_element(["geenensp", "abus3reports", "Cryptolaemus1"]),
        ]
        lines.append(",".join(f'"{field}"' for field in fields))
    return Response("\n".join(lines) + "\n", media_type="text/plain")


@router.get("/v1/payloads/recent/")
async def payloads_recent() -> dict:
    """Recent payloads: one of an unknown type, one without signature, others fine."""
    payloads = []
    for i in range(6):
        sha256 = fake.sha256()
        payloads.append(
            {
                "md5_hash": fake.md5(),
                "sha256_hash": sha256,
                "file_type": "unknown" if i == 4 else FILE_TYPES[i % len(FILE_TYPES)],
                "file_size": str(fake.random_int(4096, 900_000)),
                "signature": None if i == 5 else fake.malware_family(),
                "firstseen": (datetime.utcnow() - timedelta(minutes=5 * i)).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "urlhaus_download": f"https://urlhaus-api.abuse.ch/v1/download/{sha256}/",
                "virustotal": None,
                "imphash": fake.md5(),
                "ssdeep": fake.ssdeep(),
                "tlsh": fake.tlsh(),
            }
        )
    return {"query_status": "ok", "payloads": payloads}


@router.get("/v1/download/{sha256}/")
async def download(sha256: str) -> Response:
    """The sample, zipped as the service serves it."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(sha256, b"MZ\x90\x00" + fake.sha256().encode() + b"\x00" * 64)
    return Response(buffer.getvalue(), media_type="application/zip")
