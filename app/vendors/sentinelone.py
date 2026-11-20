"""SentinelOne management console (``<tenant>.sentinelone.net``, API v2.1), read by the
OpenCTI sentinelone-incidents, sentinelone-threats and sentinelone-intel connectors.

The OpenAEV components use the older fake of the ``/sentinelone`` prefix
(``app/main.py``); this one answers the real console host under its own prefix.
"""

import hashlib
import struct
import zlib
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["*.sentinelone.net"]
router = APIRouter(prefix="/sentinelone-console", tags=["SentinelOne"])

ZIP_PASSWORD = b"S1BinaryVault"
CLASSIFICATIONS = ["Malware", "Trojan", "Ransomware", "PUA", "Hacktool"]
TECHNIQUES = [
    ("Command and Scripting Interpreter", "T1059"),
    ("OS Credential Dumping", "T1003"),
    ("Process Injection", "T1055"),
    ("Ingress Tool Transfer", "T1105"),
]

# Threats served by id (their downloadable file), filled when they are listed
FILES: dict[str, bytes] = {}


def _timestamp(minutes_ago: int) -> str:
    moment = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _threat(minutes_ago: int, **info) -> dict:
    """A threat as listed by ``GET /threats``, its hashes those of its download."""
    content = b"MZ" + fake.binary(length=256)
    threat_id = fake.numerify("1#################")
    FILES[threat_id] = content
    name = f"{fake.word()}{fake.random_int(1, 99)}.exe"
    created = _timestamp(minutes_ago)
    technique, link = fake.random_element(TECHNIQUES)
    return {
        "id": threat_id,
        "agentRealtimeInfo": {
            "agentComputerName": f"{fake.word()}-pc-{fake.random_int(1, 99)}",
            "accountId": "1000000000000000001",
            "accountName": "Staticfire",
            "agentOsType": "windows",
        },
        "indicators": [
            {
                "category": "Persistence",
                "description": "Persistence through a scheduled task",
                "ids": [fake.random_int(1, 99)],
                "tactics": [
                    {
                        "name": "Persistence",
                        "source": "MITRE",
                        "techniques": [
                            {
                                "name": link + " " + technique,
                                "link": f"https://attack.mitre.org/techniques/{link}",
                            }
                        ],
                    }
                ],
            }
        ],
        "threatInfo": {
            "threatId": threat_id,
            "threatName": name,
            "filePath": f"\\Device\\HarddiskVolume3\\Users\\Public\\{name}",
            "fileExtension": "EXE",
            "sha1": hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "md5": hashlib.md5(content).hexdigest(),
            "classification": fake.random_element(CLASSIFICATIONS[:3]),
            "classificationSource": "Static",
            "confidenceLevel": "malicious",
            "analystVerdict": "undefined",
            "mitigationStatusDescription": "Mitigated",
            "createdAt": created,
            "identifiedAt": created,
            "updatedAt": created,
            **info,
        },
    }


@router.get("/web/api/v2.1/threats")
async def threats(skip: int = 0, cursor: str = "") -> dict:
    """Threats, newest first.

    Skip based paging (incidents connector): four threats, ``totalItems`` says so.
    Cursor based paging (threats connector): the first page has a ``nextCursor``, the
    second and last one has none, as the API does for the end of a result set.
    """
    if cursor:
        return {
            "data": [_threat(40)],
            "pagination": {"nextCursor": None, "totalItems": 1},
        }
    if skip:
        return {"data": [], "pagination": {"nextCursor": None, "totalItems": 4}}
    page = [
        _threat(5),
        _threat(15),
        _threat(25, analystVerdict="false_positive"),
        _threat(35, classification="PUA", fileExtension="DLL"),
    ]
    return {"data": page, "pagination": {"nextCursor": fake.sha1(), "totalItems": 4}}


@router.get("/web/api/v2.1/threats/{threat_id}/notes")
async def threat_notes(threat_id: str) -> dict:  # noqa: ARG001
    notes = [
        {
            "id": fake.numerify("1#################"),
            "text": fake.sentence(),
            "creator": fake.email(),
            "createdAt": _timestamp(3),
        }
    ]
    return {"data": notes, "pagination": {"nextCursor": None, "totalItems": 1}}


def _zip_crypto(name: str, content: bytes, password: bytes) -> bytes:
    """A ZIP archive holding ``name``, stored and encrypted with the traditional
    PKWARE cipher (what the console's password protected downloads use)."""
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        table.append(crc)
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(byte: int) -> None:
        keys[0] = (keys[0] >> 8) ^ table[(keys[0] ^ byte) & 0xFF]
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = (keys[2] >> 8) ^ table[(keys[2] ^ (keys[1] >> 24)) & 0xFF]

    def encrypt(byte: int) -> int:
        temp = (keys[2] | 2) & 0xFFFF
        cipher = byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF)
        update(byte)
        return cipher

    for byte in password:
        update(byte)
    crc = zlib.crc32(content)
    header = bytes(fake.random_int(0, 255) for _ in range(11)) + bytes([crc >> 24])
    data = bytes(encrypt(byte) for byte in header + content)
    raw_name = name.encode()
    fixed = struct.pack(
        "<HHHHHIIIHH", 20, 1, 0, 0, 0x21, crc, len(data), len(content), len(raw_name), 0
    )
    local = b"PK\x03\x04" + fixed + raw_name + data
    central = (
        b"PK\x01\x02"
        + struct.pack("<H", 20)
        + fixed
        + struct.pack("<HHHII", 0, 0, 0, 0, 0)
        + raw_name
    )
    end = b"PK\x05\x06" + struct.pack(
        "<HHHHIIH", 0, 0, 1, 1, len(central), len(local), 0
    )
    return local + central + end


@router.get("/web/api/v2.1/threats/{threat_id}/download-from-cloud")
async def download_from_cloud(threat_id: str) -> dict:
    """The URL of the threat's file, in a password protected archive."""
    url = f"https://staticfire.sentinelone.net/cloud-files/{threat_id}.zip"
    return {"data": {"downloadUrl": url}}


@router.get("/cloud-files/{archive}")
async def cloud_file(archive: str) -> Response:
    threat_id = archive.removesuffix(".zip")
    content = FILES.get(threat_id)
    if content is None:
        return Response(status_code=404)
    name = f"C/ProgramData/Sentinel/AFUCache/{threat_id}"
    return Response(
        content=_zip_crypto(name, content, ZIP_PASSWORD),
        media_type="application/zip",
    )


@router.post("/web/api/v2.1/threat-intelligence/iocs/stix")
async def import_iocs() -> dict:
    return {"data": {"affected": 1}}
