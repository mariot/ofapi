"""NSFOCUS Threat Intelligence (NTI): the feed package, a zip of JSON-lines files (IOCs,
IP, domain, URL and sample basics), read by the OpenCTI nti connector."""

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Header, HTTPException, Response

from app.fake import fake

HOSTS = ["nti.nsfocusglobal.com"]
router = APIRouter(prefix="/nti", tags=["NTI"])

PREFIX = "data.NTI.API.V2.0"


def _time(hours_ago: int = 3) -> str:
    when = datetime.now(UTC) - timedelta(hours=hours_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _later(days: int = 30) -> str:
    when = datetime.now(UTC) + timedelta(days=days)
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _ioc(pattern: str, observable: dict, **extra) -> dict:
    return {
        "id": f"indicator--{fake.uuid4()}",
        "pattern": pattern,
        "observables": [observable],
        "modified": _time(),
        "valid_until": _later(),
        "confidence": fake.random_int(60, 95),
        "revoked": False,
        "threat_level": fake.random_int(2, 5),
        "threat_types": [104, 40702],
        "tags": [
            {"tag_type": "direction", "tag_values": ["inbound"]},
            {"tag_type": "family", "tag_values": [fake.malware_family()]},
        ],
        **extra,
    }


def _hashes() -> dict:
    return {
        "MD5": fake.md5(),
        "SHA1": fake.sha1(),
        "SHA256": fake.sha256(),
        "1KHASH": fake.sha1(),
    }


def _iocs() -> list[dict]:
    ip = fake.ipv4_public()
    ip_observable = {"type": "ipv4-addr", "address": {"type": "ipv4-addr", "value": ip}}
    domain = fake.domain_name()
    hashes = _hashes()
    file_pattern = f"[file:hashes.'MD5' = '{hashes['MD5']}']"
    url = fake.url()
    return [
        _ioc(f"[ipv4-addr:value = '{ip}']", ip_observable),
        # the same indicator listed twice: the connector merges its tags and levels
        _ioc(f"[ipv4-addr:value = '{ip}']", ip_observable, threat_types=[102]),
        _ioc(
            f"[domain-name:value = '{domain}']",
            {"type": "domain-name", "value": domain},
        ),
        _ioc(f"[url:value = '{url}']", {"type": "url", "value": url}),
        _ioc(file_pattern, {"type": "file", "hashes": hashes}),
    ]


def _ip_basics() -> list[dict]:
    return [
        {
            "object": {"type": "ipv4-addr", "value": fake.ipv4_public()},
            "modified": _time(),
            "locations": [
                {
                    "country": "United States",
                    "region": "California",
                    "city": "Los Angeles",
                    "latitude": 34.05,
                    "longitude": -118.24,
                    "postal_code": "90001",
                },
                {"country": "Germany"},
            ],
            "ases": [
                {
                    "number": f"AS{fake.random_int(1000, 64000)}",
                    "name": fake.company(),
                    "rir": "arin",
                    "country_code": "US",
                    "registered": ["2001-03-30"],
                    "first_seen": _time(2000),
                    "last_seen": _time(),
                }
            ],
        }
        for _ in range(3)
    ]


def _domain_basics() -> list[dict]:
    return [
        {
            "object": {"type": "domain-name", "value": fake.domain_name()},
            "modified": _time(),
            "ips": [
                {
                    "ips": [fake.ipv4_public()],
                    "first_seen": _time(900),
                    "last_seen": _time(5),
                },
                {"ips": [fake.ipv6()], "first_seen": _time(400)},
            ],
        }
        for _ in range(2)
    ]


def _url_basics() -> list[dict]:
    return [
        {
            "object": {"type": "url", "value": fake.url()},
            "modified": _time(),
            "contents": [{"contents": [29, 65]}],
            "industries": [{"industries": [10, 24]}],
            "businesses": [{"businesses": [12]}],
        }
        for _ in range(2)
    ]


def _samples() -> list[dict]:
    return [
        {
            "type": "sample",
            "modified": _time(),
            "names": [fake.file_name(extension="exe")],
            "metadata": {
                "hashes": _hashes(),
                "size": fake.random_int(10000, 900000),
                "mime_type": "application/x-dosexec",
            },
        }
        for _ in range(2)
    ]


def _package(kind: str, rows: list[dict], day: str) -> tuple[str, bytes]:
    """A feed file: a header line, then one JSON object per line."""
    header = {"feed": kind, "version": "2.0", "count": len(rows)}
    lines = [json.dumps(header), *(json.dumps(row) for row in rows)]
    return f"{PREFIX}.{kind}-updated.{day}.0001.json", "\n".join(lines).encode()


@router.get("/api/v2/download/feed/")
async def feed(key: str | None = Header(None, alias="X-Ns-Nti-Key")):
    """The zip of every feed file of the day."""
    if not key:
        raise HTTPException(401, "missing API key")
    day = datetime.now(UTC).strftime("%Y%m%d")
    files = [
        _package("ioc", _iocs(), day),
        _package("ip-basic", _ip_basics(), day),
        _package("domain-basic", _domain_basics(), day),
        _package("url-basic", _url_basics(), day),
        _package("sample", _samples(), day),
    ]
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files:
            archive.writestr(name, data)
    return Response(out.getvalue(), media_type="application/zip")
