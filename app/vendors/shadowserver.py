"""Shadowserver: the reports API (``transform.shadowserver.org``) and the report
downloads (``dl.shadowserver.org``), read by the OpenCTI shadowserver connector."""

import csv
import hashlib
import hmac
import io
from datetime import UTC, datetime

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["transform.shadowserver.org", "dl.shadowserver.org"]
router = APIRouter(prefix="/shadowserver", tags=["Shadowserver"])

API_SECRET = "staticfire-fake-secret"
REPORT_URLS = {
    "blocklist": "blocklist-report",
    "device_id": "device-identification-report",
    "scan_http": "accessible-http-report",
    "scan_ssl": "accessible-ssl-report",
}

# Downloadable reports: id -> type
REPORTS: dict[str, str] = {}


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def _row(report_type: str) -> dict:
    """A row with the columns every report has, plus those of its type."""
    row = {
        "timestamp": _timestamp(),
        "ip": fake.ipv4_public(),
        "port": fake.random_element([22, 80, 443, 8080]),
        "hostname": fake.domain_name(),
        "tag": f"{report_type.replace('_', '-')};{fake.cve_id()}",
        "asn": fake.random_int(1000, 399999),
        "geo": fake.country_code(),
        "region": fake.state(),
        "city": fake.city(),
        "naics": 517311,
        "sector": "Communications, Service Provider, and Hosting Service",
        "severity": fake.random_element(["info", "low", "medium", "high"]),
    }
    if report_type == "blocklist":
        row |= {"source": fake.word(), "reason": "not-specified"}
    elif report_type == "device_id":
        row |= {"device_vendor": "Hikvision", "device_type": "video-system"}
    elif report_type == "scan_http":
        row |= {"http_code": 200, "server": "nginx", "protocol": "tcp"}
    elif report_type == "scan_ssl":
        row |= {
            "port": 443,
            "protocol": "tcp",
            "cert_serial_number": fake.hexify("^" * 16).upper(),
            "cert_issue_date": "2025-01-01 00:00:00",
            "cert_expiration_date": "2027-01-01 00:00:00",
            "md5_fingerprint": fake.md5(),
            "sha1_fingerprint": fake.sha1(),
            "sha256_fingerprint": fake.sha256(),
            "subject_common_name": fake.domain_name(),
            "issuer_common_name": "Staticfire CA",
            "handshake": "TLSv1.2",
        }
    return row


def _csv(report_type: str) -> str:
    rows = [_row(report_type) for _ in range(5)]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def _authentic(body: bytes, signature: str) -> bool:
    expected = hmac.new(API_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/api2/reports/list")
async def reports_list(request: Request) -> Response:
    """The reports of a day: ``type`` and ``reports`` filter them."""
    body = await request.body()
    if not _authentic(body, request.headers.get("hmac2", "")):
        return Response(status_code=401)
    query = await request.json()
    types = query.get("type") or list(REPORT_URLS)
    if isinstance(types, str):
        types = [types]
    day = query.get("date") or datetime.now(UTC).strftime("%Y-%m-%d")
    listing = []
    for report_type in types[: query.get("limit", 1000)]:
        if report_type not in REPORT_URLS:
            continue
        report_id = fake.sha256()[:32]
        REPORTS[report_id] = report_type
        listing.append(
            {
                "file": f"{day}-{report_type}-staticfire-ip.csv",
                "id": report_id,
                "report": "staticfire",
                "timestamp": day,
                "type": report_type,
                "url": "https://www.shadowserver.org/what-we-do/network-reporting/"
                + REPORT_URLS[report_type],
            }
        )
    return JSONResponse(listing)


@router.get("/{report_id}")
async def download(report_id: str) -> Response:
    if report_id not in REPORTS:
        return Response(status_code=404)
    return Response(content=_csv(REPORTS[report_id]), media_type="text/csv")
