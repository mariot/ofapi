"""Kaspersky Threat Intelligence Portal (tip.kaspersky.com): the lookup API (ip,
domain, hash, url) read by the OpenCTI kaspersky-enrichment connector, and the
publications API (report list and details, Master IOC and Master YARA files, POST with
basic auth and a client certificate) read by the kaspersky import connector."""

import base64
import gzip
import time
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["tip.kaspersky.com"]
router = APIRouter(prefix="/kaspersky", tags=["Kaspersky"])

ZONES = ["Red", "Orange", "Yellow", "Gray"]
CATEGORIES = ["CATEGORY_MALWARE", "CATEGORY_PHISHING", "CATEGORY_BOTNET_CC"]
INDUSTRIES = ["Finance", "Government", "Telecommunications"]
NS_OPENIOC = "http://schemas.mandiant.com/2010/ioc"

# publication id -> its details, kept for the call that reads it after the list
PUBLICATIONS: dict[str, dict] = {}


def _zone() -> str:
    return fake.random_element(ZONES)


def _seen() -> dict:
    now = datetime.now(UTC)
    first = now - timedelta(days=fake.random_int(10, 60))
    last = now - timedelta(days=fake.random_int(1, 9))
    return {
        "FirstSeen": first.strftime("%Y-%m-%dT%H:%MZ"),
        "LastSeen": last.strftime("%Y-%m-%dT%H:%MZ"),
    }


def _license() -> dict:
    return {
        "LicenseInfo": {
            "DayRequests": fake.random_int(1, 100),
            "DayQuota": 2000,
            "Quota": 100000,
            "YearRequests": fake.random_int(100, 5000),
        }
    }


def _files() -> list[dict]:
    return [{"Md5": fake.md5(), "Zone": _zone(), **_seen()} for _ in range(2)]


def _urls() -> list[dict]:
    return [{"Url": fake.url(), "Zone": _zone(), **_seen()} for _ in range(2)]


@router.get("/api/ip/{ip}")
async def ip_lookup(ip: str) -> dict:
    """Reputation, WHOIS, DNS resolutions, hosted URLs and files of an address."""
    return {
        "Zone": "Red",
        **_license(),
        "IpGeneralInfo": {
            "Ip": ip,
            "Status": "Malware",
            "CountryCode": "RU",
            "Categories": CATEGORIES[:2],
            "HitsCount": fake.random_int(10, 5000),
            **_seen(),
        },
        "IpWhoIs": {
            "Asn": [
                {
                    "Number": str(fake.random_int(1000, 399999)),
                    "Description": fake.company(),
                }
            ],
            "Net": {"RangeStart": ip, "RangeEnd": ip, "Created": "2015-01-01"},
        },
        "FilesDownloadedFromIp": _files(),
        "HostedUrls": _urls(),
        "IpDnsResolutions": [
            {"Domain": fake.domain_name(), "Zone": _zone(), **_seen()}
        ],
        "Industries": INDUSTRIES[:2],
    }


@router.get("/api/domain/{domain}")
async def domain_lookup(domain: str) -> dict:
    """Reputation, DNS resolutions, downloaded and accessed files of a domain."""
    return {
        "Zone": "Orange",
        **_license(),
        "DomainGeneralInfo": {
            "Domain": domain,
            "Status": "Malware",
            "Categories": CATEGORIES[1:],
            "HitsCount": fake.random_int(10, 5000),
            "Ipv4Count": 1,
            **_seen(),
        },
        "DomainDnsResolutions": [{"Ip": fake.ipv4_public(), "Zone": _zone()}],
        "FilesDownloaded": [
            {"Md5": fake.md5(), "Url": fake.url(), "Zone": _zone(), **_seen()}
        ],
        "FilesAccessed": _files(),
        "Industries": INDUSTRIES[1:],
    }


@router.get("/api/hash/{file_hash}")
async def hash_lookup(file_hash: str) -> dict:
    """Detections, names, download URLs and general information of a file."""
    return {
        "Zone": "Red",
        **_license(),
        "FileGeneralInfo": {
            "Md5": fake.md5().upper(),
            "Sha1": fake.sha1().upper(),
            "Sha256": file_hash.upper(),
            "Size": fake.random_int(10000, 900000),
            "Type": "PE32",
            "Categories": CATEGORIES[:1],
            "HitsCount": fake.random_int(10, 5000),
            **_seen(),
        },
        "DetectionsInfo": [
            {
                "LastDetectDate": "2026-05-01T09:30Z",
                "DetectionName": f"HEUR:Trojan.Win32.{fake.malware_family()}.gen",
                "DescriptionUrl": "https://threats.kaspersky.com/en/threat/",
                "DetectionMethod": "Heuristic",
            }
        ],
        "FileNames": [{"FileName": f"{fake.word()}.exe"}],
        "FileDownloadedFromUrls": _urls(),
        "Industries": INDUSTRIES[:1],
    }


@router.get("/api/url/{url:path}")
async def url_lookup(url: str) -> dict:
    """Reputation, host, downloaded and accessed files of a URL."""
    return {
        "Zone": "Orange",
        **_license(),
        "UrlGeneralInfo": {
            "Url": url,
            "Host": fake.domain_name(),
            "Categories": CATEGORIES[:1],
            "HitsCount": fake.random_int(10, 5000),
            **_seen(),
        },
        "FilesDownloaded": _files(),
        "FilesAccessed": _files(),
        "Industries": INDUSTRIES[:1],
    }


def _gzip_base64(data: str | bytes) -> str:
    raw = data.encode() if isinstance(data, str) else data
    return base64.b64encode(gzip.compress(raw)).decode()


def _ok(return_data: dict) -> JSONResponse:
    return JSONResponse(
        {"status": "ok", "status_msg": "ok", "return_data": return_data}
    )


def _openioc(description: str, authored: datetime) -> bytes:
    """An OpenIOC document: network indicators and hashes (some excluded by default)."""
    items = [
        ("Network/DNS", "Network", "string", fake.domain_name()),
        ("Network/URI", "Network", "string", fake.url()),
        ("PortItem/remoteIP", "PortItem", "IP", fake.ipv4_public()),
        ("FileItem/Sha256sum", "FileItem", "string", fake.sha256()),
        ("FileItem/Md5sum", "FileItem", "string", fake.md5()),
        ("FileItem/Sha1sum", "FileItem", "string", fake.sha1()),
        ("FileItem/FileName", "FileItem", "string", f"{fake.word()}.dll"),
    ]
    rows = "".join(
        f'<IndicatorItem id="{uuid.uuid4()}" condition="is">'
        f'<Context document="{document}" search="{search}" type="mir"/>'
        f'<Content type="{kind}">{value}</Content></IndicatorItem>'
        for search, document, kind, value in items
    )
    stamp = authored.strftime("%Y-%m-%dT%H:%M:%S")
    return (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<ioc xmlns="{NS_OPENIOC}" id="{uuid.uuid4()}" last-modified="{stamp}">'
        f"<short_description>{description}</short_description>"
        f"<description>{description}</description>"
        f"<authored_by>Kaspersky</authored_by><authored_date>{stamp}</authored_date>"
        f'<definition><Indicator operator="OR" id="{uuid.uuid4()}">{rows}</Indicator>'
        f"</definition></ioc>"
    ).encode()


def _yara_rule(report: str, modified: str) -> str:
    name = f"APT_{fake.word().capitalize()}_{uuid.uuid4().hex[:8]}"
    return (
        f"rule {name}\n{{\n"
        f"    meta:\n"
        f'        description = "Detects a loader used by {report}"\n'
        f'        report = "{report}"\n'
        f'        last_modified = "{modified}"\n'
        f"    strings:\n"
        f'        $a = "{fake.word()}-{uuid.uuid4().hex[:6]}" ascii\n'
        f"        $mz = {{ 4D 5A }}\n"
        f"    condition:\n"
        f"        $mz at 0 and $a\n"
        f"}}\n"
    )


def _pdf(title: str) -> bytes:
    return (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
        + f"% {title}\n".encode()
        + b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


@router.post("/api/publications/get_list")
async def publications_list(date_start: int = 0) -> JSONResponse:
    """The reports published since ``date_start`` (a unix timestamp)."""
    now = int(time.time())
    publications = []
    for age_days in (9, 5, 2):
        pub_id = uuid.uuid4().hex[:12]
        updated = now - age_days * 86400
        actor = fake.intrusion_set()
        entry = {
            "id": pub_id,
            "updated": updated,
            "published": updated - 3600,
            "name": f"{actor} targets {fake.industry_sector()} ({pub_id[:4]})",
            "desc": f"Kaspersky analysis of the {actor} activity.",
            "report_group": "apt",
            "tags": ["apt", "espionage"],
            "tags_industry": [fake.random_element(INDUSTRIES)],
            "tags_geo": ["Germany", "France"],
            "tags_actors": [actor],
        }
        PUBLICATIONS[pub_id] = entry
        if updated >= date_start:
            publications.append(entry)
    return _ok({"count": len(publications), "publications": publications})


@router.post("/api/publications/get_one")
async def publication_one(publication_id: str, include_info: str = "") -> JSONResponse:
    """A report with its PDF, YARA rules and OpenIOC indicators (base64 of gzip)."""
    entry = PUBLICATIONS.get(publication_id)
    if entry is None:
        return JSONResponse(
            {"status": "error", "status_msg": "Publication not found"}, status_code=404
        )
    details = dict(entry)
    wanted = include_info.split(",")
    if "pdf" in wanted:
        details["report_pdf"] = _gzip_base64(_pdf(entry["name"]))
    if "yara" in wanted:
        rules = "".join(_yara_rule(entry["name"], "2026-05-01") for _ in range(2))
        details["report_yara"] = _gzip_base64(rules)
    if "iocs" in wanted:
        authored = datetime.fromtimestamp(entry["published"], UTC)
        details["report_iocs"] = _gzip_base64(_openioc(entry["name"], authored))
    return _ok(details)


@router.post("/api/publications/get_master_ioc")
async def master_ioc() -> JSONResponse:
    """The Master IOC CSV: uid, publication, indicator, detection date, type."""
    today = datetime.now(UTC)
    rows = ["uid,publication,indicator,detection_date,indicator_type"]
    for i in range(6):
        publication = f"{fake.intrusion_set()} report {uuid.uuid4().hex[:4]}"
        day = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        for kind, indicator in (
            ("networkActivity", fake.domain_name()),
            ("networkActivity", fake.ipv4_public()),
            ("sha256Hash", fake.sha256()),
            ("md5Hash", fake.md5()),
        ):
            rows.append(f"{uuid.uuid4()},'{publication}',{indicator},{day},{kind}")
    return _ok({"master_ioc": _gzip_base64("\n".join(rows) + "\n")})


@router.post("/api/publications/get_master_yara")
async def master_yara() -> JSONResponse:
    """The Master YARA file: rules with description, report and modification date."""
    reports = [f"{fake.intrusion_set()} {uuid.uuid4().hex[:4]}" for _ in range(2)]
    rules = [_yara_rule(report, "2026-05-01") for report in reports for _ in range(2)]
    text = 'import "pe"\n\n' + "\n".join(rules)
    return _ok({"master_yara": _gzip_base64(text)})
