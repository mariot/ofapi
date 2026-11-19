"""Dragos WorldView portal API v1: products (reports), their PDF and their indicators,
read by the OpenCTI dragos connector."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query, Response

from app.fake import fake
from app.vendors.fixtures import _pdf, _report_text

HOSTS = ["portal.dragos.com"]
router = APIRouter(prefix="/dragos", tags=["Dragos"])

# serial, title, type, tags (type, text), age in days
PRODUCTS = [
    (
        "WW-2026-01",
        "Energy sector intrusion set targets power grid operators",
        "Threat Report",
        [
            ("Industry", "Energy"),
            ("ThreatGroup", "KAMACITE"),
            ("Malware", "PIPEDREAM"),
            ("CVE", "CVE-2024-3400"),
            ("Government Organization", "CISA"),
            ("Topic", "OT security"),
        ],
        3,
    ),
    (
        "DOM-2026-02",
        "Suspect domains registered against industrial vendors",
        "Suspect Domain Report",
        [("Industry", "Manufacturing"), ("ExternalName", "DOMAIN-WATCH")],
        6,
    ),
]


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _product(serial: str, title: str, kind: str, tags: list, age: int) -> dict:
    released = datetime.now(UTC) - timedelta(days=age)
    return {
        "tlp_level": "amber",
        "title": title,
        "executive_summary": (
            f"<p>{fake.paragraph()}</p><ul><li>{fake.sentence()}</li>"
            f"<li>{fake.sentence()}</li></ul>"
        ),
        "updated_at": _stamp(released + timedelta(hours=2)),
        "threat_level": 3,
        "serial": serial,
        "ioc_count": 7,
        "tags": [{"text": text, "tag_type": tag_type} for tag_type, text in tags],
        "release_date": _stamp(released),
        "type": kind,
        "report_link": f"https://portal.dragos.com/api/v1/products/{serial}/report",
        "ioc_csv_link": f"https://portal.dragos.com/api/v1/products/{serial}/csv",
        "ioc_stix2_link": f"https://portal.dragos.com/api/v1/products/{serial}/stix2",
    }


def _after(stamp: str | None) -> datetime | None:
    return datetime.fromisoformat(stamp.replace(" ", "+")) if stamp else None


@router.get("/api/v1/products")
async def products(
    page: int = 1,
    page_size: int = 50,
    updated_after: str | None = None,
    serials: Annotated[list[str] | None, Query()] = None,
) -> dict:
    """The products, oldest release first; a page past the last one is empty."""
    since = _after(updated_after)
    rows = [_product(*p) for p in PRODUCTS]
    rows.sort(key=lambda p: p["release_date"])
    if serials:
        rows = [p for p in rows if p["serial"] in serials]
    if since:
        rows = [p for p in rows if _after(p["updated_at"]) > since]
    total_pages = max(1, -(-len(rows) // page_size))
    start = (page - 1) * page_size
    return {
        "products": rows[start : start + page_size],
        "total": len(rows),
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


@router.get("/api/v1/products/{serial}/report")
async def product_report(serial: str) -> Response:
    """The report as a PDF."""
    return Response(
        _pdf(f"Dragos report {serial}\n\n{_report_text()}"),
        media_type="application/pdf",
    )


def _indicator(number: int, kind: str, value: str, serial: str) -> dict:
    seen = datetime.now(UTC) - timedelta(days=number + 10)
    return {
        "id": 1000 + number,
        "value": value,
        "indicator_type": kind,
        "category": None,
        "comment": fake.sentence(),
        "first_seen": _stamp(seen),
        "last_seen": _stamp(seen + timedelta(days=5)),
        "updated_at": _stamp(seen + timedelta(days=5, hours=1)),
        "confidence": fake.random_element(["low", "moderate", "high"]),
        "kill_chain": None,
        "uuid": fake.uuid4(),
        "status": "released",
        "severity": None,
        "attack_techniques": ["Command and Control:Dynamic Resolution"],
        "ics_attack_techniques": [],
        "kill_chains": [],
        "pre_attack_techniques": [],
        "threat_groups": [],
        "products": [{"serial": serial}],
    }


@router.get("/api/v1/indicators")
async def indicators(
    page: int = 1,
    page_size: int = 500,
    serial: Annotated[list[str] | None, Query()] = None,
) -> dict:
    """The indicators of the products asked: every type the connector maps."""
    rows = []
    for serial_ in serial or []:
        rows += [
            _indicator(1, "domain", fake.domain_name(), serial_),
            _indicator(2, "ip", fake.ipv4_public(), serial_),
            _indicator(3, "md5", fake.md5(), serial_),
            _indicator(4, "sha1", fake.sha1(), serial_),
            _indicator(5, "sha256", fake.sha256(), serial_),
            _indicator(6, "url", f"https://{fake.domain_name()}/stage2", serial_),
        ]
    total_pages = max(1, -(-len(rows) // page_size))
    start = (page - 1) * page_size
    return {
        "indicators": rows[start : start + page_size],
        "total": len(rows),
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }
