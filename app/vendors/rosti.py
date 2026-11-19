"""Rösti API v2: reports with their IOCs, YARA rules, MITRE IDs and CVEs, read by the
OpenCTI rosti connector."""

import hashlib
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["api.rosti.dev"]
router = APIRouter(prefix="/rosti", tags=["Rösti"])

# Reports built by the list call, read back by id (their IOCs and rules with them)
_REPORTS: dict[str, dict] = {}
# A small IOC page makes the connector join groups across pages
_IOC_PAGE = 10

MITIGATIONS = [
    ("M1049", "Antivirus/Antimalware"),
    ("M1031", "Network Intrusion Prevention"),
    ("M1017", "User Training"),
]
CAMPAIGNS = ["SolarWinds Compromise", "Operation Wocao", "C0010"]
SOFTWARE = [("S0154", "Cobalt Strike"), ("S0002", "Mimikatz")]


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ioc(report_id: str, ioc_type: str, value: str, **extra) -> dict:
    seen = fake.date_time_between("-10d", "-2d")
    return {
        "id": fake.uuid4(),
        "type": ioc_type,
        "value": value,
        "category": fake.random_element(["malware", "c2", "phishing"]),
        "date": seen.strftime("%Y-%m-%d"),
        "ids": fake.pybool(),
        "report": report_id,
        "comment": fake.sentence(),
        "tags": fake.random_elements(
            ["malware", "c2", "proxy-tor", "compromised", "lookup"],
            length=2,
            unique=True,
        ),
        "risk": {
            "level": fake.random_int(0, 3),
            "meaning": fake.random_element(["nothing found", "small", "moderate"]),
            "msg": None,
        },
        "timestamp": _iso(seen),
        "entity_ref": None,
        **extra,
    }


def _iocs(report_id: str) -> list[dict]:
    """File hashes of one sample and a domain with its address come as groups."""
    sample, network = fake.uuid4(), fake.uuid4()
    domain, address = fake.domain_name(), fake.ipv4_public()
    sha256 = fake.sha256()
    iocs = [
        _ioc(report_id, "md5", fake.md5(), entity_ref=sample),
        _ioc(report_id, "sha1", fake.sha1(), entity_ref=sample),
        _ioc(report_id, "sha256", sha256, entity_ref=sample),
        _ioc(report_id, "filename", "invoice_scan.exe", entity_ref=sample),
        _ioc(report_id, "domain", domain, entity_ref=network),
        _ioc(report_id, "ip", address, entity_ref=network),
        _ioc(report_id, "url", f"https://{domain}/gate.php", entity_ref=network),
        _ioc(report_id, "domain", fake.domain_name()),
        _ioc(report_id, "ip", fake.ipv4_public()),
        _ioc(report_id, "ip:port", f"{fake.ipv4_public()}:8443"),
        _ioc(report_id, "domain:ip", f"{fake.domain_name()}:{fake.ipv4_public()}"),
        _ioc(report_id, "sha512", hashlib.sha512(fake.binary(32)).hexdigest()),
        _ioc(report_id, "ssdeep", fake.ssdeep()),
        _ioc(report_id, "filepath", "C:\\Users\\Public\\Libraries\\update.dll"),
        _ioc(report_id, "email", fake.email()),
        _ioc(report_id, "mutex", fake.mutex_name()),
        _ioc(report_id, "user-agent", fake.user_agent()),
        _ioc(report_id, "blockchain", "bc1q" + fake.sha1()[:38]),
        _ioc(report_id, "port", "4444"),
    ]
    return iocs


def _yara() -> list[dict]:
    """A rule using another rule of the report, which the connector must complete."""
    base = "base_" + fake.lexify("????????")
    family = "family_" + fake.lexify("????????")
    marker = fake.lexify("??????????")
    rules = [
        (base, f'rule {base} {{ strings: $a = "{marker}" condition: $a }}'),
        (
            family,
            f'rule {family} {{ strings: $b = "{marker}_cfg" '
            f"condition: {base} and $b and filesize < 2MB }}",
        ),
    ]
    return [
        {
            "id": fake.uuid4(),
            "name": name,
            "filename": "rules.yar",
            "rule": rule,
            "tags": ["malware"],
            "hash": fake.sha256(),
        }
        for name, rule in rules
    ]


def _mitre() -> list[dict]:
    technique = fake.mitre_attack_technique()
    mitigation = fake.random_element(MITIGATIONS)
    software = fake.random_element(SOFTWARE)
    return [
        {
            "id": technique["external_id"],
            "description": technique["name"],
            "object_type": "techniques",
        },
        {
            "id": mitigation[0],
            "description": mitigation[1],
            "object_type": "mitigations",
        },
        {
            "id": fake.mitre_attack_group_id(),
            "description": fake.intrusion_set(),
            "object_type": "groups",
        },
        {
            "id": "C" + fake.numerify("####"),
            "description": fake.random_element(CAMPAIGNS),
            "object_type": "campaigns",
        },
        {"id": software[0], "description": software[1], "object_type": "software"},
        {"id": "TA0001", "description": "Initial Access", "object_type": "tactics"},
    ]


def _report(index: int) -> dict:
    report_id = fake.bothify("????????").lower() + str(index)
    updated = _now() - timedelta(hours=6 * (3 - index), minutes=index)
    with_iocs = index != 2
    iocs = _iocs(report_id) if with_iocs else []
    rules = _yara() if index != 1 else []
    report = {
        "id": report_id,
        "title": f"{fake.intrusion_set()} campaign delivers {fake.malware_family()}",
        "date": (updated - timedelta(days=2)).strftime("%Y-%m-%d"),
        "url": f"https://{fake.domain_name()}/blog/{fake.slug()}",
        "authors": [fake.name()],
        "tags": ["apt", "windows"],
        "count": {
            "iocs": len(iocs),
            "yara_rules": len(rules),
            "mitre_ids": 6 if index else 0,
        },
        "source": {"id": fake.uuid4(), "name": fake.company(), "url": fake.url()},
        "last_updated": _iso(updated),
        "mitre_ids": _mitre() if index else [],
        "cve": (
            [
                {
                    "id": fake.cve_id(),
                    "description": fake.sentence(),
                    "timestamp": _iso(updated),
                }
            ]
            if index != 1
            else []
        ),
        "notes": [],
    }
    _REPORTS[report_id] = {"report": report, "iocs": iocs, "yara": rules}
    return report


def _page(items: list[dict], cursor: str | None, size: int) -> dict:
    start = int(cursor or 0)
    end = start + size
    more = end < len(items)
    return {
        "data": items[start:end],
        "meta": {"has_more": more, "next_cursor": str(end) if more else None},
    }


def _known(report_id: str) -> dict:
    if report_id not in _REPORTS:
        raise HTTPException(404, "report not found")
    return _REPORTS[report_id]


@router.get("/v2/reports")
async def reports(
    timestamp: str | None = None,
    limit: int = 100,
    cursor: str | None = None,
) -> dict:
    """Reports updated after the timestamp, oldest change first (one page of three)."""
    if cursor is None:
        _REPORTS.clear()
        for index in range(3):
            _report(index)
    listed = sorted(
        (entry["report"] for entry in _REPORTS.values()),
        key=lambda r: r["last_updated"],
    )
    if timestamp:
        listed = [r for r in listed if r["last_updated"] >= timestamp]
    summaries = [
        {k: v for k, v in r.items() if k not in ("mitre_ids", "cve", "notes")}
        for r in listed
    ]
    return _page(summaries, cursor, limit)


@router.get("/v2/reports/{report_id}")
async def report(report_id: str, mitre_ids: bool = False, cve: bool = False) -> dict:
    """One report, with its MITRE IDs and CVEs on request."""
    detail = dict(_known(report_id)["report"])
    if not mitre_ids:
        detail.pop("mitre_ids")
    if not cve:
        detail.pop("cve")
    return detail


@router.get("/v2/reports/{report_id}/iocs")
async def report_iocs(
    report_id: str, limit: int = 100, cursor: str | None = None
) -> dict:
    """The IOCs of a report, pages of ten, groups of one entity next to each other."""
    return _page(_known(report_id)["iocs"], cursor, min(limit, _IOC_PAGE))


@router.get("/v2/reports/{report_id}/yara-rules")
async def report_yara_rules(report_id: str) -> dict:
    """The YARA rules of a report."""
    return {"data": _known(report_id)["yara"]}
