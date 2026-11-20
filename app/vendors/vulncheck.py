"""VulnCheck: the index API (KEV, NVD2, EPSS, exploits, botnets, ransomware, threat
actors, IP intelligence, initial access) and the Snort and Suricata rules, read by the
OpenCTI vulncheck connector through the VulnCheck SDK (``/v3/index/<name>``,
``/v3/rules/...``).

Every index answers in two cursor pages."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Response

from app.fake import fake
from app.vendors.nvd import _vulnerability

HOSTS = ["api.vulncheck.com"]
router = APIRouter(prefix="/vulncheck", tags=["VulnCheck"])

SDK_PATH = "/v3"


def _date(days: int = 5) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _kev() -> dict:
    return {
        "_timestamp": _date(1),
        "cve": [fake.cve_id()],
        "cwes": ["CWE-79"],
        "date_added": _date(),
        "cisa_date_added": _date(),
        "dueDate": _date(-14),
        "knownRansomwareCampaignUse": "Known",
        "product": fake.word(),
        "vendorProject": fake.company(),
        "required_action": "Apply updates per vendor instructions.",
        "shortDescription": fake.sentence(),
        "vulnerabilityName": f"{fake.company()} {fake.word()} vulnerability",
        "reported_exploited_by_vulncheck_canaries": True,
    }


def _nvd() -> dict:
    """The CVE of an NVD 2.0 vulnerability, as the nist-nvd2 index lists it."""
    return _vulnerability(fake.random_int(0, 8))["cve"]


def _epss() -> dict:
    return {
        "_timestamp": _date(1),
        "cve": fake.cve_id(),
        "epss_score": 0.42,
        "epss_percentile": 0.97,
    }


def _botnet() -> dict:
    return {
        "botnet_name": fake.malware_family(),
        "date_added": _date(),
        "cve": [fake.cve_id()],
        "cve_references": [{"cve": [fake.cve_id()], "url": fake.url()}],
    }


def _ransomware() -> dict:
    return {
        "ransomware_family": fake.malware_family(),
        "date_added": _date(),
        "cve": [fake.cve_id()],
    }


def _threat_actor() -> dict:
    return {
        "threat_actor_name": fake.intrusion_set(),
        "date_added": _date(),
        "country": "RU",
        "cve_references": [{"cve": [fake.cve_id()], "url": fake.url()}],
        "misp_threat_actor": {"description": fake.sentence(), "country": "RU"},
    }


def _ipintel() -> dict:
    return {
        "ip": fake.ipv4_public(),
        "asn": f"AS{fake.random_int(1000, 64000)}",
        "city": fake.city(),
        "country": "Germany",
        "country_code": "DE",
        "cve": [fake.cve_id()],
        "feed_ids": ["c2"],
        "hostnames": [fake.domain_name()],
        "lastSeen": _date(1).removesuffix("Z"),
        "matches": [fake.malware_family()],
    }


def _exploit() -> dict:
    return {
        "_timestamp": _date(1),
        "id": fake.cve_id(),
        "date_added": _date(),
        "inKEV": True,
        "commercial_exploit_found": False,
        "epss": {"epss_score": 0.5, "epss_percentile": 0.9},
        "exploits": [
            {
                "url": fake.url(),
                "name": f"{fake.word()} exploit",
                "date_added": _date(),
            }
        ],
    }


def _initial_access() -> dict:
    vendor = fake.word()
    return {
        "id": fake.uuid4(),
        "cve": fake.cve_id(),
        "inKEV": True,
        "inVCKEV": True,
        "vulnerable_cpes": [
            f"cpe:2.3:a:{vendor}:{fake.word()}:1.{fake.random_int(0, 9)}:*:*:*:*:*:*:*"
        ],
    }


BUILDERS = {
    "vulncheck-kev": _kev,
    "nist-nvd2": _nvd,
    "epss": _epss,
    "botnets": _botnet,
    "ransomware": _ransomware,
    "threat-actors": _threat_actor,
    "ipintel-3d": _ipintel,
    "exploits": _exploit,
    "initial-access": _initial_access,
}


def _page(name: str, cursor: str, limit: int) -> dict:
    """First page with a next cursor, then the last one."""
    build = BUILDERS[name]
    last = bool(cursor)
    return {
        "_benchmark": 0.012,
        "_meta": {
            "index": name,
            "limit": limit,
            "total_documents": 4,
            "page": 2 if last else 1,
            "next_cursor": None if last else "page2",
            "timestamp": _date(0),
        },
        "data": [build() for _ in range(2)],
    }


@router.api_route("/v3/index/{name}", methods=["GET", "HEAD"])
async def index(
    name: str, response: Response, cursor: str = "", limit: int = 100
) -> dict | str:
    """One page of an index (the IP intelligence one is ``ipintel-3d``)."""
    if name == "ipintel":  # the availability check of the connector (HEAD)
        return ""
    if name not in BUILDERS:
        response.status_code = 404
        return "index not found"
    return _page(name, cursor, limit)


def _rules(kind: str) -> str:
    rules = []
    for _ in range(3):
        sid = fake.random_int(5_000_000, 5_999_999)
        cve = fake.cve_id()
        rules.append(
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"VULNCHECK {kind} '
            f'{cve} exploit attempt"; flow:to_server,established; '
            f'content:"/{fake.word()}"; http_uri; reference:cve,{cve}; '
            f"sid:{sid}; rev:1;)\n"
        )
    return "".join(rules)


@router.api_route("/v3/rules/initial-access/{kind}", methods=["GET", "HEAD"])
async def rules(kind: str) -> Response:
    return Response(_rules(kind), media_type="text/plain")
