"""RST Cloud: the threat feed (gzip JSON lines per IOC type), report hub, IOC lookup,
noise control and WHOIS APIs, read by the OpenCTI rst-threat-feed, rst-report-hub,
rst-ioc-lookup, rst-noise-control and rst-whois-api connectors."""

import gzip
import ipaddress
import json
import time
import uuid

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["api.rstcloud.net"]
router = APIRouter(prefix="/rstcloud", tags=["RST Cloud"])

# MITRE techniques of the ATT&CK bundle the rst-threat-feed spec serves for the mapping
TTPS = ["T1566", "T1059", "T1003", "T1027"]
THREAT_SUFFIXES = [
    "group",
    "actor",
    "campaign",
    "tool",
    "technique",
    "ransomware",
    "backdoor",
    "rat",
    "exploit",
    "miner",
    "vuln",
    "",
]
INDUSTRIES = ["financial", "healthcare", "energy", "government", "telco"]
TAGS = ["c2", "phishing", "malware", "scanner", "botnet", "ransomware", "spam"]


def _threats() -> list[str]:
    """Threat codes of the RST taxonomy: a name and a suffix giving its kind."""
    picks = fake.random_elements(THREAT_SUFFIXES, length=3, unique=True)
    codes = []
    for suffix in picks:
        name = fake.word().lower() + fake.lexify("??").lower()
        codes.append(f"{name}_{suffix}" if suffix else name)
    return codes


def _record() -> dict:
    """The fields every feed shares."""
    collect = int(time.time()) - fake.random_int(60, 3600)
    seen = collect - fake.random_int(0, 30000)
    reports = ",".join(
        f"https://{fake.domain_name()}/{fake.slug()}"
        for _ in range(fake.random_int(1, 2))
    )
    return {
        "fseen": seen,
        "lseen": collect,
        "collect": collect,
        "tags": {
            "str": fake.random_elements(TAGS, length=2, unique=True),
            "codes": [],
        },
        "threat": _threats(),
        "score": {
            "total": fake.random_int(30, 95),
            "src": fake.random_int(40, 90),
            "tags": 20,
            "frequency": 10,
        },
        "src": {"vendor": "rst", "report": reports},
        "description": fake.sentence(),
        "cve": [fake.cve_id()] if fake.pybool() else [],
        "industry": fake.random_elements(INDUSTRIES, length=2, unique=True),
        "ttp": fake.random_elements(TTPS, length=2, unique=True),
        "fp": {"alarm": "false", "descr": ""},
    }


def _feed_whois() -> dict:
    created = fake.date_time_between("-5y", "-1y")
    return {
        "havedata": "true",
        "registrar": fake.company(),
        "registrant": fake.company(),
        "age": fake.random_int(30, 1800),
        "created": created.strftime("%Y-%m-%d %H:%M:%S"),
        "updated": "1970-01-01 00:00:00",
        "expires": fake.future_datetime().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _geo_asn() -> dict:
    return {
        "geo": {
            "country": fake.country_code(),
            "region": fake.state(),
            "city": fake.city(),
        },
        "asn": {
            "num": fake.random_int(1000, 399999),
            "org": fake.company(),
            "isp": fake.company(),
            "cloud": "",
            "domains": fake.random_int(1, 500),
        },
    }


def _ip() -> dict:
    return {
        **_record(),
        "ip": {"v4": fake.ipv4_public()},
        "ports": [443, 8080],
        **_geo_asn(),
    }


def _domain() -> dict:
    return {
        **_record(),
        "domain": fake.domain_name(),
        "resolved": {
            "whois": _feed_whois(),
            "ip": {"a": [fake.ipv4_public()], "alias": [], "cname": []},
            "status": 200,
        },
        **_geo_asn(),
    }


def _url() -> dict:
    return {
        **_record(),
        "url": f"https://{fake.domain_name()}/{fake.slug()}.php?id={fake.pyint()}",
        "resolved": {"status": 200},
    }


def _hash() -> dict:
    return {
        **_record(),
        "md5": fake.md5(),
        "sha1": fake.sha1(),
        "sha256": fake.sha256(),
        "filename": [fake.file_name(extension="exe")],
    }


FEEDS = {"ip": _ip, "domain": _domain, "url": _url, "hash": _hash}

# A PDF of one empty page, the report hub's rendering of a report
PDF = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF\n"
)
# Reports the hub lists, by id: their STIX bundle is built when listed
_REPORTS: dict[str, dict] = {}


def _json(body: dict | list, status: int = 200) -> Response:
    return Response(json.dumps(body), status_code=status, media_type="application/json")


def _reference(value: str) -> str | None:
    """The feed type a looked up value belongs to."""
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if value.startswith(("http://", "https://")):
        return "url"
    if len(value) in (32, 40, 64) and all(c in "0123456789abcdef" for c in value):
        return "hash"
    return "domain" if "." in value else None


@router.get("/v1/ioc")
async def ioc_lookup(value: str) -> Response:
    """One IOC with its score, threats and context ({} when unknown)."""
    kind = _reference(value)
    if kind is None:
        return _json({})
    record = FEEDS[kind]()
    if kind == "ip":
        record["ip"]["v4"] = value
    elif kind == "hash":
        record[{32: "md5", 40: "sha1", 64: "sha256"}[len(value)]] = value
    else:
        record[kind] = value
    record["score"]["last"] = fake.random_int(50, 95)
    record["score"]["first"] = fake.random_int(30, 80)
    record["tags"]["tags"] = record["tags"]["str"]
    return _json(
        {"id": str(uuid.uuid4()), "ioc_value": value, "ioc_type": kind, **record}
    )


@router.get("/v1/benign/lookup")
async def benign_lookup(value: str) -> Response:
    """Whether a value is known noise: resolvers are dropped, hosting scored down."""
    kind = _reference(value)
    if kind == "ip":
        reason = "Drop Public DNS/Resolver"
    elif kind in ("domain", "url"):
        reason = "Change Score Cloud/Hosting"
    else:
        return _json({"benign": "false", "reason": ""})
    return _json({"benign": "true", "reason": reason, "value": value})


def _whois(domain: str, full: bool, raw: bool) -> dict:
    created = fake.date_time_between("-8y", "-1y")
    record = {
        "domain": domain,
        "registrar": fake.company(),
        "registrant": fake.company(),
        "created": created.strftime("%Y-%m-%d %H:%M:%S"),
        "updated": fake.date_time_between(created, "now").strftime("%Y-%m-%d %H:%M:%S"),
        "expires": fake.future_datetime().strftime("%Y-%m-%d %H:%M:%S"),
        "age": fake.random_int(100, 3000),
        "nameservers": [f"ns1.{fake.domain_name()}", f"ns2.{fake.domain_name()}"],
        "status": ["clientTransferProhibited"],
    }
    if full:
        record["contacts"] = {
            "registrant": {
                "name": fake.name(),
                "email": fake.email(),
                "country": fake.country_code(),
            },
            "admin": {"name": fake.name(), "email": fake.email()},
        }
    if raw:
        record["raw"] = (
            f"Domain Name: {domain.upper()}\nRegistrar: {record['registrar']}"
        )
    return record


@router.get("/v1/whois/full/raw/{domain}")
async def whois_full_raw(domain: str) -> Response:
    """WHOIS in the extended format, with the raw record."""
    return _json(_whois(domain, True, True))


@router.get("/v1/whois/full/{domain}")
async def whois_full(domain: str) -> Response:
    """WHOIS in the extended format."""
    return _json(_whois(domain, True, False))


@router.get("/v1/whois/raw/{domain}")
async def whois_raw(domain: str) -> Response:
    """WHOIS in the standard format, with the raw record."""
    return _json(_whois(domain, False, True))


@router.get("/v1/whois/{domain}")
async def whois_standard(domain: str) -> Response:
    """WHOIS in the standard format."""
    return _json(_whois(domain, False, False))


def _report_bundle() -> dict:
    """A report with indicators of every type the hub maps, threats and techniques."""
    indicators = [
        fake.stix_indicator(stix_type=kind)
        for kind in ("ipv4-addr", "domain-name", "url", "file", "email-addr")
    ]
    malware = fake.stix_malware()
    group = fake.stix_intrusion_set()
    mitre = fake.stix_attack_pattern()
    custom = fake.stix_attack_pattern()
    custom.pop("x_mitre_id")
    custom.pop("external_references")
    custom["name"] = f"{fake.word().title()} Abuse Technique"
    objects = [*indicators, malware, group, mitre, custom]
    relationships = [
        fake.stix_relationship(i["id"], malware["id"], "indicates") for i in indicators
    ]
    relationships += [
        fake.stix_relationship(malware["id"], group["id"], "related-to"),
        fake.stix_relationship(group["id"], mitre["id"], "uses"),
        fake.stix_relationship(malware["id"], custom["id"], "uses"),
    ]
    objects += relationships
    report = fake.stix_report(object_refs=[o["id"] for o in objects])
    report["name"] = f"{group['name']} targets {fake.industry_sector()}"
    report["labels"] = ["apt", "phishing"]
    for obj in (*objects, report):
        obj.pop("object_marking_refs", None)
    return fake.stix_bundle(objects=[*objects, report])


@router.get("/v1/reports")
async def reports(
    id: str | None = None,
    format: str | None = None,
    lang: str = "eng",
) -> Response:
    """Reports of a day (a list), or one report as a STIX bundle or a PDF."""
    if id is None:
        for _ in range(2):
            report_id = fake.uuid4()
            _REPORTS[report_id] = _report_bundle()
        return _json([{"id": r, "lang": lang} for r in _REPORTS])
    if id not in _REPORTS:
        return _json({"message": "report not found"}, 404)
    if format == "pdf":
        return Response(PDF, media_type="application/pdf")
    return _json(_REPORTS[id])


@router.get("/v1/{ioc_type}")
async def feed(ioc_type: str) -> Response:
    """The latest feed of one IOC type: a gzip of one JSON record per line."""
    if ioc_type not in FEEDS:
        return _json({"status": "error", "message": "unknown feed"}, 404)
    lines = "\n".join(json.dumps(FEEDS[ioc_type]()) for _ in range(6))
    return Response(gzip.compress(lines.encode()), media_type="application/gzip")
