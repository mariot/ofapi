"""DomainTools: Real-time Threat Feeds, Iris Detect and Iris Investigate (IrisQL), read
by the OpenCTI domaintools-feeds, domaintools-iris-detect, domaintools-irisql and
domaintools (enrichment) connectors."""

import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["api.domaintools.com"]
router = APIRouter(prefix="/domaintools", tags=["DomainTools"])


def _now() -> datetime:
    return datetime.now(UTC)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _recent() -> str:
    return _stamp(_now() - timedelta(minutes=fake.random_int(1, 50)))


def _domain() -> str:
    return f"{fake.domain_word()}-{fake.random_int(10, 99)}.{fake.tld()}"


def _risk_components() -> list[dict]:
    names = ("proximity", "threat_profile_malware", "threat_profile_phishing")
    return [
        {"name": name, "risk_score": fake.random_int(10, 100)} for name in names
    ] + [{"name": "threat_profile_spam", "risk_score": fake.random_int(10, 100)}]


# --- Real-time Threat Feeds -----------------------------------------------------------


@router.get("/v1/feed/{feed}/")
async def feed(feed: str, top: int = 10) -> Response:
    """One JSON object per line: risk feeds carry scores, observation feeds a domain."""
    risk = feed in ("domainhotlist", "domainrisk")
    lines = []
    for _ in range(min(top, 8)):
        entry = {"timestamp": _recent(), "domain": _domain()}
        if risk:
            entry |= {
                "overall_risk": fake.random_int(70, 100),
                "proximity_risk": fake.random_int(0, 100),
                "malware_risk": fake.random_int(0, 100),
                "phishing_risk": fake.random_int(0, 100),
                "spam_risk": fake.random_int(0, 100),
            }
        lines.append(json.dumps(entry))
    return Response("\n".join(lines) + "\n", media_type="application/x-ndjson")


# --- Iris Detect ----------------------------------------------------------------------

MONITORS = [
    {"id": "mon-0001", "term": "filigran"},
    {"id": "mon-0002", "term": "opencti"},
]


@router.get("/v1/iris-detect/monitors/")
async def detect_monitors() -> dict:
    return {"monitors": MONITORS, "total_count": len(MONITORS)}


@router.get("/v1/iris-detect/domains/new/")
async def detect_new_domains(offset: int = 0, limit: int = 50) -> dict:
    """Newly discovered look-alike domains, paged by offset and limit."""
    total = 5
    rows = []
    for _ in range(total):
        name = _domain()
        rows.append(
            {
                "id": fake.uuid4(),
                "domain": name,
                "tld": name.rsplit(".", 1)[-1],
                "discovered_date": _recent(),
                "changed_date": _recent(),
                "risk_score": fake.random_int(40, 100),
                "risk_score_status": "provisional",
                "risk_score_components": {
                    "proximity": fake.random_int(50, 100),
                    "threat_profile": {
                        "phishing": fake.random_int(0, 100),
                        "malware": fake.random_int(0, 100),
                        "spam": fake.random_int(0, 100),
                        "evidence": ["registrar", "mail"],
                    },
                },
                "monitor_ids": [fake.random_element([m["id"] for m in MONITORS])],
                "mx_exists": True,
                "ip": [
                    {
                        "ip": fake.ipv4_public(),
                        "country_code": "us",
                        "asn": fake.random_int(1000, 60000),
                        "isp": fake.company(),
                    }
                ],
                "mx": [
                    {
                        "host": f"mail.{name}",
                        "domain": name,
                        "ip": [fake.ipv4_public()],
                        "priority": 10,
                    }
                ],
                "name_server": [
                    {"host": "ns1.dns-host.net", "domain": "dns-host.net", "ip": []},
                    # a name server pointing at the domain itself is skipped
                    {"host": name, "domain": name, "ip": []},
                ],
                "registrar": fake.company(),
                "status": "new",
            }
        )
    return {
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "watchlist_domains": rows[offset : offset + limit],
    }


# --- Iris Investigate -----------------------------------------------------------------


def _value(value, count: int = 1) -> dict:
    return {"value": value, "count": count}


def _investigated(name: str, ip: str | None = None) -> dict:
    """An Iris Investigate result for a domain, in the API's documented shape."""
    address = ip or fake.ipv4_public()
    created = _now() - timedelta(days=fake.random_int(300, 3000))
    expires = _now() + timedelta(days=fake.random_int(30, 700))
    contact = {"email": [_value(fake.email())], "name": _value(fake.name())}
    return {
        "domain": name,
        "active": True,
        "create_date": _value(created.strftime("%Y-%m-%d")),
        "expiration_date": _value(expires.strftime("%Y-%m-%d")),
        "domain_risk": {
            "risk_score": fake.random_int(50, 100),
            "components": _risk_components(),
        },
        "ip": [
            {
                "address": _value(address),
                "asn": [_value(fake.random_int(1000, 60000))],
                "country_code": _value("us"),
                "isp": _value(fake.company()),
            }
        ],
        "mx": [
            {
                "host": _value(f"mail.{name}"),
                "domain": _value(name),
                "ip": [_value(fake.ipv4_public())],
                "priority": 10,
            }
        ],
        "name_server": [
            {
                "host": _value("ns1.example-dns.net"),
                "domain": _value("example-dns.net"),
                "ip": [_value(fake.ipv4_public())],
            }
        ],
        "admin_contact": contact,
        "billing_contact": {"email": [_value(fake.email())]},
        "registrant_contact": {"email": [_value(fake.email())]},
        "technical_contact": {"email": [_value(fake.email())]},
        "soa_email": [_value(fake.email())],
        "ssl_email": [_value(fake.email())],
        "additional_whois_email": [_value(fake.email())],
        "ssl_info": [{"email": [_value(fake.email())], "hash": _value(fake.sha1())}],
        "email_domain": [_value("mail-provider.net")],
        "redirect_domain": _value(_domain()),
        "registrar": fake.company(),
    }


def _investigation(names: list[str], ip: str | None = None) -> dict:
    results = [_investigated(name, ip) for name in names]
    return {
        "response": {
            "limit_exceeded": False,
            "has_more_results": False,
            "message": f"Your query returned {len(results)} results.",
            "results_count": len(results),
            "total_count": len(results),
            "position": "",
            "results": results,
        }
    }


@router.post("/v1/iris-investigate/")
async def investigate_ql() -> dict:
    """An IrisQL query (text/plain body): a handful of matching domains."""
    return _investigation([_domain() for _ in range(4)])


@router.get("/v1/iris-investigate/")
async def investigate(domain: str | None = None, ip: str | None = None) -> dict:
    """The lookup of the enrichment: one domain, or the domains seen on an address."""
    if domain:
        return _investigation([domain.split(",")[0]])
    return _investigation([_domain(), _domain()], ip)
