"""Zetalytics (ZoneCruncher API v2): passive DNS, live DNS, subdomains, registration and
IP context lookups, read by the OpenCTI zetalytics connector through its Python SDK."""

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["zonecruncher.com"]
router = APIRouter(prefix="/zetalytics", tags=["Zetalytics"])


def _check(token: str | None) -> None:
    if not token or len(token) != 32:
        raise HTTPException(401, "invalid token")


def _day(days_ago: int) -> str:
    return fake.date_between(f"-{days_ago}d", f"-{days_ago - 5}d").isoformat()


def _record(rrtype: str, value: str) -> dict:
    return {
        "qname": "",
        "rrtype": rrtype,
        "value": value,
        "date": _day(200),
        "last_seen": _day(20),
    }


def _results(rows: list[dict]) -> dict:
    return {"results": rows}


@router.get("/api/v2/domain2rrtypes")
async def domain2rrtypes(q: str, token: str | None = None) -> dict:
    """Passive DNS records of a domain, one row per record type."""
    _check(token)
    rows = [
        _record("a", fake.ipv4_public()),
        _record("a", fake.ipv4_public()),
        _record("aaaa", fake.ipv6()),
        _record("cname", f"edge.{fake.domain_name()}"),
        _record("ns", f"ns1.{fake.domain_name()}"),
        _record("mx", f"10 mail.{fake.domain_name()}"),
        _record("txt", "v=spf1 include:_spf.example.net ~all"),
        _record("soa_email", fake.email()),
    ]
    for row in rows:
        row["qname"] = q
    return _results(rows)


@router.get("/api/v2/liveDNS")
async def live_dns(q: str, token: str | None = None) -> dict:  # noqa: ARG001
    """Records resolved right now."""
    _check(token)
    return _results(
        [_record("a", fake.ipv4_public()), _record("ns", fake.domain_name())]
    )


@router.get("/api/v2/subdomains")
async def subdomains(q: str, token: str | None = None) -> dict:
    """Subdomains seen under a domain."""
    _check(token)
    rows = [
        {"qname": f"{fake.word()}.{q}", "date": _day(300), "last_seen": _day(10)}
        for _ in range(4)
    ]
    return _results(rows)


@router.get("/api/v2/domain2d8s")
async def domain2d8s(q: str, token: str | None = None) -> dict:  # noqa: ARG001
    """Registration context of a domain."""
    _check(token)
    row = {
        "registrar": "Gandi SAS",
        "creation_date": _day(900),
        "updated_date": _day(100),
        "expiry_date": fake.date_between("+100d", "+400d").isoformat(),
        "registrant_org": fake.company(),
        "registrant_country": fake.country_code(),
        "status": "clientTransferProhibited",
    }
    return _results([row])


@router.get("/api/v2/domain2whois")
async def domain2whois(q: str, token: str | None = None) -> dict:
    """Historical WHOIS snapshots."""
    _check(token)
    rows = [
        {
            "domain": q,
            "registrar": "Gandi SAS",
            "registrant_email": fake.email(),
            "date": _day(400 + 100 * n),
        }
        for n in range(2)
    ]
    return _results(rows)


@router.get("/api/v2/domain2nsglue")
@router.get("/api/v2/ip2nsglue")
async def nsglue(q: str, token: str | None = None) -> dict:  # noqa: ARG001
    """Nameserver glue records."""
    _check(token)
    return _results([{"ns": f"ns1.{fake.domain_name()}", "ip": fake.ipv4_public()}])


@router.get("/api/v2/ns2domain")
@router.get("/api/v2/mx2domain")
async def pivot(q: str, token: str | None = None) -> dict:
    """Domains served by a nameserver or mail host."""
    _check(token)
    rows = [
        {
            "qname": fake.domain_name(),
            "value": q,
            "date": _day(200),
            "last_seen": _day(5),
        }
        for _ in range(3)
    ]
    return _results(rows)


@router.get("/api/v2/ip")
async def ip(q: str, token: str | None = None) -> dict:  # noqa: ARG001
    """Passive DNS: names seen on an address."""
    _check(token)
    rows = [
        {"qname": fake.domain_name(), "date": _day(200), "last_seen": _day(5)}
        for _ in range(4)
    ]
    return _results(rows)


@router.get("/api/v2/ip2pwhois")
async def ip2pwhois(q: str, token: str | None = None) -> dict:
    """Routing, ASN and location context of an address."""
    _check(token)
    pwhois = {
        "Origin-AS": fake.random_int(1000, 64000),
        "AS-Org-Name": fake.company(),
        "Prefix": f"{'.'.join(q.split('.')[:2])}.0.0/16"
        if "." in q
        else "2001:db8::/32",
        "Org-Name": fake.company(),
        "Net-Name": fake.word().upper() + "-NET",
        "City": fake.city(),
        "Region": fake.state(),
        "Country": "France",
        "Country-Code": "FR",
        "Latitude": float(fake.latitude()),
        "Longitude": float(fake.longitude()),
    }
    return _results([{"pwhois": pwhois, "r": "ripencc"}])
