"""Shodan: the REST API (``api.shodan.io``) and InternetDB (``internetdb.shodan.io``),
read by the OpenCTI shodan and shodan-internetdb enrichment connectors.

The OpenAEV Shodan injector uses the older fake of the ``/shodan`` prefix
(``app/main.py``); this one answers the real hosts under its own prefix.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["api.shodan.io", "internetdb.shodan.io"]
router = APIRouter(prefix="/shodan-service", tags=["Shodan"])

PRODUCTS = [
    ("nginx", "cpe:/a:nginx:nginx:1.18.0"),
    ("Apache httpd", "cpe:/a:apache:http_server:2.4.52"),
    ("OpenSSH", "cpe:/a:openbsd:openssh:8.9p1"),
]


def _banner(ip: str, port: int, hostname: str) -> dict:
    """A service banner; the HTTPS one carries a certificate."""
    product, cpe = fake.random_element(PRODUCTS)
    banner = {
        "port": port,
        "transport": "tcp",
        "ip_str": ip,
        "product": product,
        "cpe": [cpe],
        "data": f"HTTP/1.1 200 OK\r\nServer: {product}\r\nContent-Length: 0\r\n\r\n",
        "hostnames": [hostname],
        "domains": [".".join(hostname.split(".")[-2:])],
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f"),
        "opts": {},
        "_shodan": {"module": "https" if port == 443 else "http"},
    }
    if port == 443:
        issued = datetime.now(UTC) - timedelta(days=90)
        banner["ssl"] = {
            "versions": ["-TLSv1", "TLSv1.2", "TLSv1.3"],
            "cert": {
                "sig_alg": "sha256WithRSAEncryption",
                "issued": issued.strftime("%Y%m%d%H%M%SZ"),
                "expires": (issued + timedelta(days=365)).strftime("%Y%m%d%H%M%SZ"),
                "expired": False,
                "version": 2,
                "serial": fake.random_number(digits=30, fix_len=True),
                "issuer": {"C": "US", "O": "Staticfire", "CN": "Staticfire CA"},
                "subject": {"CN": hostname},
                "pubkey": {"type": "rsa", "bits": 2048},
                "fingerprint": {"sha256": fake.sha256(), "sha1": fake.sha1()},
            },
        }
    return banner


def _host(ip: str) -> dict:
    hostname = fake.domain_name()
    return {
        "ip": 0,
        "ip_str": ip,
        "asn": f"AS{fake.random_int(1000, 399999)}",
        "isp": fake.company(),
        "org": fake.company(),
        "os": fake.random_element([None, "Linux 5.x"]),
        "city": fake.city(),
        "region_code": fake.state_abbr(),
        "country_code": fake.country_code(),
        "country_name": fake.country(),
        "latitude": float(fake.latitude()),
        "longitude": float(fake.longitude()),
        "hostnames": [hostname],
        "domains": [".".join(hostname.split(".")[-2:])],
        "tags": ["cloud"],
        "vulns": [fake.cve_id(), fake.cve_id()],
        "ports": [22, 80, 443],
        "last_update": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f"),
        "data": [_banner(ip, port, hostname) for port in (22, 80, 443)],
    }


@router.get("/shodan/host/count")
async def host_count(query: str, facets: str = "") -> dict:  # noqa: ARG001
    """Total of a search and the top values of each facet asked (``name:size``)."""
    values = {
        "org": fake.company,
        "domain": fake.domain_name,
        "port": lambda: str(fake.random_element([22, 80, 443, 8080])),
        "asn": lambda: f"AS{fake.random_int(1000, 399999)}",
        "country": fake.country_code,
    }
    result = {}
    for facet in filter(None, facets.split(",")):
        name = facet.split(":")[0]
        result[name] = [
            {"value": values[name](), "count": fake.random_int(10, 5000)}
            for _ in range(3)
        ]
    return {"matches": [], "facets": result, "total": fake.random_int(100, 90000)}


@router.get("/shodan/host/search")
async def host_search(
    query: str,  # noqa: ARG001
    page: int = Query(1),
) -> dict:
    """Matches of a search; only the first page has any."""
    if page > 1:
        return {"matches": [], "total": 3}
    matches = [_banner(fake.ipv4_public(), 443, fake.domain_name()) for _ in range(3)]
    return {"matches": matches, "total": len(matches)}


@router.get("/shodan/host/{ip}")
async def host(ip: str) -> dict:
    return _host(ip)


@router.get("/{ip}")
async def internetdb(ip: str) -> dict:
    """InternetDB: open ports, software, hostnames, tags and known vulnerabilities."""
    return {
        "cpes": [cpe for _, cpe in PRODUCTS],
        "hostnames": [fake.domain_name(), fake.domain_name()],
        "ip": ip,
        "ports": [22, 80, 443],
        "tags": ["cloud", "self-signed"],
        "vulns": [fake.cve_id(), fake.cve_id()],
    }
