"""ONYPHE: the search API (ctiscan and riskscan categories), read by the OpenCTI onyphe
enrichment connector."""

import re
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["www.onyphe.io"]
router = APIRouter(prefix="/onyphe", tags=["ONYPHE"])


def _stamp(hours: int = 2) -> str:
    when = datetime.now(UTC) - timedelta(hours=hours)
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _cert(domain: str) -> dict:
    return {
        "hostname": [domain, f"www.{domain}"],
        "domain": [domain],
        "fingerprint": {
            "md5": fake.md5(),
            "sha1": fake.sha1(),
            "sha256": fake.sha256(),
        },
        "validity": {
            "notbefore": "2026-01-10T00:00:00Z",
            "notafter": "2027-01-10T00:00:00Z",
        },
        "issuer": {"commonname": "R11", "organization": "Let's Encrypt"},
        "subject": {"commonname": domain},
        "serial": {"hex": fake.sha1()[:32]},
    }


def _ctiscan(ip: str, port: int, domain: str, asn: str, org: str) -> dict:
    return {
        "@category": "ctiscan",
        "@timestamp": _stamp(),
        "ip": {
            "dest": ip,
            "version": 4,
            "asn": asn,
            "organization": org,
            "country": "FR",
            "lcountry": "FR",
        },
        "tcp": {"dest": port, "fingerprint": {"md5": fake.md5()}},
        "scanner": {"country": "US", "ip": fake.ipv4_public()},
        "app": {
            "transport": "tcp",
            "protocol": "http",
            "tls": "true",
            "data": {
                "text": "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html>Welcome</html>",
                "sha256": fake.sha256(),
                "md5": fake.md5(),
                "mmh3": str(fake.random_int(1, 10**9)),
            },
        },
        "cert": _cert(domain),
        "dns": {"hostname": [f"mail.{domain}"], "domain": [domain]},
        "component": {"text": ["nginx", "OpenSSL"], "cve": []},
        "hhhash": {"fingerprint": {"sha256": fake.sha256(), "md5": fake.md5()}},
        "ja3s": {"fingerprint": {"md5": fake.md5()}},
        "favicon": {"data": {"sha256": fake.sha256()}},
        "http": {
            "header": {"data": {"sha256": fake.sha256()}},
            "body": {"data": {"sha256": fake.sha256()}},
        },
        "tag": ["cdn", "webserver"],
    }


def _riskscan(ip: str, port: int, domain: str, asn: str, org: str) -> dict:
    cert = _cert(domain)
    return {
        "@category": "riskscan",
        "@timestamp": _stamp(),
        "ip": ip,
        "ipv6": False,
        "port": port,
        "transport": "tcp",
        "protocol": "http",
        "tls": True,
        "asn": asn,
        "organization": org,
        "country": "FR",
        "domain": [domain],
        "hostname": [f"vpn.{domain}"],
        "tag": ["risk::opendatabase", "risk::weakcipher"],
        "cve": [fake.cve_id(), fake.cve_id()],
        "fingerprint": cert["fingerprint"],
        "validity": cert["validity"],
        "issuer": cert["issuer"],
        "subject": cert["subject"],
        "serial": fake.sha1()[:32],
    }


@router.get("/api/v2/search/")
async def search(q: str, size: int = 10, page: int = 1) -> dict:
    """The documents of the category in the query, for the address it filters on."""
    found = re.search(r"ip(?:\.dest)?:(\d+\.\d+\.\d+\.\d+)", q)
    ip = found.group(1) if found else fake.ipv4_public()
    category = "riskscan" if "category:riskscan" in q else "ctiscan"
    build = _riskscan if category == "riskscan" else _ctiscan
    domain = fake.domain_name()
    asn, org = f"AS{fake.random_int(1000, 64000)}", fake.company()
    results = [build(ip, port, domain, asn, org) for port in (443, 8443, 22)]
    start = (page - 1) * size
    return {
        "error": 0,
        "text": "OK",
        "status": "ok",
        "myip": "127.0.0.1",
        "count": len(results[start : start + size]),
        "page": page,
        "max_page": 1,
        "took": "0.05",
        "total": len(results),
        "results": results[start : start + size],
    }
