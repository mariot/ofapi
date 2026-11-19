"""Modat Magnify: the host details of an IPv4 address, read by the OpenCTI
modat-enrichment connector."""

import json

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["api.magnify.modat.io"]
router = APIRouter(prefix="/modat", tags=["Modat"])


def _name(common: str, org: str) -> dict:
    return {
        "common_name": [common],
        "organization": [org],
        "country": ["US"],
        "locality": ["San Francisco"],
    }


def _cve(score: float, kev: bool = False) -> dict:
    return {"id": fake.cve_id(), "cvss": score, "is_kev": kev}


def _tls_service(domains: list[str]) -> dict:
    """An HTTPS service whose certificate names the host's domains."""
    issuer = _name("R11", "Let's Encrypt")
    return {
        "transport": "tcp",
        "protocol": "http",
        "last_scanned_port": 443,
        "ports": [443, 8443],
        "scanned_at": fake.date_time_this_month().isoformat() + "Z",
        "banner": "HTTP/1.1 200 OK\r\nServer: nginx\r\n",
        "fingerprints": {
            "service": {"name": "nginx", "version": "1.24.0"},
            "os": {"name": "Ubuntu"},
            "technologies": [{"name": "PHP", "version": "8.2"}, "jQuery"],
        },
        "http": {
            "title": "Welcome",
            "status_code": 200,
            "headers": {"server": "nginx/1.24.0", "content-type": "text/html"},
        },
        "tls": {
            "fingerprint_sha256": fake.sha256(),
            "fingerprint_sha1": fake.sha1(),
            "serial_number": fake.sha1()[:32],
            "issuer": issuer,
            "subject": _name(domains[0], "Example Corp"),
            "valid_from": "2026-01-10T00:00:00Z",
            "expires_at": "2027-01-10T00:00:00Z",
            "is_self_signed": False,
            "supported_versions": ["TLSv1.2", "TLSv1.3"],
            "extensions": {"subject_alt_name": {"dns": domains}},
            "raw": (
                "Certificate:\n    Data:\n        Signature Algorithm: "
                "sha256WithRSAEncryption\n        Subject Public Key Info:\n"
                "            Public Key Algorithm: rsaEncryption\n"
            ),
        },
        "cves": [_cve(7.5)],
    }


@router.get("/host/{ip}/v1")
async def host_details(ip: str) -> Response:
    """The Magnify record of a host: ASN, geolocation, domains, services and CVEs."""
    domains = [fake.domain_name(), "www." + fake.domain_name()]
    record = {
        "ip": ip,
        "asn": {"number": fake.random_int(1000, 64000), "org": fake.company()},
        "geo": {
            "country_name": "France",
            "city_name": "Paris",
            "country_iso_code": "FR",
        },
        "fqdns": [*domains, "*." + fake.domain_name()],
        "tags": ["Cloud Hosting", "web"],
        "is_anycast": False,
        "cves": [_cve(9.8, kev=True), _cve(5.3)],
        "services": [
            _tls_service(domains),
            {
                "transport": "tcp",
                "protocol": "ssh",
                "last_scanned_port": 22,
                "ports": [22],
                "scanned_at": fake.date_time_this_month().isoformat() + "Z",
                "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
                "fingerprints": {"service": {"name": "OpenSSH", "version": "9.6"}},
                "ssh": {"hassh": fake.md5(), "server_id": "SSH-2.0-OpenSSH_9.6"},
            },
        ],
    }
    return Response(
        content=json.dumps({"data": record}),
        media_type="application/json",
    )
