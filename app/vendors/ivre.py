"""IVRE: the web API (``/cgi``) an IVRE client reads through its ``http`` database
backend, read by the OpenCTI ivre enrichment connector (``IVRE_DB_URL`` points here).

``/cgi/ipdata/<addr>`` is the GeoIP data of an address; ``/cgi/passive`` and
``/cgi/scans`` answer a filter (``f``, a JSON search tree) with pages of records, the
last one empty.
"""

import json
import time

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["ivre.staticfire.test"]
router = APIRouter(prefix="/ivre", tags=["IVRE"])


def _search(f: str) -> dict:
    """The search function of the filter and its first argument."""
    flt = json.loads(f)
    while flt.get("f") == "and":
        flt = flt["a"][0]
    args = flt.get("a") or [""]
    return {
        "name": flt.get("f"),
        "arg": args[0],
        "reverse": (flt.get("k") or {}).get("reverse"),
    }


def _seen() -> dict:
    last = time.time() - fake.random_int(60, 86400 * 5)
    return {"firstseen": last - 86400 * 3, "lastseen": last, "count": 4}


def _certificate() -> dict:
    now = time.time()
    return {
        "md5": fake.md5(),
        "sha1": fake.sha1(),
        "sha256": fake.sha256(),
        "self_signed": True,
        "not_before": now - 86400 * 90,
        "not_after": now + 86400 * 270,
        "issuer_text": "commonName=staticfire.example.com",
        "subject_text": "commonName=staticfire.example.com",
        "pubkey": {"type": "rsa", "exponent": 65537, "bits": 2048},
    }


@router.get("/cgi/ipdata/{addr}")
async def ipdata(addr: str) -> dict:
    """GeoIP data of ``addr``: country, city, registered country and AS."""
    del addr
    return {
        "country_code": "DE",
        "country_name": "Germany",
        "registered_country_code": "NL",
        "registered_country_name": "Netherlands",
        "city": "Frankfurt am Main",
        "continent_code": "EU",
        "continent_name": "Europe",
        "coordinates": [50.1155, 8.6842],
        "as_num": fake.random_int(1000, 399999),
        "as_name": fake.company().split(",")[0],
    }


@router.get("/cgi/passive")
async def passive(f: str = "{}", q: str = "") -> list[dict]:
    """Passive records: DNS answers, a certificate, a scanner of an address; for a
    domain, its A answers (and the CNAMEs pointing to it for the reverse search)."""
    if "skip:0" not in q:
        return []
    search = _search(f)
    if search["name"] == "dns":
        domain = search["arg"]
        if search["reverse"]:
            return [
                {
                    **_seen(),
                    "recontype": "DNS_ANSWER",
                    "source": "CNAME",
                    "value": f"alias.{domain}",
                    "targetval": domain,
                }
            ]
        return [
            {
                **_seen(),
                "addr": fake.ipv4_public(),
                "recontype": "DNS_ANSWER",
                "source": "A",
                "value": value,
            }
            for value in (domain, f"mail.{domain}")
        ]
    addr = search["arg"]
    return [
        {
            **_seen(),
            "addr": addr,
            "recontype": "DNS_ANSWER",
            "source": "A",
            "value": f"host-{addr.replace('.', '-')}.{fake.domain_name()}",
        },
        {
            **_seen(),
            "addr": addr,
            "recontype": "SSL_SERVER",
            "source": "cert",
            "port": 443,
            "infos": _certificate(),
        },
        {
            **_seen(),
            "addr": addr,
            "recontype": "UDP_HONEYPOT_HIT",
            "source": "SCANNER",
            "port": 53,
            "infos": {"service_name": "scanner", "service_product": "ZMap"},
        },
    ]


@router.get("/cgi/scans")
async def scans(f: str = "{}", q: str = "") -> list[dict]:
    """The scan result of an address: hostnames and a TLS certificate on port 443."""
    if "skip:0" not in q:
        return []
    addr = _search(f)["arg"]
    start = time.time() - 86400 * 2
    return [
        {
            "addr": addr,
            "starttime": start,
            "endtime": start + 900,
            "state": "up",
            "hostnames": [
                {
                    "type": "PTR",
                    "name": f"scan-{addr.replace('.', '-')}.{fake.domain_name()}",
                    "domains": [],
                }
            ],
            "ports": [
                {
                    "protocol": "tcp",
                    "port": 443,
                    "state_state": "open",
                    "service_name": "https",
                    "scripts": [
                        {
                            "id": "ssl-cert",
                            "output": "Subject: commonName=staticfire.example.com",
                            "ssl-cert": [_certificate()],
                        }
                    ],
                }
            ],
        }
    ]
