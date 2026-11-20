"""Spur: anonymous and residential infrastructure feeds, gzipped JSON lines of IP
Context records (spur connector)."""

import gzip
import json

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["feeds.spur.us"]
router = APIRouter(prefix="/spur", tags=["Spur"])

RISKS = [
    "CALLBACK_PROXY",
    "GEO_MISMATCH",
    "LOGIN_BRUTE_FORCE",
    "TUNNEL",
    "WEB_SCRAPING",
]


def _record(anonymous: bool) -> dict:
    asn = fake.random_int(1000, 64000)
    record = {
        "ip": fake.ipv4_public() if fake.boolean(80) else fake.ipv6(),
        "as": {"number": asn, "organization": fake.company()},
        "organization": fake.company(),
        "infrastructure": "DATACENTER" if anonymous else "MOBILE",
        "location": {
            "city": fake.city(),
            "state": fake.state(),
            "country": fake.country_code(),
        },
        "services": fake.random_elements(
            ["IPSEC", "OPENVPN", "SSH"], length=2, unique=True
        ),
        "client": {
            "types": ["MOBILE", "DESKTOP"],
            "count": fake.random_int(1, 500),
            "countries": fake.random_int(1, 20),
        },
    }
    if anonymous:
        record["risks"] = fake.random_elements(RISKS, length=2, unique=True)
        record["tunnels"] = [
            {
                "type": "VPN",
                "operator": fake.random_element(["NORDVPN", "PROTON_VPN", "MULLVAD"]),
                "anonymous": True,
            }
        ]
    return record


def _feed(anonymous: bool) -> Response:
    lines = "\n".join(json.dumps(_record(anonymous)) for _ in range(8))
    return Response(gzip.compress(lines.encode()), media_type="application/gzip")


@router.get("/v2/anonymous/feed.json.gz")
async def anonymous_feed() -> Response:
    """Addresses of VPNs, proxies and other anonymous infrastructure, with risks."""
    return _feed(True)


@router.get("/v2/residential/feed.json.gz")
async def residential_feed() -> Response:
    """Residential exit nodes: no risks or tunnels."""
    return _feed(False)
