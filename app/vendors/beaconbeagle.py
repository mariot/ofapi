"""BeaconBeagle: Cobalt Strike C2 list, details and beacon configs, for the beaconbeagle
connector."""

import time

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["beaconbeagle.com"]
router = APIRouter(prefix="/beaconbeagle", tags=["BeaconBeagle"])

VERSIONS = ["Cobalt Strike 4.8 (Feb 28, 2023)", "Cobalt Strike 4.9.1 (Dec 06, 2023)"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
]
SPAWN_TO = [
    r"%windir%\sysnative\rundll32.exe",
    r"%windir%\syswow64\rundll32.exe",
]


def _epoch(days_ago: float) -> int:
    return int(time.time() - days_ago * 86400)


@router.get("/api/v1/c2")
async def c2_list() -> dict:
    """C2 servers, the most recent first; some have a domain, one has no ASN."""
    items = []
    for index in range(6):
        ip = fake.ipv4_public()
        items.append(
            {
                "ip": ip,
                "key": fake.domain_name() if index % 2 == 0 else ip,
                "Firsttime": _epoch(10 - index),
                "lasttime": _epoch(index / 2),
                "endpoints": fake.random_int(1, 4),
                "asn": fake.random_int(1000, 399999) if index != 5 else None,
                "asn_org": fake.company() if index != 5 else "",
                "country": fake.country_code() if index != 5 else None,
            }
        )
    return {"count": len(items), "items": items}


@router.get("/api/v1/c2/{ip}")
async def c2_details(ip: str) -> dict:
    """The URLs of a C2 and the beacons that were seen using each of its endpoints."""
    endpoints = {}
    for path in ("/jquery-3.3.1.min.js", "/submit.php"):
        endpoints[path] = {
            "seen_in": [
                {
                    "watermark": str(fake.random_int(100000000, 999999999)),
                    "config_hash": fake.sha256(),
                    "beacon_ip": fake.ipv4_public(),
                    "beacon_port": 443,
                    "arch": "x64",
                }
            ]
        }
    return {
        "ip": ip,
        "URLs": [f"https://{ip}{path}" for path in endpoints],
        "Endpoints": endpoints,
    }


@router.get("/api/v1/configs/{config_hash}")
async def config(config_hash: str) -> dict:
    """The decoded Cobalt Strike beacon configuration."""
    return {
        "config_hash": config_hash,
        "config": {
            "version": fake.random_element(VERSIONS),
            "settings": {
                "SETTING_USERAGENT": fake.random_element(USER_AGENTS),
                "SETTING_SPAWNTO_X86": SPAWN_TO[1],
                "SETTING_SPAWNTO_X64": SPAWN_TO[0],
                "SETTING_SPAWNTO": "00000000000000000000000000000000",
            },
        },
    }
