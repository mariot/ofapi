"""Lamis Network: IP reputation (fraud score, ASN, geolocation, infrastructure flags),
read by the OpenCTI lamis-network enrichment connector."""

import ipaddress

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["api.lamisnetwork.com"]
router = APIRouter(prefix="/lamis-network", tags=["Lamis Network"])


def _reputation(ip: str) -> dict:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid IP address") from None
    return {
        "ip": ip,
        "fraud_score": fake.random_int(80, 100),
        "is_datacenter": True,
        "is_vpn": fake.boolean(),
        "is_tor": False,
        "is_proxy": fake.boolean(),
        "asn": {
            "asn": fake.random_int(1000, 65000),
            "name": fake.company(),
            "rir": fake.random_element(["RIPE", "ARIN", "APNIC"]),
            "type": "hosting",
        },
        "geo": {
            "country_code": "FR",
            "country_name": "France",
            "city": "Paris",
        },
    }


@router.get("/v1/ip/{ip}")
async def ip_reputation(ip: str) -> dict:
    return _reputation(ip)


@router.get("/v1/score")
async def score(ip: str) -> dict:
    return _reputation(ip)
