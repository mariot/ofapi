"""ShadowTrackr: the IP information API (``shadowtrackr.com``), read by the OpenCTI
shadowtrackr enrichment connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["shadowtrackr.com"]
router = APIRouter(prefix="/shadowtrackr", tags=["ShadowTrackr"])


@router.get("/api/v3/ip_info")
async def ip_info(ip: str) -> dict:  # noqa: ARG001
    """An address of a CDN, which the connector labels and describes."""
    return {
        "false_positive_estimate": fake.random_int(70, 99),
        "bogon": False,
        "cdn": True,
        "cdn_provider": "Cloudflare",
        "cloud": False,
        "cloud_provider": "",
        "vpn": False,
        "tor": False,
        "public_dns": False,
    }
