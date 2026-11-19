"""Fortinet premium threat intelligence feed (fortinet-ti external-import connector).

The feed endpoint answers the link of the day's gzipped STIX bundle, which the same host
serves.
"""

import gzip
import json

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["premiumapi.fortinet.com"]
router = APIRouter(prefix="/fortinet-ti", tags=["Fortinet TI"])

# An address of the bundle of the previous day (the connector only imports what is new)
KNOWN_IP = "198.51.100.10"
WATCHLISTS = ["malware-c2", "phishing", "botnet", "scanner"]


def _indicator(pattern: str, name: str, watchlist: str) -> dict:
    now = fake.date_time_this_month().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{fake.uuid4()}",
        "created": now,
        "modified": now,
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "indicator_types": [watchlist],
    }


@router.get("/v1/cti/feed/stix2")
async def feed_link(cc: str = "all") -> list[dict]:  # noqa: ARG001
    """The link of the feed archive."""
    link = "https://premiumapi.fortinet.com/v1/cti/feed/download/stix2.json.gz"
    return [{"data": link}]


@router.get("/v1/cti/feed/download/stix2.json.gz")
async def feed_archive() -> Response:
    """The STIX bundle of the day: URL and address indicators, plus the infrastructure
    and identity objects the connector drops."""
    indicators = [
        _indicator(f"[ipv4-addr:value = '{KNOWN_IP}']", KNOWN_IP, "malware-c2")
    ]
    for index in range(4):
        ip = fake.ipv4_public()
        indicators.append(
            _indicator(f"[ipv4-addr:value = '{ip}']", ip, WATCHLISTS[index])
        )
        url = fake.url()
        indicators.append(_indicator(f"[url:value = '{url}']", url, WATCHLISTS[index]))
    now = fake.date_time_this_month().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle = {
        "type": "bundle",
        "id": f"bundle--{fake.uuid4()}",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": f"identity--{fake.uuid4()}",
                "created": now,
                "modified": now,
                "name": "FortiGuard",
                "identity_class": "organization",
            },
            {
                "type": "infrastructure",
                "spec_version": "2.1",
                "id": f"infrastructure--{fake.uuid4()}",
                "created": now,
                "modified": now,
                "name": "FortiGuard feed",
            },
            *indicators,
        ],
    }
    return Response(
        content=gzip.compress(json.dumps(bundle).encode()),
        media_type="application/gzip",
    )
