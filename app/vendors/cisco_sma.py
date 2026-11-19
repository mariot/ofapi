"""Cisco Secure Malware Analytics (Threat Grid): the daily domain feeds, read by the
OpenCTI cisco-sma connector."""

import re

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["panacea.threatgrid.eu"]
router = APIRouter(prefix="/cisco-sma", tags=["Cisco SMA"])

DESCRIPTIONS = {
    "banking-dns": "Banking Trojan Network Communications",
    "dga-dns": "Domain Generation Algorithm domains",
    "ransomware-dns": "Samples Communicating with Ransomware Servers",
    "rat-dns": "Remote Access Trojan (RAT) Network Communications",
}


@router.get("/api/v3/feeds/{feed}.json")
async def feed(feed: str, api_key: str = "") -> list[dict]:
    """A day of one feed (``<category>_<date>``): domains seen in analysed samples."""
    category = re.sub(r"_\d{4}-\d{2}-\d{2}$", "", feed)
    if not api_key:
        raise HTTPException(401, "missing api_key")
    description = DESCRIPTIONS.get(category, category.replace("-", " ").capitalize())
    return [
        {
            "domain": fake.domain_name(),
            "description": description,
            "sample": fake.sha256(),
            "sample_sha256": fake.sha256(),
            "ts": fake.date_time_this_month().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        for _ in range(5)
    ]
