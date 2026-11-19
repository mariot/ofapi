"""CISA: the Known Exploited Vulnerabilities catalog, read by the OpenCTI
cisa-known-exploited-vulnerabilities connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["www.cisa.gov"]
router = APIRouter(prefix="/cisa", tags=["CISA"])

VENDORS = {
    "Microsoft": ["Windows", "Exchange Server", "SharePoint"],
    "Cisco": ["IOS XE", "ASA"],
    "Fortinet": ["FortiOS", "FortiWeb"],
    "Apache": ["Struts", "Tomcat"],
}


def _entry() -> dict:
    vendor = fake.random_element(list(VENDORS))
    product = fake.random_element(VENDORS[vendor])
    added = datetime.now(UTC) - timedelta(days=fake.random_int(1, 30))
    return {
        "cveID": fake.cve_id(),
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": f"{vendor} {product} {fake.word()} vulnerability",
        "dateAdded": added.strftime("%Y-%m-%d"),
        "shortDescription": fake.paragraph(),
        "requiredAction": "Apply mitigations per vendor instructions.",
        "dueDate": (added + timedelta(days=21)).strftime("%Y-%m-%d"),
        "knownRansomwareCampaignUse": fake.random_element(["Known", "Unknown"]),
        "notes": fake.url(),
        "cwes": [f"CWE-{fake.random_int(20, 900)}"],
    }


@router.get("/sites/default/files/feeds/known_exploited_vulnerabilities.json")
async def catalog() -> dict:
    """The KEV catalog: its version (``dateReleased``) and its entries."""
    entries = {e["cveID"]: e for e in (_entry() for _ in range(8))}
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": datetime.now(UTC).strftime("%Y.%m.%d"),
        "dateReleased": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "count": len(entries),
        "vulnerabilities": list(entries.values()),
    }
