"""ENISA EUVD: the vulnerability search (enisa-euvd import connector)."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["euvdservices.enisa.europa.eu"]
router = APIRouter(prefix="/enisa-euvd", tags=["ENISA-EUVD"])

CVSS = {
    "3.1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "4.0": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "2.0": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
}


def euvd_date(moment: datetime) -> str:
    """The API's date format, e.g. "Sep 23, 2026, 12:31:13 PM" (UTC, no zone)."""
    return moment.strftime("%b %d, %Y, %I:%M:%S %p")


def vulnerability(updated: datetime) -> dict:
    version = fake.random_element(list(CVSS))
    cve = fake.cve_id()
    vendor = fake.company()
    return {
        "id": f"EUVD-{updated.year}-{fake.random_int(10000, 99999)}",
        "enisaUuid": fake.uuid4(),
        "description": fake.sentence(nb_words=18),
        "datePublished": euvd_date(updated - timedelta(days=fake.random_int(1, 5))),
        "dateUpdated": euvd_date(updated),
        "baseScore": round(fake.random.uniform(4.0, 9.9), 1),
        "baseScoreVersion": version,
        "baseScoreVector": CVSS[version],
        "references": f"{fake.url()}\nhttps://nvd.nist.gov/vuln/detail/{cve}\n",
        "aliases": f"{cve}\nGHSA-{fake.bothify('????-????-????').lower()}\n",
        "assigner": fake.random_element(["mitre", "github_M", "Fortra", "VulDB"]),
        "epss": round(fake.random.uniform(0.01, 90), 2),
        "enisaIdProduct": [
            {
                "id": fake.uuid4(),
                "product": {
                    "name": fake.word().title() + " Server",
                    "vendor": {"name": vendor},
                },
                "product_version": f"{fake.random_int(1, 5)}.{fake.random_int(0, 9)}.0",
            }
        ],
        "enisaIdVendor": [{"id": fake.uuid4(), "vendor": {"name": vendor}}],
    }


@router.get("/api/search")
async def search(page: int = 0) -> dict:
    """One page of recent vulnerabilities, last updated first; later pages are empty."""
    if page:
        return {"items": [], "total": 8}
    now = datetime.now(UTC).replace(microsecond=0)
    items = [vulnerability(now - timedelta(days=i, hours=i)) for i in range(8)]
    return {"items": items, "total": len(items)}
