"""FIRST EPSS: the daily scores file of epss.cyentia.com (first-epss-bulk connector) and
the per-CVE API of api.first.org (first-epss enrichment connector)."""

import csv
import gzip
import io
from datetime import UTC, datetime

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["epss.cyentia.com", "api.first.org"]
router = APIRouter(prefix="/first-epss", tags=["FIRST-EPSS"])

# Scored in every file: the test creates these vulnerabilities in OpenCTI beforehand
KNOWN_CVES = [
    "CVE-2021-44228",
    "CVE-2023-4863",
    "CVE-2024-3400",
    "CVE-2023-34362",
]


def score() -> dict[str, str]:
    epss = fake.random.uniform(0.0004, 0.97)
    return {
        "epss": f"{epss:.5f}",
        "percentile": f"{min(0.99999, epss**0.3):.5f}",
    }


@router.get("/epss_scores-{day}.csv.gz")
async def scores_file(day: str) -> Response:
    """The scores of every CVE, after a comment line naming the model and score date."""
    out = io.StringIO()
    out.write(f"#model_version:v2025.03.14,score_date:{day}T12:55:00Z\n")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["cve", "epss", "percentile"])
    for cve in [*KNOWN_CVES, *(fake.cve_id() for _ in range(200))]:
        writer.writerow([cve, *score().values()])
    return Response(
        content=gzip.compress(out.getvalue().encode()),
        media_type="application/gzip",
    )


@router.get("/data/v1/epss")
async def epss(cve: str = "") -> dict:
    """The EPSS records of the CVEs asked (comma separated), as strings."""
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    data = [
        {"cve": name.strip(), **score(), "date": day}
        for name in cve.split(",")
        if name.strip()
    ]
    return {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "access": "public",
        "total": len(data),
        "offset": 0,
        "limit": 100,
        "data": data,
    }
