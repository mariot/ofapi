"""Silobreaker: lists, document search, enrichments, PDFs (silobreaker connector)."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query, Response

from app.fake import fake

HOSTS = ["api.silobreaker.com"]
router = APIRouter(prefix="/silobreaker", tags=["Silobreaker"])

LIST_NAMES = {
    "138809": "Infostealers and Keyloggers",
    "96910": "RAT Malware",
    "36592": "Ransomware",
    "55112": "APTs",
    "50774": "Threat Publications",
}


def _entities() -> list[dict]:
    values = {
        "ThreatActor": fake.intrusion_set(),
        "Malware": fake.malware_family(),
        "MitreTechnique": fake.mitre_attack_technique()["name"],
        "Person": fake.name(),
        "Country": fake.country(),
        "City": fake.city(),
        "Company": fake.company(),
        "Organization": fake.company(),
        "GovernmentBody": f"Ministry of {fake.word().title()}",
        "Vulnerability": fake.cve_id(),
        "Domain": fake.domain_name(),
        "IPv4": fake.ipv4_public(),
        "Subdomain": f"mail.{fake.domain_name()}",
        "Email": fake.email(),
    }
    return [
        {"Type": kind, "Description": value, "Id": fake.random_int(1, 10**6)}
        for kind, value in values.items()
    ]


def _document(kind: str, with_pdf: bool = False) -> dict:
    published = datetime.now(UTC) - timedelta(days=fake.random_int(1, 2))
    doc_id = fake.random_int(10**6, 10**7)
    html = f"<p>{fake.paragraph()}</p><h2>Indicators</h2><p>{fake.domain_name()}</p>"
    item = {
        "Id": doc_id,
        "Type": kind,
        "Description": fake.sentence(nb_words=6).rstrip("."),
        "PublicationDate": published.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Publisher": fake.company(),
        "SilobreakerUrl": f"https://reports.silobreaker.com/doc/{doc_id}",
        "SourceUrl": fake.url(),
        "Extras": {
            "DocumentTeasers": {"HtmlSnippet": html},
            "DocumentFullText": {"HtmlFullText": html + f"<p>{fake.paragraph()}</p>"},
            "RelatedEntities": {"Items": _entities()},
        },
    }
    if with_pdf:
        item["FileName"] = f"report-{doc_id}.pdf"
        item["DownloadUrl"] = (
            f"https://api.silobreaker.com/v2/documents/{doc_id}/download"
        )
    return item


@router.get("/v2/lists/{list_id}")
async def get_list(list_id: str) -> dict:
    """A list; its Description is the name used in the document search query."""
    number = list_id.split("_", 1)[-1]
    name = LIST_NAMES.get(number, f"List {number}")
    return {"Id": list_id, "Description": name, "Type": "List"}


@router.get("/v2/documents/search")
async def search(
    page_number: int = Query(0, alias="pageNumber"),
) -> dict:
    """Documents of a list; a single page of results, later pages are empty."""
    if page_number > 0:
        return {"Items": [], "ResultCount": 0, "TotalCount": 3}
    items = [
        _document("Report", with_pdf=True),
        _document("News"),
        _document("Blog"),
    ]
    return {"Items": items, "ResultCount": len(items), "TotalCount": len(items)}


@router.get("/v2/documents/{doc_id}/download")
async def download() -> Response:
    return Response(
        content=b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n",
        media_type="application/pdf",
    )


@router.get("/v2/enrichments")
async def enrichments() -> dict:
    """Risk modules of an indicator entity."""
    return {
        "modules": [
            {
                "name": "Recorded Future",
                "risk": {"riskScore": fake.random_int(20, 99), "riskLevel": "High"},
            }
        ]
    }
