"""Pages and PDF reports external references can point to, fetched by the
import-external-reference enrichment connector (a headless browser for web pages, a
plain download for PDFs)."""

from fastapi import APIRouter, Response

from app.fake import fake
from app.vendors.fixtures import _pdf, _report_text

HOSTS = ["blog.staticfire.test", "reports.staticfire.test"]
router = APIRouter(prefix="/import-external-reference", tags=["External references"])


def _page(slug: str) -> str:
    group = fake.intrusion_set()
    sector = fake.industry_sector()
    domain = fake.domain_name()
    rows = "".join(
        f"<tr><td>{kind}</td><td>{value}</td></tr>"
        for kind, value in [
            ("Domain", domain),
            ("IPv4", fake.ipv4_public()),
            ("SHA-256", fake.sha256()),
        ]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{group} targets the {sector} sector</title>
<link rel="canonical" href="/blog/{slug}">
</head>
<body>
<div id="cookie-banner"><p>We use cookies.</p><button>Accept</button></div>
<article>
<h1>{group} targets the {sector} sector</h1>
<p>{fake.paragraph(nb_sentences=5)}</p>
<h2>Infrastructure</h2>
<p>The operators relied on {fake.malware_family()} and {domain}.</p>
<table><thead><tr><th>Type</th><th>Indicator</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Mitigations</h2>
<ul><li>{fake.sentence()}</li><li>{fake.sentence()}</li></ul>
</article>
</body>
</html>"""


@router.get("/blog/{slug}")
async def web_page(slug: str) -> Response:
    """A threat research article."""
    return Response(_page(slug), media_type="text/html")


@router.get("/reports/{name}.pdf")
async def pdf_report(name: str) -> Response:
    """A threat report as a PDF (its text names the requested report)."""
    text = f"{name.replace('-', ' ')}\n\n{_report_text()}"
    return Response(_pdf(text), media_type="application/pdf")
