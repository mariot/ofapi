"""NVD CPE dictionary API 2.0, read by the OpenCTI cpe connector.

The connector is pointed at its own host (``CPE_BASE_URL``) so that it does not compete
for ``services.nvd.nist.gov`` with the connectors reading the NVD CVE API.
"""

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["cpe-api.nvd.staticfire.test"]
router = APIRouter(prefix="/nvd-cpe", tags=["NVD CPE"])

PAGE_SIZE = 6
TOTAL = 10

# (part, vendor, product, version, deprecated, language)
_PRODUCTS = [
    ("a", "apache", "http_server", "2.4.58", False, "*"),
    ("a", "microsoft", "edge_chromium", "119.0.2151.44", False, "*"),
    ("a", "mozilla", "firefox", "120.0", False, "en-US"),
    ("a", "openssl", "openssl", "3.0.12", False, "*"),
    ("a", "oracle", "jdk", "17.0.9", True, "*"),
    ("h", "cisco", "asa_5506-x", "-", False, "*"),
    ("a", "vlc", "vlc_media_player", "3.0.20", False, "fr"),
    ("o", "linux", "linux_kernel", "6.6.4", False, "*"),
    ("a", "python", "python", "3.12.1", False, "*"),
    ("a", "gnu", "bash", "5.2", False, "*"),
]


def _product(part: str, vendor: str, product: str, version: str, *rest) -> dict:
    deprecated, language = rest
    name = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:{language}:*:*:*:*"
    title = f"{vendor.title()} {product.replace('_', ' ').title()} {version}"
    return {
        "cpe": {
            "deprecated": deprecated,
            "cpeName": name,
            "cpeNameId": fake.uuid4().upper(),
            "created": "2024-03-01T12:00:00.000",
            "lastModified": "2026-11-10T09:30:00.000",
            "titles": [{"title": title, "lang": "en"}],
            "refs": [{"ref": f"https://{vendor}.example.org/", "type": "Vendor"}],
        }
    }


@router.get("/rest/json/cpes/2.0")
async def cpes(start_index: int = Query(0, alias="startIndex")) -> dict:
    """Pages of PAGE_SIZE products out of TOTAL; resultsPerPage is the page count."""
    page = _PRODUCTS[start_index : start_index + PAGE_SIZE]
    return {
        "resultsPerPage": len(page),
        "startIndex": start_index,
        "totalResults": TOTAL,
        "format": "NVD_CPE",
        "version": "2.0",
        "timestamp": "2026-11-19T10:00:00.000",
        "products": [_product(*p) for p in page],
    }
