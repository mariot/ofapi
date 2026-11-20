"""VX Vault: the URL list (text, three line header), read by the vxvault connector."""

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from app.fake import fake

HOSTS = ["vxvault.net"]
router = APIRouter(prefix="/vxvault", tags=["VXVault"])


@router.get("/URL_List.php", response_class=PlainTextResponse)
async def url_list() -> str:
    """Three header lines, then one URL per line inside a <pre> block."""
    urls = [fake.url() + fake.file_name(extension="exe") for _ in range(8)]
    header = ["<pre>", "VX Vault - URL list", "Last update: 2026-11-19", ""]
    return "\n".join(header + urls + ["</pre>"]) + "\n"
