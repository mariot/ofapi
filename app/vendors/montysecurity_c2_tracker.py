"""MontySecurity C2-Tracker: the GitHub directory page listing the "<malware> IPs.txt"
files and the IP lists themselves (served as the GitHub repository
montysecurity/C2-Tracker), read by the OpenCTI montysecurity-c2-tracker connector.

The directory page is a GitHub HTML page the connector scrapes: it is served on an own
host, the connector's list URL setting pointing at it.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app.fake import fake
from app.vendors.github import Repo

HOSTS = ["c2-tracker.staticfire.test"]
router = APIRouter(prefix="/montysecurity-c2-tracker", tags=["C2-Tracker"])

MALWARE = ["Cobalt Strike C2", "Sliver C2", "Brute Ratel C4", "Havoc C2"]


def _lists() -> dict[str, bytes]:
    files = {}
    for name in MALWARE:
        ips = [fake.ipv4_public() for _ in range(4)] + [fake.ipv6()]
        files[f"data/{name} IPs.txt"] = ("\n".join(ips) + "\n").encode()
    return files


def _repo() -> Repo:
    return Repo(_lists(), branch="main", description="Live Hunting Of Control Servers")


GITHUB_REPOS = {"montysecurity/C2-Tracker": _repo}


@router.get("/montysecurity/C2-Tracker/tree/main/data")
async def data_directory() -> HTMLResponse:
    """The directory page: its embedded payload names every file of ``data``."""
    items = ",".join(
        f'{{"name":"{name} IPs.txt","path":"data/{name} IPs.txt","contentType":"file"}}'
        for name in MALWARE
    )
    page = (
        "<!DOCTYPE html><html><head><title>C2-Tracker/data at main</title></head>"
        '<body><script type="application/json" data-target="react-app.embeddedData">'
        f'{{"payload":{{"tree":{{"items":[{items}]}}}}}}'
        "</script></body></html>"
    )
    return HTMLResponse(page)
