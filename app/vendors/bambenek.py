"""Bambenek Consulting: the C2 and DGA feeds, read by the OpenCTI bambenek connector."""

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import PlainTextResponse

from app.fake import fake

HOSTS = ["faf.bambenekconsulting.com"]
router = APIRouter(prefix="/bambenek", tags=["Bambenek"])

FAMILIES = ["cryptolocker", "dyre", "emotet", "gozi", "pykspa", "qakbot", "tinba"]
HEADER = """\
####################################################################
# Master Feed of known, active and non-sinkholed C&Cs domain names
# Feed generated at: 2026-11-19 12:00
# (C) Bambenek Consulting. Licensed for staticfire tests
####################################################################
"""


def _reference(family: str) -> str:
    return f"http://osint.bambenekconsulting.com/manual/{family}.txt"


def _feed(kind: str, count: int = 6) -> str:
    """Comment lines, then one CSV record per line: value,tag,fetch date,reference."""
    lines = []
    for _ in range(count):
        family = fake.random_element(FAMILIES)
        value = fake.domain_name() if kind == "domain" else fake.ipv4_public()
        what = "Domain" if kind == "domain" else "IP"
        when = fake.date_time_between("-3d", "now").strftime("%Y-%m-%d %H:%M")
        lines.append(f"{value},{what} used by {family} C&C,{when},{_reference(family)}")
    return HEADER + "\n".join(lines) + "\n"


def _auth(authorization: str | None) -> None:
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(401, "Unauthorized", {"WWW-Authenticate": "Basic"})


@router.get("/feeds/dga/{name}", response_class=PlainTextResponse)
async def dga_feed(name: str, authorization: str | None = Header(None)) -> str:
    """A feed of domains (DGA or C2 domain master lists) or of C2 addresses."""
    _auth(authorization)
    return _feed("ip" if "ipmasterlist" in name else "domain")
