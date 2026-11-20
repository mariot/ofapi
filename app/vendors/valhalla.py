"""Valhalla (Nextron Systems): the API status and the YARA rule set (JSON, form POST
with an ``apikey`` field), read by the OpenCTI valhalla connector through the
valhallaAPI client. The ATT&CK dataset its tags map to comes from the GitHub module."""

import hashlib
from datetime import datetime, timedelta

from fastapi import APIRouter, Form

from app.fake import fake

HOSTS = ["valhalla.nextron-systems.com"]
router = APIRouter(prefix="/valhalla", tags=["Valhalla"])

VERSION = 90210
# ATT&CK technique and group ids of the GitHub module's dataset, and other tags
ATTACK_TAGS = ["T1059", "T1566", "T1003", "G0016"]
OTHER_TAGS = ["APT", "RAT", "EXE", "FILE", "WEBSHELL", "MAL", "CVE_2024_3094"]


def _rule(index: int) -> dict:
    """A rule with a PE module requirement for every other one, tagged with an ATT&CK
    id and a family or topic."""
    name = f"{fake.malware_family()}_{fake.bothify('??##').upper()}".replace(" ", "_")
    name = name.replace("-", "_")
    uses_pe = index % 2 == 0
    condition = "uint16(0) == 0x5a4d and pe.is_dll() and " if uses_pe else ""
    content = (
        f"rule {name} {{\n"
        "   meta:\n"
        f'      description = "Detects {name} samples"\n'
        '      author = "Nextron Systems"\n'
        "   strings:\n"
        f'      $s1 = "{fake.word()}_{fake.word()}" ascii wide\n'
        f'      $x1 = "{fake.sha1()[:16]}" ascii\n'
        "   condition:\n"
        f"      {condition}filesize < 800KB and 1 of them\n"
        "}\n"
    )
    when = datetime.utcnow() - timedelta(days=3 + index)
    return {
        "author": "Nextron Systems",
        "content": content,
        "date": when.strftime("%Y-%m-%d %H:%M:%S"),
        "description": f"Detects {name} samples",
        "minimum_yara": "2.2.0" if not uses_pe else "3.2.0",
        "name": name,
        "reference": "-" if index == 1 else f"https://www.{fake.domain_name()}/blog",
        "required_modules": ["pe"] if uses_pe else [],
        "rule_hash": hashlib.sha256(content.encode()).hexdigest(),
        "score": fake.random_element([60, 75, 80, 90]),
        "tags": [
            ATTACK_TAGS[index % len(ATTACK_TAGS)],
            OTHER_TAGS[index % len(OTHER_TAGS)],
        ],
    }


@router.post("/api/v1/status")
async def status(apikey: str = Form("")) -> dict:  # noqa: ARG001
    return {"error": "", "num_rules": 6, "status": "ok", "version": VERSION}


@router.post("/api/v1/get")
async def get(apikey: str = Form(""), format: str = Form("json")) -> dict:  # noqa: A002, ARG001
    """The rule set, newest rules first."""
    return {
        "api_version": "1.0",
        "copyright": "Copyright by Nextron Systems GmbH, all rights reserved.",
        "customer": "staticfire",
        "date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "legal_note": "Valhalla rules are licensed for internal use only.",
        "title": "Valhalla YARA Rule Set",
        "rules": [_rule(i) for i in range(6)],
    }
