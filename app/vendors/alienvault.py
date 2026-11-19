"""AlienVault OTX: subscribed pulses, read by the OpenCTI alienvault connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["otx.alienvault.com"]
router = APIRouter(prefix="/alienvault", tags=["AlienVault OTX"])

YARA_RULE = """rule {name}
{{
    meta:
        description = "Staticfire fake rule"
    strings:
        $s = "{marker}"
    condition:
        $s
}}"""


def _date() -> str:
    """OTX dates: UTC, microseconds, no timezone."""
    return fake.date_time_between("-2d", "now").strftime("%Y-%m-%dT%H:%M:%S.%f")


def _indicator(indicator_id: int, kind: str, value: str, content: str = "") -> dict:
    return {
        "id": indicator_id,
        "indicator": value,
        "type": kind,
        "created": _date(),
        "content": content,
        "title": "",
        "description": fake.sentence(),
        "expiration": None,
        "is_active": 1,
        "role": None,
        "access_type": "public",
        "access_reason": "",
        "access_groups": [],
        "observations": 0,
    }


def _pulse() -> dict:
    """A pulse with one indicator of each kind the connector maps."""
    marker = fake.lexify("????????")
    indicators = [
        _indicator(1, "IPv4", fake.ipv4_public()),
        _indicator(2, "IPv6", fake.ipv6()),
        _indicator(3, "domain", fake.domain_name()),
        _indicator(4, "hostname", f"c2.{fake.domain_name()}"),
        _indicator(5, "email", fake.email()),
        _indicator(6, "URL", fake.url()),
        _indicator(7, "FileHash-SHA256", fake.sha256()),
        _indicator(8, "FileHash-MD5", fake.md5()),
        _indicator(9, "FileHash-SHA1", fake.sha1()),
        _indicator(10, "CVE", fake.cve_id()),
        _indicator(
            11,
            "YARA",
            f"rule_{marker}",
            YARA_RULE.format(name=f"rule_{marker}", marker=marker),
        ),
    ]
    created = _date()
    return {
        "id": fake.hexify("^" * 24, upper=False),
        "name": f"{fake.malware_family()} campaign {fake.year()}",
        "description": fake.paragraph(),
        "author_name": fake.user_name(),
        "modified": created,
        "created": created,
        "revision": 1,
        "tlp": fake.random_element(["white", "green"]),
        "public": 1,
        "adversary": fake.intrusion_set(),
        "indicators": indicators,
        "tags": [fake.malware_family().lower(), "phishing"],
        "targeted_countries": ["France", "Germany"],
        "malware_families": [fake.malware_family()],
        "attack_ids": ["T1566", "T1059.001"],
        "references": [fake.url()],
        "industries": [fake.industry_sector()],
    }


@router.get("/api/v1/pulses/subscribed")
async def subscribed(limit: int = 50) -> dict:
    """One page of subscribed pulses: ``next`` is null, so the connector stops."""
    return {
        "count": 3,
        "next": None,
        "previous": None,
        "results": [_pulse() for _ in range(3)][:limit],
    }
