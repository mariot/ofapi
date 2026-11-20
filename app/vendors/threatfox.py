"""abuse.ch ThreatFox: the recent IOC export (CSV, behind the auth key path), read by
the OpenCTI threatfox connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["threatfox-api.abuse.ch"]
router = APIRouter(prefix="/threatfox", tags=["ThreatFox"])

HEADER = [
    "################################################################",
    "# abuse.ch ThreatFox IOCs (recent)",
    "################################################################",
    '# "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type", '
    '"fk_malware", "malware_alias", "malware_printable", "last_seen_utc", '
    '"confidence_level", "is_compromised", "reference", "tags", "anonymous", '
    '"reporter"',
]
MALWARE = [
    ("win.cobalt_strike", "Cobalt Strike", "CobaltStrike,Beacon"),
    ("win.lumma", "Lumma Stealer", "LummaC2"),
    ("elf.mirai", "Mirai", "Katana"),
    ("unknown", "Unknown malware", "None"),
]


def _row(kind: str, value: str, threat: str) -> str:
    """One export line: the six IOC types the connector maps, with a malware family
    or none, a reference or none, and tags."""
    family, printable, aliases = fake.random_element(MALWARE)
    seen = datetime.now(UTC) - timedelta(hours=fake.random_int(1, 40))
    last = (
        ""
        if fake.boolean()
        else (seen + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    )
    reference = fake.random_element([fake.url(), "None"])
    tags = ",".join(fake.random_elements(["c2", "stealer", "rat", "loader"], 2, True))
    fields = [
        seen.strftime("%Y-%m-%d %H:%M:%S"),
        str(fake.random_int(1000000, 9999999)),
        value,
        kind,
        threat,
        family,
        aliases,
        printable,
        last,
        str(fake.random_element([50, 75, 100])),
        "False",
        reference,
        tags,
        "0",
        "abuse_ch",
    ]
    return ", ".join(f'"{field}"' for field in fields)


@router.get("/v2/files/exports/{auth_key}/recent.csv")
async def recent(auth_key: str) -> Response:  # noqa: ARG001
    """The recent IOCs as CSV, a comment header then one line per IOC."""
    rows = [
        _row(
            "ip:port", f"{fake.ipv4_public()}:{fake.random_int(80, 9000)}", "botnet_cc"
        ),
        _row("ip:port", f"{fake.ipv4_public()}:443", "botnet_cc"),
        _row("domain", fake.domain_name(), "botnet_cc"),
        _row("url", fake.url(), "payload_delivery"),
        _row("md5_hash", fake.md5(), "payload"),
        _row("sha1_hash", fake.sha1(), "payload"),
        _row("sha256_hash", fake.sha256(), "payload"),
        _row("sha256_hash", fake.sha256(), "payload_delivery"),
    ]
    return Response("\n".join([*HEADER, *rows]) + "\n", media_type="text/csv")
