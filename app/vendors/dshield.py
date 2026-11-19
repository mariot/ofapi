"""DShield (SANS ISC): the recommended block list, read by the dshield connector."""

from datetime import UTC, datetime

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["feeds.dshield.org", "isc.sans.edu"]
router = APIRouter(prefix="/dshield", tags=["DShield"])


@router.get("/block.txt")
async def block_list() -> Response:
    """The top 20 attacking /24 networks: comment header, then tab separated rows."""
    now = datetime.now(UTC).strftime("%a %b %d %H:%M:%S %Y UTC")
    lines = [
        "#",
        "#  DShield.org Recommended Block List",
        "#  (c) 2007-2026 DShield.org, some rights reserved. ",
        f"#  updated {now}",
        "#",
        "# Start\tEnd\tNetmask\tAttacks\tName\tCountry\tEmail",
    ]
    for _ in range(8):
        network = ".".join(fake.ipv4_public().split(".")[:3])
        lines.append(
            "\t".join(
                [
                    f"{network}.0",
                    f"{network}.255",
                    "24",
                    str(fake.random_int(500, 90000)),
                    fake.company().replace(",", "").upper()[:30],
                    fake.country_code(),
                    fake.email(),
                ]
            )
        )
    return Response("\n".join(lines) + "\n", media_type="text/plain")
