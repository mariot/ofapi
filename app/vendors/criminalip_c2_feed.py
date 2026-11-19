"""Criminal IP C2 Daily Feed: one CSV per day, read by criminalip-c2-daily-feed.

The connector reads ``CRIMINALIP_CSV_URL`` (the raw GitHub folder of the feed): it is
pointed at its own host so that it does not compete for ``raw.githubusercontent.com``.
"""

import csv
import io

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["c2-daily-feed.criminalip.staticfire.test"]
router = APIRouter(prefix="/criminalip-c2-feed", tags=["Criminal IP C2 Feed"])

COUNTRIES = ["US", "DE", "CN", "FR", "RU"]
C2_FAMILIES = ["Cobalt Strike", "Sliver", "Metasploit", "Havoc"]


@router.get("/{day}.csv")
async def daily_feed(day: str) -> Response:
    """The feed of a day: address, country, targeted C2 and open ports."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["IP", "Country", "Target C2", "OpenPorts", "Last Seen"])
    for _ in range(8):
        writer.writerow(
            [
                fake.ipv4_public(),
                fake.random_element(COUNTRIES),
                f"C2_{fake.random_element(C2_FAMILIES)}",
                fake.random_element([80, 443, 8080, 50050]),
                day,
            ]
        )
    return Response(content=out.getvalue(), media_type="text/csv")
