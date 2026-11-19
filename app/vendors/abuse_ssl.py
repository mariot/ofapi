"""abuse.ch SSLBL: the botnet C2 IP blacklist (CSV), read by the abuse-ssl connector."""

from fastapi import APIRouter, Response

from app.fake import fake

HOSTS = ["sslbl.abuse.ch"]
router = APIRouter(prefix="/abuse-ssl", tags=["Abuse SSL"])


@router.get("/blacklist/sslipblacklist.csv")
async def ssl_ip_blacklist() -> Response:
    """The CSV blacklist: comment header, then Listingdate,DstIP,DstPort rows."""
    rows = [
        f"{fake.date_time_this_month().strftime('%Y-%m-%d %H:%M:%S')},"
        f"{fake.ipv4_public()},{fake.random_element([443, 447, 8443, 8080])}"
        for _ in range(8)
    ]
    header = [
        "################################################################",
        "# abuse.ch SSLBL SSL IP Blacklist (CSV)                        #",
        f"# Last updated: {fake.date_time_this_month():%Y-%m-%d %H:%M:%S} UTC",
        "################################################################",
        "# Listingdate,DstIP,DstPort",
    ]
    return Response("\n".join([*header, *rows]) + "\n", media_type="text/plain")
