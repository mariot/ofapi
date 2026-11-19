"""crt.sh: the certificate search (``?q=<domain>&output=json``), read by
the OpenCTI crtsh connector."""

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["crt.sh"]
router = APIRouter(prefix="/crtsh", tags=["crt.sh"])

ISSUERS = [
    "C=US, O=Let's Encrypt, CN=R11",
    "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
    "C=BE, O=GlobalSign nv-sa, CN=GlobalSign Atlas R3 DV TLS CA 2024 Q1",
]


@router.get("/")
async def search(q: str = Query("")) -> list[dict]:
    """The certificates of the searched domain, newest id first."""
    domain = q.removeprefix("%.")
    first_id = fake.random_int(10**10, 10**10 + 10**6)
    entries = []
    for index in range(6):
        not_before = fake.date_time_between(start_date="-300d", end_date="-5d")
        names = [f"{fake.word()}.{domain}", f"www.{domain}"]
        if index == 0:
            names.append(f"*.{domain}")
        if index == 1:
            names.append(f"admin@{domain}")
        entries.append(
            {
                "issuer_ca_id": fake.random_int(1000, 99999),
                "issuer_name": fake.random_element(ISSUERS),
                "common_name": domain,
                "name_value": "\n".join(names),
                "id": first_id - index * 1000,
                "entry_timestamp": not_before.isoformat(timespec="milliseconds"),
                "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%S"),
                "not_after": fake.date_time_between(
                    start_date="+20d", end_date="+90d"
                ).strftime("%Y-%m-%dT%H:%M:%S"),
                "serial_number": fake.sha1(),
                "result_count": 2,
            }
        )
    return entries
