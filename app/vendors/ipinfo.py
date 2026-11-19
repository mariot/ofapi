"""IPinfo: the IP details lookup (business plan shape, with ASN and privacy), read by
the OpenCTI ipinfo enrichment connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["ipinfo.io"]
router = APIRouter(prefix="/ipinfo", tags=["IPinfo"])

CITIES = [
    ("Paris", "FR", "Ile-de-France", "48.8534,2.3488", "Europe/Paris"),
    ("Frankfurt am Main", "DE", "Hesse", "50.1155,8.6842", "Europe/Berlin"),
    ("Amsterdam", "NL", "North Holland", "52.3740,4.8897", "Europe/Amsterdam"),
    ("Ashburn", "US", "Virginia", "39.0437,-77.4875", "America/New_York"),
]


@router.get("/{ip}")
@router.get("/{ip}/json")
@router.get("/{ip}/json/")
async def details(ip: str) -> dict:
    """The location, organization, ASN and privacy flags of an address."""
    city, country, region, loc, timezone = fake.random_element(CITIES)
    asn = f"AS{fake.random_int(1000, 399999)}"
    organization = fake.company().split(",")[0]
    domain = fake.domain_name()
    return {
        "ip": ip,
        "hostname": f"host-{ip.replace('.', '-')}.{domain}",
        "city": city,
        "region": region,
        "country": country,
        "loc": loc,
        "postal": fake.postcode(),
        "timezone": timezone,
        "org": f"{asn} {organization}",
        "asn": {
            "asn": asn,
            "name": organization,
            "domain": domain,
            "route": ".".join(ip.split(".")[:2]) + ".0.0/16",
            "type": "hosting",
        },
        "company": {"name": organization, "domain": domain, "type": "hosting"},
        "privacy": {
            "vpn": True,
            "proxy": False,
            "tor": False,
            "relay": False,
            "hosting": True,
            "service": "NordVPN",
        },
        "abuse": {
            "address": fake.address().replace("\n", ", "),
            "country": country,
            "email": f"abuse@{domain}",
            "name": f"{organization} Abuse",
            "network": ".".join(ip.split(".")[:2]) + ".0.0/16",
            "phone": fake.phone_number(),
        },
    }
