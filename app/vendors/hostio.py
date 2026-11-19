"""Host.io: the full domain report and the reverse IP to domains lookup, read by the
OpenCTI hostio enrichment connector (the IP details come from the IPinfo fake)."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["host.io"]
router = APIRouter(prefix="/hostio", tags=["Host.io"])

TOTAL_DOMAINS = 7


@router.get("/api/full/{domain}")
async def full(domain: str) -> dict:
    """DNS records, the addresses with their IPinfo data, web and related sections."""
    addresses = [fake.ipv4_public(), fake.ipv4_public()]
    return {
        "domain": domain,
        "dns": {
            "a": addresses,
            "aaaa": [fake.ipv6()],
            "mx": [f"mail.{domain}"],
            "ns": [f"ns1.{domain}", f"ns2.{domain}"],
            "cname": [f"edge.{fake.domain_name()}"],
        },
        "ipinfo": {
            address: {
                "city": "Paris",
                "region": "Ile-de-France",
                "country": "FR",
                "loc": "48.8534,2.3488",
                "org": f"AS{fake.random_int(1000, 399999)} {fake.company()}",
                "timezone": "Europe/Paris",
            }
            for address in addresses
        },
        "web": {
            "domain": domain,
            "url": f"https://{domain}/",
            "title": fake.sentence(nb_words=4),
            "server": "nginx",
            "ip": addresses[0],
            "date": fake.date_time_this_month().isoformat() + "Z",
            "tld": domain.rsplit(".", 1)[-1],
        },
        "related": {
            "ip": {"count": TOTAL_DOMAINS, "ips": addresses},
            "backlinks": {"count": fake.random_int(1, 50)},
            "redirects": {"count": 0},
        },
    }


@router.get("/api/domains/ip/{ip}")
async def domains_of_ip(ip: str, limit: int = 5, page: int = 0) -> dict:
    """The domains hosted on an address, ``limit`` per page (zero-based ``page``)."""
    count = max(min(limit, TOTAL_DOMAINS - page * limit), 0)
    return {
        "ip": ip,
        "total": TOTAL_DOMAINS,
        "page": page,
        "domains": [fake.domain_name() for _ in range(count)],
    }
