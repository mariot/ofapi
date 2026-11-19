"""Proofpoint Emerging Threats: IP and domain reputation lists (reputation connector)
and the ET Intelligence API (intelligence connector)."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["rules.emergingthreatspro.com", "api.emergingthreats.net"]
router = APIRouter(prefix="/proofpoint-et", tags=["Proofpoint ET"])

CATEGORIES = ["P2P", "VPN", "Spam", "CnC", "Bot", "Phishing", "Scanner", "TorNode"]


def _scores() -> dict[str, int]:
    """Categories of an entity with their reputation score (the API goes up to 127)."""
    categories = fake.random_elements(
        CATEGORIES, length=fake.random_int(1, 3), unique=True
    )
    return {category: fake.random_int(20, 127) for category in categories}


@router.get("/{token}/reputation/iprepdata.json")
async def ip_reputation_list(token: str) -> dict:  # noqa: ARG001
    """Every IP with its categories and scores."""
    return {fake.ipv4_public(): _scores() for _ in range(12)}


@router.get("/{token}/reputation/domainrepdata.json")
async def domain_reputation_list(token: str) -> dict:  # noqa: ARG001
    """Every domain with its categories and scores."""
    return {fake.domain_name(): _scores() for _ in range(12)}


def _ok(response) -> dict:
    return {"success": True, "response": response}


def _seen() -> dict:
    first = fake.date_between(start_date="-20d", end_date="-10d")
    last = fake.date_between(start_date="-9d", end_date="today")
    return {"first_seen": first.isoformat(), "last_seen": last.isoformat()}


@router.get("/v1/{kind}/{value}/reputation")
async def reputation(kind: str, value: str) -> dict:  # noqa: ARG001
    """Reputation of an IP or a domain: one score per category."""
    return _ok(
        [{"category": c, "score": s} for c, s in _scores().items()],
    )


@router.get("/v1/ips/{ip}/domains")
async def ip_domains(ip: str) -> dict:  # noqa: ARG001
    """Domains seen on the IP."""
    return _ok([{"domain": fake.domain_name(), **_seen()} for _ in range(3)])


@router.get("/v1/domains/{domain}/ips")
async def domain_ips(domain: str) -> dict:  # noqa: ARG001
    """IPs the domain resolved to."""
    return _ok([{"ip": fake.ipv4_public(), **_seen()} for _ in range(3)])


@router.get("/v1/{kind}/{value}/samples")
async def samples(kind: str, value: str) -> dict:  # noqa: ARG001
    """Malware samples (MD5) that talked to the IP or domain."""
    return _ok([{"source": fake.md5(), **_seen()} for _ in range(3)])


@router.get("/v1/ips/{ip}/geoloc")
async def geolocation(ip: str) -> dict:
    """Where the IP was last observed."""
    return _ok(
        [
            {
                "ip": ip,
                "country_code": "FR",
                "country": "France",
                "region": "IDF",
                "city": "Paris",
                "latitude": 48.8566,
                "longitude": 2.3522,
            }
        ]
    )


@router.get("/v1/ips/{ip}/asn")
async def asn(ip: str) -> dict:  # noqa: ARG001
    """The autonomous system announcing the IP."""
    return _ok(
        {
            "asn": fake.random_int(1000, 64000),
            "owner": fake.company(),
            "authorizer": "ripencc",
            "country": "FR",
            "registration_date": "2005-03-14",
            "reverse_lookup": None,
        }
    )


@router.get("/v1/samples/{md5}")
async def sample_details(md5: str) -> dict:
    """Details of a submitted sample."""
    return _ok(
        {
            "md5sum": md5,
            "submit_date": fake.date_time_this_year().strftime("%Y-%m-%d %H:%M:%S"),
            "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
            "file_size": fake.random_int(20000, 900000),
            "sha256": fake.sha256(),
        }
    )
