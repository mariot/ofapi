"""GreyNoise: IP context, GNQL feed and CVE details, read by the OpenCTI greynoise,
greynoise-feed and greynoise-vuln connectors (``greynoise`` Python client)."""

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["api.greynoise.io"]
router = APIRouter(prefix="/greynoise", tags=["GreyNoise"])

CLASSIFICATIONS = ("malicious", "suspicious", "benign")
SCROLL_TOKEN = "staticfire-scroll-page-2"


def _timestamp(hours: int = 20) -> str:
    return fake.date_time_between(f"-{hours}h", "now").strftime("%Y-%m-%d %H:%M:%S")


def _business_service() -> dict:
    """The IP is not a known business service (every field is present but empty)."""
    return {
        "found": False,
        "category": "",
        "name": "",
        "description": "",
        "explanation": "",
        "last_updated": "",
        "reference": "",
        "trust_level": "",
        "link": "",
    }


def _tags() -> list[dict]:
    return [
        {
            "id": "3b7b4a1f-6f7a-4a53-a0a6-1e5f0a4e6b21",
            "slug": "mirai",
            "name": "Mirai",
            "category": "worm",
            "intention": "malicious",
            "description": "Mirai is an IoT botnet worm scanning for telnet services.",
            "references": ["https://en.wikipedia.org/wiki/Mirai_(malware)"],
            "recommend_block": True,
            "cves": [],
            "created_at": "2020-01-01",
            "updated_at": "2025-01-01",
        },
        {
            "id": "0f1a8f2c-0a54-4a0e-9a4d-0f7d7e5b8c11",
            "slug": "ssh-bruteforcer",
            "name": "SSH Bruteforcer",
            "category": "activity",
            "intention": "malicious",
            "description": "IP addresses attempting SSH logins with many credentials.",
            "references": [],
            "recommend_block": True,
            "cves": [],
            "created_at": "2020-01-01",
            "updated_at": "2025-01-01",
        },
        {
            "id": "5d8c1d5e-4b43-4c7d-8ad0-2a9a0d6a4f33",
            "slug": "web-scanner",
            "name": "Web Scanner",
            "category": "activity",
            "intention": "suspicious",
            "description": "IP addresses crawling the web for exposed paths.",
            "references": [],
            "recommend_block": False,
            "cves": [],
            "created_at": "2020-01-01",
            "updated_at": "2025-01-01",
        },
        {
            "id": "9a2e3c6b-1f0d-4e55-bd1c-6a7b8c9d0e44",
            "slug": "censys",
            "name": "Censys",
            "category": "actor",
            "intention": "benign",
            "description": "Benign internet-wide scanner.",
            "references": [],
            "recommend_block": False,
            "cves": [],
            "created_at": "2020-01-01",
            "updated_at": "2025-01-01",
        },
    ]


def _scanner(classification: str, found: bool = True) -> dict:
    """The ``internet_scanner_intelligence`` block of the v3 API."""
    first_seen = fake.date_between("-60d", "-5d").isoformat()
    return {
        "first_seen": first_seen,
        "last_seen": fake.date_between("-2d", "today").isoformat(),
        "last_seen_timestamp": _timestamp(),
        "found": found,
        "tags": _tags(),
        "actor": fake.intrusion_set() if classification != "benign" else "Shodan.io",
        "spoofable": False,
        "classification": classification,
        "cves": [fake.cve_id(), fake.cve_id()],
        "bot": True,
        "vpn": True,
        "vpn_service": "NordVPN",
        "tor": False,
        "metadata": {
            "asn": f"AS{fake.random_int(1000, 399999)}",
            "city": fake.city(),
            "country": "France",
            "country_code": "FR",
            "organization": fake.company(),
            "category": "hosting",
            "rdns": fake.domain_name(),
            "rdns_parent": fake.domain_name(),
            "rdns_validated": False,
            "os": "Linux 2.2.x-3.x",
            "region": "Ile-de-France",
            "mobile": False,
            "single_destination": False,
            "destination_countries": ["United States", "Germany"],
            "destination_country_codes": ["US", "DE"],
            "destination_asns": [],
            "destination_cities": [],
            "sensor_count": fake.random_int(1, 200),
            "sensor_hits": fake.random_int(10, 5000),
            "source_country": "France",
            "source_country_code": "FR",
            "source_city": fake.city(),
        },
    }


def _context(ip: str, classification: str = "malicious") -> dict:
    return {
        "ip": ip,
        "business_service_intelligence": _business_service(),
        "internet_scanner_intelligence": _scanner(classification),
    }


@router.get("/v3/ip/{ip}")
async def ip_context(ip: str) -> dict:
    """The full context of one IP: a malicious scanner, not a business service."""
    return _context(ip)


@router.get("/v3/gnql/metadata")
async def gnql_metadata(query: str = "", scroll: str | None = Query(None)) -> dict:
    """GNQL results without the raw scan data, over two scroll pages."""
    classification = next(
        (c for c in CLASSIFICATIONS if f"classification:{c}" in query), "malicious"
    )
    last_page = scroll == SCROLL_TOKEN
    data = [_context(fake.ipv4_public(), classification) for _ in range(5)]
    return {
        "request_metadata": {
            "query": query,
            "scroll": "" if last_page else SCROLL_TOKEN,
            "complete": last_page,
            "message": "",
            "count": 10,
        },
        "data": data,
    }


@router.get("/v1/cve/{cve_id}")
async def cve(cve_id: str) -> dict:
    """The exploitation intelligence of a CVE."""
    return {
        "id": cve_id,
        "details": {
            "vulnerability_name": "Apache Log4j2 Remote Code Execution",
            "vulnerability_description": fake.paragraph(),
            "cve_cvss_score": 10.0,
            "product": "Log4j2",
            "vendor": "Apache",
            "published_to_nvd": True,
        },
        "timeline": {
            "cve_published_date": "2021-12-10T10:15:00Z",
            "cve_last_updated_date": "2025-05-01T10:00:00Z",
            "first_known_published_date": "2021-12-09T12:00:00Z",
            "cisa_kev_date_added": "2021-12-10T00:00:00Z",
        },
        "exploitation_details": {
            "attack_vector": "NETWORK",
            "epss_score": 0.97,
            "exploit_found": True,
            "exploitation_registered_in_kev": True,
        },
        "exploitation_stats": {
            "number_of_available_exploits": 12,
            "number_of_threat_actors_exploiting_vulnerability": 3,
            "number_of_botnets_exploiting_vulnerability": 2,
        },
        "exploitation_activity": {
            "activity_seen": True,
            "benign_ip_count_1d": 4,
            "benign_ip_count_10d": 20,
            "benign_ip_count_30d": 55,
            "threat_ip_count_1d": 120,
            "threat_ip_count_10d": 900,
            "threat_ip_count_30d": 2500,
        },
    }
