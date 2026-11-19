"""IPGeolocation.io: the v3 IP geolocation lookup, read by the OpenCTI ipgeolocation
enrichment connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.ipgeolocation.io"]
router = APIRouter(prefix="/ipgeolocation", tags=["IPGeolocation"])

PLACES = [
    ("US", "USA", "United States", "North America", "NA", "Dallas", "Texas", "US-TX"),
    ("DE", "DEU", "Germany", "Europe", "EU", "Frankfurt", "Hesse", "DE-HE"),
    ("FR", "FRA", "France", "Europe", "EU", "Paris", "Ile-de-France", "FR-IDF"),
    ("NL", "NLD", "Netherlands", "Europe", "EU", "Amsterdam", "North Holland", "NL-NH"),
]


@router.get("/v3/ipgeo")
async def ipgeo(ip: str, include: str = "") -> dict:
    """The location, ASN, company, network and time zone of an address; the security
    and abuse modules and the reverse DNS name when asked with ``include``."""
    code2, code3, country, continent, continent_code, city, state, state_code = (
        fake.random_element(PLACES)
    )
    organization = fake.company().split(",")[0]
    domain = fake.domain_name()
    route = ".".join(ip.split(".")[:3]) + ".0/24"
    response = {
        "ip": ip,
        "location": {
            "continent_code": continent_code,
            "continent_name": continent,
            "country_code2": code2,
            "country_code3": code3,
            "country_name": country,
            "country_name_official": country,
            "country_capital": city,
            "state_prov": state,
            "state_code": state_code,
            "district": city,
            "city": city,
            "locality": city,
            "accuracy_radius": "20",
            "confidence": "high",
            "zipcode": fake.postcode(),
            "latitude": str(fake.latitude()),
            "longitude": str(fake.longitude()),
            "is_eu": continent_code == "EU",
            "geoname_id": str(fake.random_int(1000000, 9999999)),
            "country_flag": f"https://ipgeolocation.io/static/flags/{code2.lower()}_64.png",
            "country_emoji": "",
        },
        "country_metadata": {"calling_code": "+1", "tld": f".{code2.lower()}"},
        "network": {"connection_type": "", "route": route, "is_anycast": False},
        "asn": {
            "as_number": f"AS{fake.random_int(1000, 399999)}",
            "organization": organization,
            "country": code2,
            "type": "HOSTING",
            "domain": domain,
            "date_allocated": "2012-04-18",
            "rir": "RIPE",
        },
        "company": {"name": organization, "type": "hosting", "domain": domain},
        "time_zone": {
            "name": "Europe/Paris",
            "offset": 1,
            "offset_with_dst": 2,
            "current_time": "2026-06-01 12:00:00.000+0200",
            "is_dst": True,
            "dst_savings": 1,
            "dst_exists": True,
            "dst_start": "2026-03-29T01:00:00",
            "dst_end": "2026-10-25T01:00:00",
        },
        "currency": {"code": "EUR", "name": "Euro", "symbol": "EUR"},
    }
    modules = include.split(",")
    if "hostname" in modules:
        response["hostname"] = f"host-{ip.replace('.', '-')}.{domain}"
    if "security" in modules:
        response["security"] = {
            "threat_score": fake.random_int(60, 95),
            "is_tor": False,
            "is_proxy": True,
            "proxy_provider_names": ["Zyte Proxy"],
            "proxy_confidence_score": 80,
            "proxy_last_seen": "2026-05-12",
            "is_residential_proxy": False,
            "is_vpn": True,
            "vpn_provider_names": ["Nord VPN"],
            "vpn_confidence_score": 80,
            "vpn_last_seen": "2026-05-19",
            "is_relay": False,
            "relay_provider_name": "",
            "is_anonymous": True,
            "is_known_attacker": True,
            "is_bot": False,
            "is_spam": False,
            "is_cloud_provider": True,
            "cloud_provider_name": organization,
        }
    if "abuse" in modules:
        response["abuse"] = {
            "route": route,
            "country": code2,
            "name": f"{organization} Abuse",
            "organization": organization,
            "kind": "group",
            "address": fake.address().replace("\n", ", "),
            "emails": [f"abuse@{domain}"],
            "phone_numbers": [fake.phone_number()],
        }
    return response
