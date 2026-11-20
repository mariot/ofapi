"""Silent Push: IP and domain enrichment (OpenCTI silentpush-enrichment connector)."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["app.silentpush.com"]
router = APIRouter(prefix="/silentpush", tags=["Silent Push"])


def _ip_enrichment(ip: str, version: str) -> dict:
    subnet = ".".join(ip.split(".")[:3]) + ".0/24" if version == "ipv4" else ip
    return {
        "ip2asn": [
            {
                "ip": ip,
                "asn": fake.random_int(1000, 64000),
                "asname": fake.company().upper(),
                "asn_reputation_score": fake.random_int(0, 100),
                "sp_risk_score": fake.random_int(40, 100),
                "subnet": subnet,
                "subnet_reputation_score": fake.random_int(0, 100),
                "ip_ptr": fake.domain_name(),
                "ip_location": {
                    "country_name": fake.random_element(["France", "Germany", "Japan"]),
                    "continent_name": "Europe",
                },
                "ip_flags": {
                    "is_proxy": False,
                    "is_sinkhole": False,
                    "is_vpn": True,
                    "is_tor": False,
                },
                "benign_info": {"known_benign": False},
                "sinkhole_info": {"known_sinkhole_ip": False},
                "ip_has_expired_certificate": True,
                "ip_has_open_directory": False,
                "ip_is_dsl_dynamic": False,
                "ip_is_ipfs_node": False,
                "ip_is_tor_exit_node": False,
                "scan_data": {
                    "certificates": [
                        {
                            "serial_number": fake.hexify("^" * 20),
                            "fingerprint_sha1": fake.sha1(),
                            "issuer_organization": "Let's Encrypt",
                            "not_before": "2025-01-10T08:00:00Z",
                            "not_after": "2025-04-10T08:00:00Z",
                        }
                    ],
                    "favicon": [{"favicon_md5": fake.md5(), "is_default": False}],
                },
            }
        ]
    }


@router.get("/api/v2/enrich/ipv4/{ip}/enrich/")
async def enrich_ipv4(ip: str) -> dict:
    """The IPv4 enrichment: ASN, location, PTR, subnet, flags, certificates, favicon."""
    return _ip_enrichment(ip, "ipv4")


@router.get("/api/v2/enrich/ipv6/{ip}/enrich/")
async def enrich_ipv6(ip: str) -> dict:
    return _ip_enrichment(ip, "ipv6")


@router.get("/api/v2/enrich/domain/{domain}/enrich/")
async def enrich_domain(domain: str) -> dict:  # noqa: ARG001
    """The domain enrichment: registrar, name server reputation, flags."""
    return {
        "sp_risk_score": fake.random_int(40, 100),
        "domaininfo": {"registrar": fake.company(), "is_new": False},
        "ns_reputation": {
            "is_expired": False,
            "is_parked": False,
            "is_sinkholed": False,
            "ns_srv_reputation": [
                {"domain": fake.domain_name(), "ns_server": f"ns1.{fake.domain_name()}"}
            ],
        },
        "nschanges": {},
        "domain_urls": {"results_summary": {"is_dynamic_domain": True}},
        "host_flags": [{}],
        "scan_data": {},
    }


@router.get("/api/v2/enrich/domain/{domain}/ip-diversity/")
async def ip_diversity(domain: str) -> dict:
    """PADNS diversity: hosts with their A records and ASN timelines."""
    return {
        "records": [
            {
                "host": f"www.{domain}",
                "asn_timelines": [
                    {
                        "ip": fake.ipv4_public(),
                        "asn": fake.random_int(1000, 64000),
                        "asn_name": fake.company().upper(),
                    }
                    for _ in range(2)
                ],
            }
        ]
    }
