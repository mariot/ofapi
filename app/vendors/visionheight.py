"""VisionHeight: the IP and domain intelligence profiles, read by the OpenCTI
visionheight enrichment connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.visionheight.com"]
router = APIRouter(prefix="/visionheight", tags=["VisionHeight"])

TAGS = ["botnet", "c2", "phishing", "scanner", "malware-hosting"]


@router.get("/ip/{ip}")
async def ip_profile(ip: str) -> dict:
    """A high risk address: anonymizer, services, CVEs and a blocklist history."""
    tags = fake.random_elements(TAGS, length=3, unique=True)
    return {
        "ip": ip,
        "risk": {
            "latest_risk": "HIGH",
            "details": [{"tag": tag, "last_seen": fake.iso8601()} for tag in tags],
        },
        "tags": tags[:2],
        "ip_attributes": {
            "tor_exit_node": True,
            "is_datacenter": True,
            "is_mobile": False,
            "is_satellite": False,
            "icloud_private_relay": False,
        },
        "anonymizer": {
            "is_anonymizer": True,
            "commercial_vpn": {"is_commercial_vpn": True, "name": fake.company()},
        },
        "residential_proxy": {"is_residential_proxy": False},
        "infrastructure": {"asn": fake.random_int(1000, 64000), "isp": fake.company()},
        "location": {"country_code": fake.country_code(), "city": fake.city()},
        "vulnerabilities": {
            "cve": [fake.cve_id(), {"cve": fake.cve_id(), "port": 443}],
        },
        "whois": {
            "registrant_name": fake.company(),
            "abuse_email": fake.company_email(),
        },
        "services": {
            "total": 2,
            "details": [
                {"port": 22, "protocol": "tcp", "product": "OpenSSH"},
                {"port": 443, "protocol": "tcp", "product": "nginx"},
            ],
        },
        "blocklist": {"last_seen": fake.date_time_this_month().isoformat() + "Z"},
    }


@router.get("/domain/{name}")
async def domain_profile(name: str) -> dict:
    """A high risk domain with its A records, certificates and WHOIS history."""
    created = fake.date_time_between("-3y", "-1y")
    return {
        "domain": name,
        "risk": {"score": "HIGH"},
        "tags": fake.random_elements(TAGS, length=2, unique=True),
        "dns": {
            "a_records": [{"ip": fake.ipv4_public()}, {"ip": fake.ipv4_public()}],
        },
        "ssl_certs": [
            {
                "cert_fingerprint_sha1": fake.sha1(),
                "cert_issuer_dn": "/C=US/O=Let's Encrypt/CN=R12",
                "cert_subject_dn": f"/CN={name}",
                "cert_not_before_timestamp": fake.date_time_between(
                    "-60d", "-30d"
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "cert_not_after_timestamp": fake.date_time_between(
                    "+30d", "+60d"
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        ],
        "whois": [
            {
                "registrar": fake.company(),
                "created_at": created.isoformat() + "Z",
                "expires_at": fake.date_time_between("+30d", "+2y").isoformat() + "Z",
                "age_in_days": (fake.date_time_this_year() - created).days,
                "name_servers": [
                    f"ns1.{fake.domain_name()}",
                    f"ns2.{fake.domain_name()}",
                ],
            }
        ],
    }
