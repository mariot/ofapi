"""Stairwell: file, hostname, IP and ASN intelligence (v1 and v2 APIs), read by the
OpenCTI stairwell-import (MalEval listing) and stairwell (enrichment) connectors."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["app.stairwell.com"]
router = APIRouter(prefix="/stairwell", tags=["Stairwell"])

BUCKETS = [
    "PROBABILITY_VERY_HIGH",
    "PROBABILITY_HIGH",
    "PROBABILITY_MEDIUM",
    "PROBABILITY_LOW",
]
SEVERITIES = ["SEVERITY_HIGH", "SEVERITY_MEDIUM", "SEVERITY_LOW"]


def _time(max_age_hours: float = 12) -> str:
    """An RFC 3339 timestamp with nanoseconds, within the last hours."""
    moment = datetime.now(UTC) - timedelta(
        minutes=fake.random_int(5, int(max_age_hours * 60))
    )
    return (
        moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{fake.random_int(0, 999999999):09d}Z"
    )


def _ipv6() -> str:
    """A global unicast address (2000::/3), which the connector keeps."""
    groups = ":".join(f"{fake.random_int(0, 65535):x}" for _ in range(7))
    return f"2a0{fake.random_int(0, 9)}:{groups}"


def _network_indicators() -> dict:
    return {
        "ipAddresses": [fake.ipv4_public() for _ in range(2)],
        "hostnames": [fake.domain_name() for _ in range(2)],
        "urls": [fake.url()],
    }


def _object(sha256: str, bucket: str | None = None) -> dict:
    """An object's metadata, as the listing and the single lookup answer it."""
    return {
        "name": f"objects/{sha256}/metadata",
        "sha256": sha256,
        "sha1": fake.sha1(),
        "md5": fake.md5(),
        "size": str(fake.random_int(20_000, 3_000_000)),
        "mimeType": "application/x-dosexec",
        "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
        "shannonEntropy": round(
            fake.pyfloat(min_value=5, max_value=7.9, right_digits=4), 4
        ),
        "imphash": fake.md5(),
        "tlsh": fake.tlsh(),
        "stairwellFirstSeenTime": _time(),
        "uploadTime": _time(),
        "malEval": {
            "malicious": True,
            "probabilityBucket": bucket or fake.random_element(BUCKETS),
            "severity": fake.random_element(SEVERITIES),
            "labels": [fake.malware_family()],
        },
        "networkIndicators": _network_indicators(),
    }


@router.get("/v1/objects/metadata")
async def list_objects(pageToken: str = "") -> dict:
    """Two pages of malicious files: three above the connector's minimum bucket and one
    under it on the first, two above it on the second."""
    if pageToken:
        buckets = ["PROBABILITY_VERY_HIGH", "PROBABILITY_HIGH"]
        return {
            "objectMetadatas": [_object(fake.sha256(), b) for b in buckets],
            "nextPageToken": "",
        }
    buckets = [
        "PROBABILITY_VERY_HIGH",
        "PROBABILITY_HIGH",
        "PROBABILITY_HIGH",
        "PROBABILITY_LOW",
    ]
    return {
        "objectMetadatas": [_object(fake.sha256(), b) for b in buckets],
        "nextPageToken": "stairwell-page-2",
    }


@router.get("/v1/objects/{sha256}/metadata")
async def object_metadata(sha256: str) -> dict:
    """The metadata of one file: scoring, YARA matches, tags, lineage and signature."""
    metadata = _object(sha256, "PROBABILITY_HIGH")
    metadata.update(
        {
            "name": "invoice_viewer.exe",
            "yaraRuleMatches": [
                f"Win_{fake.malware_family().replace(' ', '_')}_Generic",
                "Suspicious_Packer",
            ],
            "tags": [
                {"name": "campaign", "value": fake.intrusion_set().replace(" ", "-")},
                {"name": "reviewed"},
            ],
            "prevalences": [
                {"environment": "global", "prevalence": 0.0123},
                {"environment": "tenant", "prevalence": 0.002},
            ],
            "variants": {"total": "4"},
            "environments": ["environments/" + fake.uuid4()],
            "relationships": {
                "parents": [{"sha256": fake.sha256()}],
                "children": [{"sha256": fake.sha256()}],
            },
            "objectSignature": {
                "pkcs7VerificationResult": "PKCS7_VERIFICATION_RESULT_OK",
                "x509Certificates": [
                    {
                        "subject": f"CN={fake.company()}",
                        "issuer": "CN=Example Code Signing CA",
                        "earliestValidTime": _time(24 * 300),
                        "latestValidTime": _time(24 * 10),
                        "signature": fake.sha1(),
                    }
                ],
            },
        }
    )
    return metadata


@router.get("/v1/objects/{sha256}:summarize")
async def summarize() -> dict:
    """The AI File Triage write-up of a file."""
    return {
        "tldr": f"{fake.malware_family()} dropper that beacons to a remote server.",
        "summary": "\n\n".join(fake.paragraph() for _ in range(2)),
    }


@router.get("/v202112/variants/{sha256}")
async def variants() -> dict:
    """Files similar to the one asked, most similar first."""
    return {
        "family": fake.malware_family(),
        "variantCount": 4,
        "variants": [
            {
                "similarity": round(0.95 - 0.1 * rank, 2),
                "sha256": fake.sha256(),
                "sha1": fake.sha1(),
                "md5": fake.md5(),
            }
            for rank in range(4)
        ],
    }


@router.get("/v1/objects/{sha256}/sightings")
async def sightings() -> dict:
    """The events of three assets seeing the file, on one page."""
    assets = [fake.uuid4() for _ in range(3)]
    return {
        "objectSightings": [
            {
                "asset": f"assets/{asset}",
                "assetName": fake.hostname(),
                "environment": "environments/staticfire",
                "sightingTime": _time(48),
                "filepath": "C:\\Users\\Public\\",
                "filename": "invoice_viewer.exe",
            }
            for asset in assets
            for _ in range(2)
        ],
        "nextPageToken": "",
    }


@router.get("/v1/hostnames/{hostname}/metadata")
async def hostname_metadata(hostname: str) -> dict:
    """The v1 hostname record (its DNS history is also in the v2 resolutions)."""
    return {"name": f"hostnames/{hostname}", "hostname": hostname}


@router.get("/v2/hostnames/{hostname}")
async def hostname(hostname: str) -> dict:
    return {"hostname": hostname, "etldPlusOne": hostname}


@router.get("/v2/hostnames/{hostname}/whitelist-status")
async def whitelist_status(hostname: str) -> dict:
    return {"hostname": hostname, "whitelisted": False}


@router.get("/v2/hostnames/{hostname}/resolutions")
async def resolutions(hostname: str) -> dict:
    """The DNS answers seen for the hostname: addresses, mail exchangers, aliases."""
    answers = [
        ("A", fake.ipv4_public()),
        ("A", fake.ipv4_public()),
        ("AAAA", _ipv6()),
        ("MX", f"10 mx.{fake.domain_name()}"),
        ("CNAME", f"edge.{fake.domain_name()}"),
        ("NS", f"ns1.{fake.domain_name()}"),
        ("TXT", "v=spf1 -all"),
    ]
    return {
        "hostname": hostname,
        "etldPlusOne": hostname,
        "resolutions": [
            {
                "recordType": kind,
                "answer": answer,
                "firstSeen": _time(24 * 60),
                "lastSeen": _time(24),
                "observationCount": str(fake.random_int(1, 500)),
            }
            for kind, answer in answers
        ],
    }


@router.get("/v2/ips/{ip}")
async def ip(ip: str) -> dict:
    return {
        "ipAddress": ip,
        "asns": [fake.random_int(1000, 60000)],
        "geoLocation": {
            "country": "NL",
            "countryName": "Netherlands",
            "city": "Amsterdam",
            "region": "North Holland",
        },
        "cloudProvider": "AWS",
        "isDatacenter": True,
        "isVpn": False,
        "subnetInfo": {"cidr": fake.ipv4_public(), "prefixLength": 24},
    }


@router.get("/v2/ips/{ip}/whois")
async def ip_whois(ip: str) -> dict:
    return {
        "ipAddress": ip,
        "record": {
            "arinOrg": {"name": fake.company()},
            "whoisString": f"NetRange: {ip}/24\nOrgName: {fake.company()}\nCountry: NL",
        },
    }


@router.get("/v2/ips/{ip}/hostnames")
async def ip_hostnames() -> dict:
    return {"hostnames": [{"canonicalHostname": fake.domain_name()} for _ in range(3)]}


@router.get("/v2/asns/{asn}/whois")
async def asn_whois(asn: str) -> dict:
    return {
        "asn": asn,
        "records": [
            {
                "arinAsn": {
                    "name": fake.company(),
                    "registrationDate": "2012-03-14",
                },
                "whoisString": f"ASNumber: {asn}\nASName: {fake.company()}",
            }
        ],
    }
