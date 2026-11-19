"""Group-IB Threat Intelligence API (v2): collections polled by sequence number.

Read by the OpenCTI group-ib and group-ib-ti connectors (cyberintegrations and ciaops
libraries): ``sequence_list`` gives the cursor of a day, ``<collection>/updated`` pages
forward from a ``seqUpdate``, an empty page ends the session.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["tap.group-ib.com"]
router = APIRouter(prefix="/group-ib", tags=["Group-IB"])

SEQ_BASE = 1_763_500_000_000_000
PAGE_SIZE = 5
TOTAL = 7
COLLECTIONS = [
    "apt/threat",
    "apt/threat_actor",
    "attacks/ddos",
    "hi/threat",
    "malware/malware",
    "osi/vulnerability",
    "suspicious_ip/open_proxy",
    "suspicious_ip/scanner",
    "suspicious_ip/socks_proxy",
    "suspicious_ip/tor_node",
    "suspicious_ip/vpn",
]
TACTICS = ["initial-access", "execution", "persistence", "command-and-control"]
TECHNIQUES = {
    "T1566": "Phishing",
    "T1059": "Command and Scripting Interpreter",
    "T1071": "Application Layer Protocol",
    "T1486": "Data Encrypted for Impact",
}


def _day(days_ago: int = 0) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%d")


def _stamp(days_ago: int = 0) -> str:
    when = datetime.now(UTC) - timedelta(days=days_ago, minutes=fake.random_int(1, 600))
    return when.isoformat(timespec="seconds")


def _evaluation() -> dict:
    return {
        "tlp": fake.random_element(["white", "green", "amber"]),
        "admiraltyCode": "B2",
        "reliability": 80,
        "credibility": 70,
        "severity": fake.random_element(["green", "orange", "red"]),
    }


def _threat() -> dict:
    """An APT threat report with its indicators, actor, malware, CVEs and techniques."""
    actor = fake.intrusion_set()
    return {
        "id": fake.sha1(),
        "title": f"{actor} targets {fake.industry_sector()}",
        "description": fake.paragraph(nb_sentences=4),
        "shortDescription": fake.sentence(),
        "reportNumber": f"CP-{fake.random_int(2400, 2699)}-{fake.random_int(10, 99)}",
        "expertise": ["espionage"],
        "sectors": [fake.industry_sector()],
        "regions": ["europe", "north-america"],
        "targetedCompany": [fake.company()],
        "targetedPartnersAndClients": [],
        "relatedThreatActors": [fake.intrusion_set()],
        "labels": ["apt", "phishing"],
        "sources": [fake.url()],
        "isTailored": False,
        "isAutogen": False,
        "hasIocs": True,
        "indicators": [
            {
                "id": fake.sha1(),
                "type": "network",
                "params": {
                    "domain": fake.domain_name(),
                    "url": fake.url(),
                    "ipv4": [fake.ipv4_public(), fake.ipv4_public()],
                    "ipv6": [],
                },
            },
            {
                "id": fake.sha1(),
                "type": "file",
                "params": {
                    "hashes": {
                        "md5": fake.md5(),
                        "sha1": fake.sha1(),
                        "sha256": fake.sha256(),
                    },
                    "name": f"{fake.word()}.exe",
                    "size": fake.random_int(10_000, 900_000),
                },
            },
        ],
        "malwareList": [
            {
                "id": fake.sha1(),
                "name": fake.malware_family(),
                "category": ["Backdoor"],
                "platform": ["Windows"],
            }
        ],
        "threatActor": {
            "id": fake.sha1(),
            "name": actor,
            "country": fake.random_element(["CN", "RU", "KP", "IR"]),
        },
        "countries": ["FR", "DE", "US"],
        "cveList": [{"name": fake.cve_id()}],
        "mitreMatrix": [
            {
                "mitreId": technique,
                "attackTactic": fake.random_element(TACTICS),
                "attackType": "technique",
            }
            for technique in fake.random_elements(
                list(TECHNIQUES), length=2, unique=True
            )
        ],
        "evaluation": _evaluation(),
        "dateFirstSeen": _day(20),
        "dateLastSeen": _day(2),
        "datePublished": _day(3),
    }


def _threat_actor() -> dict:
    return {
        "id": fake.sha1(),
        "name": fake.intrusion_set(),
        "country": fake.random_element(["CN", "RU", "KP", "IR"]),
        "aliases": [fake.intrusion_set()],
        "description": fake.paragraph(nb_sentences=3),
        "goals": ["espionage"],
        "roles": ["agent"],
        "isAPT": True,
        "langs": ["en"],
        "spokenOnLangs": ["ru"],
        "stat": {
            "malware": [fake.malware_family(), fake.malware_family()],
            "countries": ["FR", "US"],
            "expertise": ["espionage"],
            "sectors": [fake.industry_sector()],
            "regions": ["europe"],
            "targetedCompany": [],
            "targetedPartnersAndClients": [],
            "relatedThreatActorsCount": 2,
            "allIndicatorsCount": 120,
            "allReportsCount": 14,
            "cve": [fake.cve_id()],
            "dateFirstSeen": _day(400),
            "dateLastSeen": _day(5),
        },
    }


def _vulnerability() -> dict:
    cve = fake.cve_id()
    return {
        "id": cve,
        "title": f"{cve}: {fake.sentence(nb_words=6)}",
        "description": fake.paragraph(nb_sentences=3),
        "href": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "bulletinFamily": "NVD",
        "reporter": "NVD",
        "hasExploit": True,
        "exploitCount": 2,
        "seenInTheWild": False,
        "cvssAttackVector": "NETWORK",
        "cvss": {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "mergedCvss": 9.8,
        "mergedCvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "provider": "NVD",
        "references": [fake.url()],
        "epss": {"epss": 0.42, "percentile": 0.97},
        "cveList": [cve],
        "cpeTable": [
            {
                "type": "a",
                "vendor": "acme",
                "product": fake.word(),
                "version": "1.0",
                "string": "cpe:/a:acme:product:1.0",
                "string23": "cpe:2.3:a:acme:product:1.0:*:*:*:*:*:*:*",
            }
        ],
        "evaluation": _evaluation(),
        "datePublished": _day(10),
        "dateModified": _day(1),
    }


def _suspicious_ip() -> dict:
    return {
        "ipv4": {
            "ip": fake.ipv4_public(),
            "asn": fake.asn(),
            "countryName": "France",
            "countryCode": "FR",
            "provider": fake.company(),
            "region": "Ile-de-France",
        },
        "evaluation": _evaluation(),
        "dateFirstSeen": _stamp(5),
        "dateLastSeen": _stamp(),
        "dateDetected": _stamp(1),
        "source": "Group-IB",
        "categories": ["Tor"],
        "id": fake.sha1(),
    }


def _item(collection: str) -> dict:
    if collection == "apt/threat":
        return _threat()
    if collection == "apt/threat_actor":
        return _threat_actor()
    if collection == "osi/vulnerability":
        return _vulnerability()
    return _suspicious_ip()


@router.get("/api/v2/sequence_list")
async def sequence_list(
    date: str | None = None,  # noqa: ARG001
    collection: str | None = None,
    apply_hunting_rules: str | None = None,  # noqa: ARG001
) -> dict:
    """The sequence number each collection had at the start of a day."""
    names = [collection] if collection else COLLECTIONS
    return {"list": dict.fromkeys(names, SEQ_BASE)}


@router.get("/api/v2/common/matrix/vocab/techniques")
async def mitre_techniques() -> dict:
    """The MITRE ATT&CK techniques vocabulary."""
    return {
        "AttackPattern": {
            f"attack-pattern--{fake.uuid4()}": {
                "mitreId": mitre_id,
                "name": f"[Enterprise->{name}]",
            }
            for mitre_id, name in TECHNIQUES.items()
        }
    }


@router.get("/api/v2/user/granted_collections")
async def granted_collections() -> list[dict]:
    """The collections the account may read."""
    return [{"collection": name, "access": True} for name in COLLECTIONS]


@router.get("/api/v2/{collection:path}/updated")
async def updated(collection: str, seqUpdate: int = SEQ_BASE) -> dict:
    """Events after ``seqUpdate``, five per page; an empty page ends the session."""
    last = SEQ_BASE + TOTAL
    first = seqUpdate + 1
    seqs = range(first, min(first + PAGE_SIZE, last + 1))
    items = [{**_item(collection), "seqUpdate": seq} for seq in seqs]
    return {
        "count": max(last - seqUpdate, 0),
        "seqUpdate": seqs[-1] if items else seqUpdate,
        "items": items,
    }
