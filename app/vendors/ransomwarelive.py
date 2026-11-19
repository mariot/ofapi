"""Ransomware.live: groups and victims (API v2), read by the OpenCTI ransomwarelive
connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.ransomware.live"]
router = APIRouter(prefix="/ransomwarelive", tags=["Ransomware.live"])

SECTORS = ["Technology", "Healthcare", "Manufacturing", "Energy", "Education"]
COUNTRIES = ["US", "FR", "DE", "GB", "XX"]
# MITRE ATT&CK techniques the groups are known for
TACTICS = [
    {"tactic_id": "TA0001", "techniques": [{"technique_id": "T1190"}]},
    {"tactic_id": "TA0040", "techniques": [{"technique_id": "T1486"}]},
]


def _group(name: str) -> dict:
    """A group profile with its leak sites, as listed by /groups."""
    return {
        "name": name,
        "altname": f"{name}-alt",
        "description": fake.paragraph(),
        "url": f"https://www.ransomware.live/group/{name}",
        "locations": [
            {
                "fqdn": f"{fake.lexify('?' * 16)}.onion",
                "slug": f"http://{fake.lexify('?' * 16)}.onion/",
                "title": f"{name} blog",
                "available": True,
            }
        ],
        "ttps": TACTICS,
    }


def _victim(group: str) -> dict:
    """A victim posted on a leak site within the last day."""
    discovered = datetime.now(UTC) - timedelta(hours=fake.random_int(1, 20))
    attack = discovered - timedelta(days=fake.random_int(1, 10))
    domain = fake.domain_name()
    return {
        "victim": domain,
        "group": group,
        "discovered": discovered.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "attackdate": attack.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "activity": fake.random_element(SECTORS),
        "country": fake.random_element(COUNTRIES),
        "domain": domain,
        "description": fake.paragraph(),
        "website": f"https://{domain}",
        "post_url": f"https://www.ransomware.live/id/{fake.sha1()[:16]}",
        "screenshot": f"https://images.ransomware.live/{fake.sha1()[:12]}.png",
    }


@router.get("/v2/groups")
async def groups() -> list[dict]:
    """Every tracked group."""
    return [_group(name) for name in ("lockbit5", "akira", "play")]


@router.get("/v2/recentvictims")
async def recent_victims() -> list[dict]:
    """The victims of the last days, across groups."""
    return [
        _victim(g) for g in ("lockbit5", "akira", "play", "akira", "play", "lockbit5")
    ]


@router.get("/v2/victims/{year}/{month}")
async def victims() -> list[dict]:
    """The victims of a month."""
    return [_victim(g) for g in ("akira", "play")]
