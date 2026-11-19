"""Malpedia: families, YARA rules, samples and actors (REST API with an API token),
read by the OpenCTI malpedia connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["malpedia.caad.fkie.fraunhofer.de"]
router = APIRouter(prefix="/malpedia", tags=["Malpedia"])

COUNTRIES = ["RU", "CN", "KP", "IR"]
VICTIMS = ["United States", "France", "Germany", "Japan", "Acme Corporation"]


def _slug(name: str) -> str:
    return name.lower().replace(" ", "_")


@router.get("/api/check/apikey")
async def check_apikey() -> dict:
    return {"detail": "Valid token"}


@router.get("/api/get/version")
async def version() -> dict:
    return {"version": fake.random_int(3000, 4000)}


@router.get("/api/get/families")
async def families() -> dict:
    """Family entries keyed by Malpedia name; ``attribution`` lists actor names."""
    entries = {}
    for _ in range(5):
        name = fake.malware_family()
        slug = _slug(name).replace(".", "_")
        entries[f"win.{slug}"] = {
            "common_name": name,
            "description": fake.sentence(nb_words=14),
            "alt_names": [fake.malware_family() for _ in range(2)],
            "attribution": [fake.intrusion_set() for _ in range(2)],
            "updated": fake.date_between("-30d", "today").isoformat(),
            "library_entries": [],
            "notes": [],
            "sources": [],
            "urls": [fake.url(), fake.url()],
            "uuid": fake.uuid4(),
        }
    return entries


@router.get("/api/get/yara/{family}")
async def yara(family: str) -> dict:
    """YARA rules by TLP level, each a rule name with its source."""
    rules = {}
    for level in ("tlp_white", "tlp_green"):
        rule = f"{_slug(family).replace('.', '_')}_{level}_{fake.random_int(1, 999)}"
        rules[level] = {
            rule: (
                f'rule {rule} {{ meta: author = "Malpedia" strings: '
                f'$s = "{fake.word()}" condition: $s }}'
            )
        }
    return rules


@router.get("/api/list/samples/{family}")
async def samples(family: str) -> list[dict]:  # noqa: ARG001
    return [
        {
            "sha256": fake.sha256(),
            "md5": fake.md5(),
            "status": "dll",
            "version": "2024-05-01",
        }
        for _ in range(3)
    ]


@router.get("/api/get/actor/{actor}")
async def actor(actor: str) -> dict:
    """An actor with its aliases, country of origin and suspected victims."""
    name = actor.replace("_", " ").title()
    return {
        "value": name,
        "description": fake.sentence(nb_words=16),
        "meta": {
            "synonyms": [fake.intrusion_set()],
            "country": fake.random_element(COUNTRIES),
            "cfr-type-of-incident": ["Espionage", "Sabotage"],
            "cfr-suspected-victims": fake.random_elements(
                VICTIMS, length=3, unique=True
            ),
            "refs": [fake.url()],
        },
    }
