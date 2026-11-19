"""Infoblox: the TIDE threat feed (infoblox import connector) and the Threat Defense
custom lists (infoblox-threat-defense stream connector), both on the CSP portal."""

from datetime import timedelta

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["csp.infoblox.com", "csp.eu.infoblox.com"]
router = APIRouter(prefix="/infoblox", tags=["Infoblox"])

# https://docs.infoblox.com/space/BloxOneThreatDefense (TIDE data API)
PROPERTIES = {
    "Phishing": ["Phishing_Generic", "Phishing_Credential"],
    "MalwareC2": ["MalwareC2_Generic", "MalwareC2_Beacon"],
    "MalwareDownload": ["MalwareDownload_Generic"],
    "Bot": ["Bot_Generic"],
    "Suspicious": ["Suspicious_Generic"],
}


def _threat(threat_type: str) -> dict:
    detected = fake.date_time_between(start_date="-3d", end_date="-1d")
    threat_class = fake.random_element(list(PROPERTIES))
    threat = {
        "id": fake.uuid4(),
        "type": threat_type,
        "profile": "IID",
        "property": fake.random_element(PROPERTIES[threat_class]),
        "class": threat_class,
        "threat_level": fake.random_element([30, 60, 80, 100]),
        "confidence": fake.random_element([60, 80, 100]),
        "detected": detected.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "received": (detected + timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        ),
        "imported": (detected + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "expiration": (detected + timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        ),
        "dga": False,
        "up": True,
        "batch_id": fake.uuid4(),
        "extended": {"notes": fake.sentence(), "cyberint": ""},
    }
    domain = fake.domain_name()
    if threat_type == "IP":
        threat["ip"] = fake.ipv4_public()
    elif threat_type == "URL":
        threat["url"] = f"{domain}/{fake.slug()}"
        threat["domain"] = domain
    else:
        threat["host"] = domain
        threat["domain"] = domain
    return threat


@router.get("/tide/api/data/threats")
async def threats(type: str = "host", rlimit: int = 10000) -> dict:
    """A few indicators of the type asked (ip, url or host), as TIDE lists them."""
    kind = {"ip": "IP", "url": "URL", "host": "HOST"}.get(type, "HOST")
    found = [_threat(kind) for _ in range(min(rlimit, 5))]
    return {"threat": found, "record_count": len(found), "status": "Ok"}


# custom list id -> list, kept so that a PUT shows in the next GET
LISTS: dict[str, dict] = {}


def _named_list(list_id: str) -> dict:
    if list_id not in LISTS:
        LISTS[list_id] = {
            "id": int(list_id) if list_id.isdigit() else fake.random_int(1000, 99999),
            "name": "OpenCTI custom list",
            "type": "custom_list",
            "description": "Domains pushed from OpenCTI",
            "confidence_level": "HIGH",
            "threat_level": "HIGH",
            "tags": None,
            "item_count": 1,
            "items_described": [
                {
                    "item": fake.domain_name(),
                    "description": "",
                    "created_time": "2025-01-01T00:00:00Z",
                }
            ],
            "created_time": "2025-01-01T00:00:00Z",
            "updated_time": "2025-01-01T00:00:00Z",
        }
    return LISTS[list_id]


@router.get("/api/atcfw/v1/named_lists")
async def named_lists() -> dict:
    return {"results": [_named_list("1")]}


@router.get("/api/atcfw/v1/named_lists/{list_id}")
async def named_list(list_id: str) -> dict:
    return {"results": _named_list(list_id)}


@router.put("/api/atcfw/v1/named_lists/{list_id}", status_code=201)
async def update_named_list(list_id: str, request: Request) -> dict:
    """Replaces the items of the list, answering as the Threat Defense API does."""
    body = await request.json()
    current = _named_list(list_id)
    current["items_described"] = body.get("items_described", [])
    current["item_count"] = len(current["items_described"])
    return {"results": current}
