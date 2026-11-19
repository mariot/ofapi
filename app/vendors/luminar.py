"""Cognyte Luminar: the OAuth token, the TAXII 2.1 collections and their objects (IOCs,
leaked records, cyberfeeds), read by the OpenCTI luminar connector."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["www.cyberluminar.com"]
router = APIRouter(prefix="/luminar", tags=["Luminar"])

COLLECTIONS = {
    "iocs": str(uuid.uuid5(uuid.NAMESPACE_DNS, "luminar-iocs")),
    "leakedrecords": str(uuid.uuid5(uuid.NAMESPACE_DNS, "luminar-leakedrecords")),
    "cyberfeeds": str(uuid.uuid5(uuid.NAMESPACE_DNS, "luminar-cyberfeeds")),
}
EXTENSION = "extension-definition--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, "luminar"))

# collection id -> the objects of the last first-page request, served page by page
DATASETS: dict[str, list[dict]] = {}
PAGE_SIZE = 12


def _stamp() -> str:
    moment = datetime.now(UTC) - timedelta(hours=fake.random_int(2, 72))
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "000Z"


def _sdo(kind: str, **properties) -> dict:
    created = _stamp()
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        **properties,
    }


def _score() -> dict:
    return {
        EXTENSION: {
            "extension_type": "property-extension",
            "luminar_threat_score": fake.random_int(40, 100),
        }
    }


def _relationship(source: dict, target: dict, kind: str) -> dict:
    return _sdo(
        "relationship",
        relationship_type=kind,
        source_ref=source["id"],
        target_ref=target["id"],
    )


def _indicator(pattern: str, name: str) -> dict:
    created = _stamp()
    return _sdo(
        "indicator",
        name=name,
        pattern=pattern,
        pattern_type="stix",
        valid_from=created,
        valid_until=(datetime.now(UTC) + timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        ),
        indicator_types=["malicious-activity"],
    )


def _iocs() -> list[dict]:
    """Malware and a threat actor with their indicators, then the relationships: the
    answer spans two pages."""
    malware = _sdo(
        "malware", name=fake.malware_family(), is_family=True, extensions=_score()
    )
    actor = _sdo(
        "threat-actor",
        name=fake.intrusion_set(),
        threat_actor_types=["crime-syndicate"],
        extensions=_score(),
    )
    objects = [malware, actor]
    relationships = []
    for parent in (malware, actor):
        indicators = [
            _indicator(
                f"[ipv4-addr:value = '{fake.ipv4_public()}']",
                "Known Malicious IPs - Cognyte Luminar",
            ),
            _indicator(
                f"[domain-name:value = '{fake.domain_name()}']", "Malicious domain"
            ),
            _indicator(f"[url:value = '{fake.url()}']", "Malicious URL"),
            _indicator(
                f"[file:hashes.'SHA-256' = '{fake.sha256()}']", "Malicious file hash"
            ),
        ]
        objects += indicators
        relationships += [_relationship(i, parent, "indicates") for i in indicators]
    return objects + relationships


def _leaked() -> list[dict]:
    incident = _sdo(
        "incident",
        name=f"Leaked credentials for {fake.domain_name()}",
        extensions=_score(),
    )
    stealer = _sdo("malware", name=fake.malware_family(), is_family=True)
    accounts = [
        {
            "type": "user-account",
            "spec_version": "2.1",
            "id": f"user-account--{uuid.uuid4()}",
            "user_id": fake.email(),
            "account_login": fake.email(),
            "credential": fake.password(),
            "extensions": {
                EXTENSION: {
                    "extension_type": "property-extension",
                    "monitoring_plan_terms": [fake.domain_name()],
                    "source": "stealer logs",
                    "url": fake.url(),
                    "credential_is_fresh": True,
                }
            },
        }
        for _ in range(2)
    ]
    children = [stealer, *accounts]
    return [
        incident,
        *children,
        *[_relationship(c, incident, "related-to") for c in children],
    ]


def _cyberfeeds() -> list[dict]:
    actor = _sdo(
        "threat-actor", name=fake.intrusion_set(), description=fake.paragraph()
    )
    malware = _sdo("malware", name=fake.malware_family(), is_family=True)
    vulnerability = _sdo("vulnerability", name=fake.cve_id())
    country = fake.country()
    location = _sdo("location", name=country, country=fake.country_code())
    indicator = _indicator(
        f"[domain-name:value = '{fake.domain_name()}']", "Cyberfeed domain"
    )
    report = _sdo(
        "report",
        name=f"Luminar cyber feed: {fake.catch_phrase()}",
        published=_stamp(),
        report_types=["threat-report"],
        object_refs=[
            actor["id"],
            malware["id"],
            vulnerability["id"],
            location["id"],
            indicator["id"],
        ],
    )
    relationships = [
        _relationship(actor, malware, "uses"),
        _relationship(malware, vulnerability, "targets"),
        _relationship(actor, location, "located-at"),
    ]
    return [actor, malware, vulnerability, location, indicator, *relationships, report]


GENERATORS = {
    COLLECTIONS["iocs"]: _iocs,
    COLLECTIONS["leakedrecords"]: _leaked,
    COLLECTIONS["cyberfeeds"]: _cyberfeeds,
}


@router.post("/externalApi/v2/realm/{account_id}/token")
async def token() -> dict:
    return {
        "access_token": fake.sha256(),
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "externalAPI/stix.readonly",
    }


@router.get("/externalApi/taxii/collections/")
async def collections() -> dict:
    return {
        "collections": [
            {
                "id": collection_id,
                "alias": alias,
                "title": alias,
                "can_read": True,
                "can_write": False,
                "media_types": ["application/stix+json;version=2.1"],
            }
            for alias, collection_id in COLLECTIONS.items()
        ]
    }


@router.get("/externalApi/taxii/collections/{collection_id}/objects/")
async def objects(collection_id: str, next: str | None = None) -> dict:
    """A page of PAGE_SIZE objects; ``next`` is the offset of the following one."""
    if next is None or collection_id not in DATASETS:
        DATASETS[collection_id] = GENERATORS[collection_id]()
    dataset = DATASETS[collection_id]
    start = int(next) if next else 0
    end = start + PAGE_SIZE
    page = {"more": end < len(dataset), "objects": dataset[start:end]}
    if page["more"]:
        page["next"] = str(end)
    return page
