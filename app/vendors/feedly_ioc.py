"""Feedly: the enterprise IoC stream, a STIX 2.1 bundle of article reports with their
indicators and context, paged by a ``link`` header (feedly import connector).

Kept apart from the older ``/feedly`` fake of ``app/main.py``, whose bundle has no
threat actors, vulnerabilities nor relationships.
"""

import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Query, Response

from app.fake import fake

HOSTS = ["feedly.com", "cloud.feedly.com"]
router = APIRouter(prefix="/feedly-ioc", tags=["Feedly"])

PAGES = 2
REPORTS_PER_PAGE = 2
SOURCES = ["The Hacker News", "BleepingComputer", "Mandiant Blog", "Unit 42"]


def stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def sdo(kind: str, created: str, **fields) -> dict:
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        **fields,
    }


def relationship(kind: str, source: dict, target: dict, created: str) -> dict:
    return sdo(
        "relationship",
        created,
        relationship_type=kind,
        source_ref=source["id"],
        target_ref=target["id"],
    )


def article_report(published: datetime) -> list[dict]:
    """One report with the objects of the article it summarises."""
    created = stamp(published)
    sha256, md5 = fake.sha256(), fake.md5()
    ip, domain, url = fake.ipv4_public(), fake.domain_name(), fake.url()
    technique = fake.mitre_attack_technique()
    malware = sdo(
        "malware",
        created,
        name=fake.malware_family(),
        is_family=True,
        malware_types=["remote-access-trojan"],
    )
    actor = sdo(
        "threat-actor",
        created,
        name=f"{fake.intrusion_set()} {fake.random_int(100, 999)}",
        threat_actor_types=["nation-state"],
        aliases=[f"{fake.word().title()} {fake.random_int(10, 99)}"],
    )
    vulnerability = sdo(
        "vulnerability",
        created,
        name=fake.cve_id(),
        external_references=[{"source_name": "cve", "external_id": fake.cve_id()}],
    )
    attack_pattern = sdo(
        "attack-pattern",
        created,
        name=technique["name"],
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": technique["external_id"],
                "url": technique["url"],
            }
        ],
    )
    location = sdo("location", created, name="Ukraine", country="UA")
    indicators = [
        sdo(
            "indicator",
            created,
            name=pattern,
            pattern=pattern,
            pattern_type="stix",
            valid_from=created,
        )
        for pattern in (
            f"[file:hashes.'SHA-256' = '{sha256}']",
            f"[file:hashes.MD5 = '{md5}']",
            f"[ipv4-addr:value = '{ip}']",
            f"[domain-name:value = '{domain}']",
            f"[url:value = '{url}']",
        )
    ]
    observables = [
        {"type": "ipv4-addr", "spec_version": "2.1", "id": f"ipv4-addr--{uuid.uuid4()}"}
        | {"value": value}
        for value in (ip, f"{fake.ipv4_public()}:{fake.random_int(1024, 65000)}")
    ]
    relations = [
        relationship("indicates", indicators[0], malware, created),
        relationship("indicates", indicators[2], malware, created),
        relationship("uses", actor, malware, created),
        relationship("uses", malware, attack_pattern, created),
        relationship("targets", actor, location, created),
        relationship("located-at", actor, location, created),
        relationship("exploits", malware, vulnerability, created),
    ]
    context = [malware, actor, vulnerability, attack_pattern, location]
    objects = [*context, *indicators, *observables, *relations]
    source = fake.random_element(SOURCES)
    report = sdo(
        "report",
        created,
        name=fake.sentence(nb_words=8),
        description=(
            f"## {fake.sentence()}\n\n{fake.paragraph()}\n\n"
            f"* {fake.sentence()}\n* {fake.sentence()}"
        ),
        published=created,
        report_types=["threat-report"],
        object_refs=[o["id"] for o in objects],
        external_references=[
            {
                "source_name": "Feedly AI",
                "url": f"https://feedly.com/i/entry/{uuid.uuid4().hex}",
            },
            {"source_name": source, "url": fake.url()},
        ],
    )
    return [report, *objects]


@router.get("/v3/enterprise/ioc")
async def enterprise_ioc(
    response: Response,
    stream_id: str = Query(alias="streamId"),
    continuation: str | None = None,
) -> dict:
    """A page of the stream's reports, newest first; ``link`` gives the next page."""
    page = int(continuation) if continuation and continuation.isdigit() else 1
    if page < PAGES:
        query = urlencode({"streamId": stream_id, "continuation": page + 1})
        response.headers["link"] = f'<{query}>; rel="next"'
    now = datetime.now(UTC)
    objects = []
    for index in range(REPORTS_PER_PAGE):
        age = timedelta(days=page, hours=index * 5)
        objects += article_report(now - age)
    return {"id": f"bundle--{uuid.uuid4()}", "type": "bundle", "objects": objects}
