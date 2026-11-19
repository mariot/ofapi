"""VirusTotal / Google Threat Intelligence API v3 (``www.virustotal.com/api/v3``).

Read by the OpenCTI google-ti-feeds connector (collections: reports, threat actors,
malware families, software toolkits, vulnerabilities, campaigns, and their IOCs) and
the google-dtm connector (Digital Threat Monitoring alerts, ``/dtm/alerts``).

The collection and IOC objects are recorded GTI payloads (``virustotal_samples.json``,
placeholder data) whose dates are moved to the last hours on every answer. Other
VirusTotal connectors can add their routes here."""

import copy
import json
import re
import time
from pathlib import Path

from fastapi import APIRouter, Query, Response

from app.fake import fake
from app.vendors.fixtures import _pdf, _report_text

HOSTS = ["www.virustotal.com"]
router = APIRouter(prefix="/virustotal", tags=["VirusTotal"])

SAMPLES = json.loads(Path(__file__).with_name("virustotal_samples.json").read_text())

COLLECTION_TYPES = {
    "report": "report",
    "threat-actor": "threat_actor",
    "malware-family": "malware_family",
    "software-toolkit": "malware_family",
    "vulnerability": "vulnerability",
    "campaign": "campaign",
}
# the relationship name of the API -> the sample (and collection type) it holds
RELATIONSHIPS = {
    "reports": "report",
    "threat_actors": "threat_actor",
    "malware_families": "malware_family",
    "software_toolkits": "software_toolkit",
    "vulnerabilities": "vulnerability",
    "campaigns": "campaign",
    "attack_techniques": "attack_technique",
    "domains": "domain",
    "files": "file",
    "urls": "url",
    "ip_addresses": "ip_address",
}
IOC_ENDPOINTS = {
    "domains": "domain",
    "files": "file",
    "urls": "url",
    "ip_addresses": "ip_address",
    "attack_techniques": "attack_technique",
}


SAMPLES["report"]["attributes"]["counters"].update(
    domains=1, files=1, iocs=4, ip_addresses=1, urls=1
)


def _toolkit() -> dict:
    """A software toolkit: a malware family sample under its own id and type."""
    toolkit = copy.deepcopy(SAMPLES["malware_family"])
    toolkit["id"] = "malware--0b9a3f5e-3c1d-5b6e-8f2a-7d4c1e9a6b52"
    toolkit["links"]["self"] = toolkit["links"]["self"].rsplit("/", 1)[0] + (
        "/" + toolkit["id"]
    )
    toolkit["attributes"]["name"] = "STATICTOOL"
    toolkit["attributes"]["collection_type"] = "software-toolkit"
    return toolkit


def _second_report() -> dict:
    report = copy.deepcopy(SAMPLES["report"])
    report["id"] = "report--25-20031999"
    report["links"]["self"] = (
        "https://www.virustotal.com/api/v3/collections/" + (report["id"])
    )
    report["attributes"]["report_id"] = "25-20031999"
    report["attributes"]["name"] = f"Threat Activity Alert: {fake.intrusion_set()}"
    report["attributes"]["report_type"] = "Threat Activity Alert"
    return report


def _store() -> dict[str, dict]:
    objects = [
        SAMPLES["report"],
        _second_report(),
        SAMPLES["threat_actor"],
        SAMPLES["malware_family"],
        _toolkit(),
        SAMPLES["vulnerability"],
        SAMPLES["campaign"],
    ]
    return {obj["id"]: obj for obj in objects}


COLLECTIONS = _store()


def _fresh(obj: dict) -> dict:
    """A copy of the object with its modification dates in the last hours."""
    obj = copy.deepcopy(obj)
    now = int(time.time())
    attributes = obj["attributes"]
    if "creation_date" in attributes:
        attributes["creation_date"] = now - 7200
    if "last_modification_date" in attributes:
        attributes["last_modification_date"] = now - 3600
    return obj


def _of_type(collection_type: str) -> list[dict]:
    return [
        _fresh(obj)
        for obj in COLLECTIONS.values()
        if obj["attributes"]["collection_type"] == collection_type
    ]


def _page(objects: list[dict], path: str) -> dict:
    return {
        "data": objects,
        "meta": {"count": len(objects)},
        "links": {"self": f"https://www.virustotal.com/api/v3{path}"},
    }


def _related(relationship: str) -> list[dict]:
    sample = RELATIONSHIPS[relationship]
    if sample in IOC_ENDPOINTS.values() or sample == "attack_technique":
        return [_fresh(SAMPLES[sample])]
    collection_type = sample.replace("_", "-")
    return _of_type(collection_type)


@router.get("/api/v3/collections")
async def list_collections(filter: str = "") -> dict:  # noqa: A002 - the API's name
    """One page of the collections of the type in the filter."""
    match = re.search(r"collection_type:(\S+)", filter)
    objects = _of_type(match.group(1)) if match else []
    return _page(objects, "/collections")


@router.get("/api/v3/collections/{collection_id}/download_report")
async def download_report(collection_id: str) -> dict:
    """The URL of the PDF of a report."""
    return {"data": f"https://www.virustotal.com/pdf/{collection_id}.pdf"}


@router.get("/pdf/{name}.pdf")
async def report_pdf(name: str) -> Response:  # noqa: ARG001
    return Response(_pdf(_report_text()), media_type="application/pdf")


@router.get("/api/v3/collections/{collection_id}/relationships/{relationship}")
@router.get("/api/v3/collections/{collection_id}/{relationship}")
async def collection_relationship(collection_id: str, relationship: str) -> dict:
    """The objects related to a collection (the collection itself is left out)."""
    if relationship not in RELATIONSHIPS:
        return _page([], f"/collections/{collection_id}/{relationship}")
    objects = [o for o in _related(relationship) if o["id"] != collection_id]
    return _page(objects, f"/collections/{collection_id}/{relationship}")


@router.get("/api/v3/collections/{collection_id}")
async def get_collection(collection_id: str, response: Response) -> dict:
    if collection_id not in COLLECTIONS:
        response.status_code = 404
        return {"error": {"code": "NotFoundError", "message": "Collection not found"}}
    return {"data": _fresh(COLLECTIONS[collection_id])}


def _alert(doc_type: str, alert_type: str, doc: dict) -> dict:
    """A Digital Threat Monitoring alert on a document of the given type."""
    created = fake.date_time_between("-3d", "-1d")
    return {
        "id": fake.bothify("????????-????-????-????-????????????").lower(),
        "monitor_id": fake.bothify("????????-????-????-????-????????????").lower(),
        "title": f"{fake.company()} {alert_type.lower()} alert",
        "alert_type": alert_type,
        "severity": fake.random_element(["low", "medium", "high"]),
        "status": "new",
        "tags": ["staticfire", doc_type],
        "alert_summary": fake.sentence(),
        "ai_doc_summary": fake.paragraph(),
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "updated_at": created.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "doc": {"__type": doc_type, "timestamp": created.isoformat(), **doc},
    }


def _channel() -> dict:
    return {
        "name": fake.word(),
        "channel_url": f"https://t.me/{fake.user_name()}",
        "messenger": {"name": "telegram"},
        "channel_info": {"description": fake.sentence()},
    }


@router.get("/api/v3/dtm/alerts")
async def dtm_alerts(since: str = Query("")) -> dict:  # noqa: ARG001
    """Alerts on every kind of document the connector maps, in one page."""
    alerts = [
        _alert(
            "message",
            "Compromised Credentials",
            {
                "ingested": fake.iso8601(),
                "channel": _channel(),
                "sender": {"identity": {"name": fake.user_name()}},
                "message_id": str(fake.random_int(1, 99999)),
                "body": fake.paragraph(),
            },
        ),
        _alert(
            "account_discovery",
            "Compromised Credentials",
            {
                "source_url": f"https://{fake.domain_name()}/dump.txt",
                "ingested": fake.iso8601(),
                "source_file": {
                    "filename": "combo.txt",
                    "hashes": {
                        "md5": fake.md5(),
                        "sha1": fake.sha1(),
                        "sha256": fake.sha256(),
                    },
                },
                "service_account": {
                    "login": fake.user_name(),
                    "password": {"plain_text": fake.password()},
                    "service": {
                        "inet_location": {
                            "url": f"https://{fake.domain_name()}/login",
                            "domain": fake.domain_name(),
                        }
                    },
                    "profile": {
                        "contact": {
                            "email": fake.email(),
                            "email_domain": fake.domain_name(),
                        }
                    },
                },
            },
        ),
        _alert(
            "domain_discovery",
            "Domain Discovery",
            {"domain": fake.domain_name(), "source": "certificate-transparency"},
        ),
        _alert(
            "paste",
            "Data Leak",
            {
                "paste_id": fake.bothify("????????"),
                "source_location": {"url": f"https://{fake.domain_name()}/paste"},
                "author": {"identity": {"name": fake.user_name()}},
                "title": fake.sentence(),
                "body": fake.paragraph(),
            },
        ),
        _alert(
            "web_content_publish",
            "Web Content",
            {
                "title": fake.sentence(),
                "inet_location": {"url": f"https://{fake.domain_name()}/post"},
                "text": fake.paragraph(),
            },
        ),
        _alert(
            "shop_listing",
            "Underground Shop",
            {
                "ingested": fake.iso8601(),
                "listing_url": {"url": f"https://{fake.domain_name()}/item/1"},
                "shop": {"name": fake.company()},
                "price": 250,
                "currency": "USD",
                "item_qty": 1,
                "seller": {"identity": {"name": fake.user_name()}},
                "listing_id": "1",
                "item_type": "access",
            },
        ),
        _alert(
            "document_analysis",
            "Document Analysis",
            {
                "ingested": fake.iso8601(),
                "filename": "leak.pdf",
                "file_hashes": {
                    "md5": fake.md5(),
                    "sha1": fake.sha1(),
                    "sha256": fake.sha256(),
                },
                "source": "forum",
                "source_url": f"https://{fake.domain_name()}/leak.pdf",
                "raw_text": fake.paragraph(),
            },
        ),
    ]
    return {"alerts": alerts}


@router.get("/api/v3/{kind}/{object_id}")
async def get_object(
    kind: str,
    object_id: str,  # noqa: ARG001
    response: Response,
) -> dict:
    """An IOC (domain, file, URL, IP address) or an ATT&CK technique."""
    if kind not in IOC_ENDPOINTS:
        response.status_code = 404
        return {"error": {"code": "NotFoundError", "message": "Not found"}}
    return {"data": _fresh(SAMPLES[IOC_ENDPOINTS[kind]])}
