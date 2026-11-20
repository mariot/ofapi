"""VirusTotal / Google Threat Intelligence API v3 (``www.virustotal.com/api/v3``).

Read by the OpenCTI google-ti-feeds connector (collections: reports, threat actors,
malware families, software toolkits, vulnerabilities, campaigns, and their IOCs) and
the google-dtm connector (Digital Threat Monitoring alerts, ``/dtm/alerts``).

The collection and IOC objects are recorded GTI payloads (``virustotal_samples.json``,
placeholder data) whose dates are moved to the last hours on every answer. Other
VirusTotal connectors can add their routes here."""

import base64
import copy
import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import APIRouter, Query, Request, Response

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


# --- Livehunt: hunting notifications (ioc_stream) and rulesets, read and written by the
# virustotal-livehunt-notifications and virustotal-livehunt-rules connectors ---

AV_ENGINES = ["Kaspersky", "Symantec", "Microsoft", "ESET-NOD32", "BitDefender"]
RULESETS: dict[str, dict] = {}
NOTIFICATIONS: dict[str, dict] = {}


def _yara_rule(name: str) -> str:
    return (
        f'import "pe"\n\nrule {name} {{\n'
        f'    meta:\n        author = "staticfire"\n'
        f'        date = "{fake.date_between("-30d").isoformat()}"\n'
        f'        description = "{fake.sentence()}"\n'
        f'    strings:\n        $a = "{fake.word()}" ascii wide\n'
        f"    condition:\n        uint16(0) == 0x5a4d and $a\n}}\n"
    )


def _ruleset(ruleset_id: str, name: str) -> dict:
    now = int(time.time())
    return {
        "id": ruleset_id,
        "type": "hunting_ruleset",
        "links": {
            "self": f"https://www.virustotal.com/api/v3/intelligence/"
            f"hunting_rulesets/{ruleset_id}"
        },
        "attributes": {
            "name": name,
            "enabled": True,
            "limit": 100,
            "rules": _yara_rule(name),
            "rule_names": [name],
            "creation_date": now - 86400,
            "modification_date": now - 3600,
            "notification_emails": [],
        },
    }


def _scan_results(malicious: int) -> dict:
    results = {}
    for engine in AV_ENGINES:
        flagged = malicious > 0 and fake.boolean(70)
        results[engine] = {
            "category": "malicious" if flagged else "undetected",
            "engine_name": engine,
            "method": "blacklist",
            "result": fake.malware_family() if flagged else None,
        }
    return results


def _hunted_file(extension: str, malicious: int) -> dict:
    sha256 = fake.sha256()
    now = int(time.time())
    name = f"{fake.word()}.{extension}"
    return {
        "id": sha256,
        "type": "file",
        "links": {"self": f"https://www.virustotal.com/api/v3/files/{sha256}"},
        "attributes": {
            "sha256": sha256,
            "sha1": fake.sha1(),
            "md5": fake.md5(),
            "size": fake.random_int(20000, 900000),
            "names": [name, f"{fake.word()}.{extension}"],
            "meaningful_name": name,
            "type_extension": extension,
            "type_tag": "peexe" if extension == "exe" else "pedll",
            "type_tags": ["executable", "windows", "pe"],
            "tags": ["peexe", "64bits", "signed"],
            "first_submission_date": now - 7200,
            "last_submission_date": now - 3600,
            "last_analysis_date": now - 3600,
            "last_analysis_stats": {
                "malicious": malicious,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 70 - malicious,
                "timeout": 0,
                "confirmed-timeout": 0,
                "failure": 0,
                "type-unsupported": 3,
            },
            "last_analysis_results": _scan_results(malicious),
            "reputation": -10,
        },
    }


def _notification(extension: str, malicious: int) -> dict:
    """A file that matched a hunting ruleset, with the context of its notification."""
    obj = _hunted_file(extension, malicious)
    rule_name = f"staticfire_{fake.word()}_{fake.random_int(100, 999)}"
    ruleset_id = str(fake.random_int(10**15, 10**16))
    RULESETS[ruleset_id] = _ruleset(ruleset_id, rule_name)
    notification_id = (
        fake.bothify("?" * 8).lower() + "-" + str(fake.random_int(1, 10**6))
    )
    obj["context_attributes"] = {
        "notification_id": notification_id,
        "notification_date": int(time.time()) - 1800,
        "origin": "hunting",
        "hunting_info": {
            "rule_name": rule_name,
            "rule_tags": ["staticfire"],
            "snippet": "",
            "source_country": "FR",
            "source_key": fake.sha1(),
        },
        "sources": [{"id": ruleset_id, "label": rule_name, "type": "hunting_ruleset"}],
        "tags": [rule_name, "staticfire"],
    }
    NOTIFICATIONS[notification_id] = obj
    return obj


@router.get("/api/v3/ioc_stream")
async def ioc_stream() -> dict:
    """One page of hunting notifications: files, some below the connector's filters."""
    objects = [
        _notification("exe", 28),
        _notification("dll", 17),
        _notification("exe", 9),
        _notification("exe", 2),
        _notification("txt", 30),
    ]
    return {"data": objects, "meta": {"count": len(objects)}}


@router.get("/api/v3/intelligence/hunting_rulesets")
async def list_rulesets() -> dict:
    data = list(RULESETS.values())
    return {"data": data, "meta": {"count": len(data)}}


@router.post("/api/v3/intelligence/hunting_rulesets")
async def create_ruleset(body: dict) -> dict:
    attributes = body["data"]["attributes"]
    ruleset_id = str(fake.random_int(10**15, 10**16))
    RULESETS[ruleset_id] = _ruleset(ruleset_id, attributes["name"])
    RULESETS[ruleset_id]["attributes"].update(
        rules=attributes["rules"], notification_emails=attributes["notification_emails"]
    )
    return {"data": RULESETS[ruleset_id]}


@router.get("/api/v3/intelligence/hunting_rulesets/{ruleset_id}")
async def get_ruleset(ruleset_id: str) -> dict:
    ruleset = RULESETS.get(ruleset_id) or _ruleset(ruleset_id, f"rule_{ruleset_id}")
    return {"data": ruleset}


@router.delete("/api/v3/intelligence/hunting_rulesets/{ruleset_id}")
async def delete_ruleset(ruleset_id: str) -> dict:
    RULESETS.pop(ruleset_id, None)
    return {}


@router.post("/api/v3/intelligence/hunting_rulesets/{ruleset_id}/relationships/editors")
async def add_editors(ruleset_id: str, body: dict) -> dict:  # noqa: ARG001
    return {}


@router.delete("/api/v3/intelligence/hunting_notifications/{notification_id}")
async def delete_notification(notification_id: str) -> dict:
    NOTIFICATIONS.pop(notification_id, None)
    return {}


@router.get("/api/v3/files/{sha256}/download")
async def download_file(sha256: str) -> Response:  # noqa: ARG001
    """The sample itself: a few bytes of a PE header."""
    return Response(
        b"MZ" + bytes(range(256)) * 8, media_type="application/octet-stream"
    )


@router.get("/api/v3/files/{sha256}/behaviour_mitre_trees")
async def behaviour_trees(sha256: str) -> dict:
    """The malware configuration the livehunt connector reads (domains, IPs, URLs)."""
    return {
        "data": {
            "id": sha256,
            "type": "file_behaviour_mitre_trees",
            "attributes": {
                "malware_configurations": {
                    "domains": [fake.domain_name(), fake.domain_name()],
                    "ips": [fake.ipv4_public(), fake.ipv6()],
                    "urls": [fake.url()],
                }
            },
        }
    }


# --- Enrichment: IOC reports (files, URLs, domains, IP addresses), uploads and their
# analyses, read by the virustotal enrichment and virustotal-downloader connectors ---

HASH_LENGTHS = {32, 40, 64}
SEEN: set[str] = set()  # hashes and URL ids made known by an upload
ANALYSES: dict[str, str] = {}


def _not_found(response: Response, what: str) -> dict:
    response.status_code = 404
    return {"error": {"code": "NotFoundError", "message": f"{what} not found"}}


def _gti_assessment() -> dict:
    return {
        "threat_score": {"value": fake.random_int(60, 95)},
        "severity": {"value": "SEVERITY_HIGH"},
        "verdict": {"value": "VERDICT_MALICIOUS"},
        "contributing_factors": {"mandiant_confidence_score": 90},
    }


def _unseen_file(identifier: str) -> bool:
    """Hashes starting with 00 are unknown to VirusTotal until uploaded."""
    return identifier.startswith("00") and identifier not in SEEN


def _file_report(identifier: str) -> dict:
    obj = _hunted_file("exe", fake.random_int(15, 40))
    attributes = obj["attributes"]
    length = len(identifier)
    if length == 64:
        attributes["sha256"] = identifier
    elif length == 40:
        attributes["sha1"] = identifier
    elif length == 32:
        attributes["md5"] = identifier
    obj["id"] = attributes["sha256"]
    obj["links"]["self"] = f"https://www.virustotal.com/api/v3/files/{obj['id']}"
    ruleset_id = str(fake.random_int(10**15, 10**16))
    rule_name = f"staticfire_{fake.word()}_{fake.random_int(100, 999)}"
    RULESETS[ruleset_id] = _ruleset(ruleset_id, rule_name)
    attributes.update(
        magic="PE32 executable (GUI) Intel 80386, for MS Windows",
        type_description="Win32 EXE",
        creation_date=int(time.time()) - 5 * 86400,
        popular_threat_classification={
            "suggested_threat_label": f"trojan.{fake.word()}/{fake.word()}",
        },
        signature_info={"verified": "Signed", "product": fake.word()},
        gti_assessment=_gti_assessment(),
        crowdsourced_yara_results=[
            {
                "ruleset_id": ruleset_id,
                "ruleset_name": f"set_{rule_name}",
                "rule_name": rule_name,
                "author": fake.name(),
                "description": fake.sentence(),
                "source": "https://github.com/staticfire/rules",
            }
        ],
    )
    return obj


def _ioc_report(kind: str, identifier: str, extra: dict | None = None) -> dict:
    """A recorded sample of the kind, under the identifier asked."""
    obj = _fresh(SAMPLES[IOC_ENDPOINTS[kind]])
    obj["id"] = identifier
    obj["links"]["self"] = f"https://www.virustotal.com/api/v3/{kind}/{identifier}"
    obj["attributes"]["last_analysis_results"] = _scan_results(5)
    obj["attributes"]["gti_assessment"] = _gti_assessment()
    obj["attributes"].update(extra or {})
    return obj


def _b64_decode(value: str) -> str:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()
    except ValueError:
        return ""


@router.get("/api/v3/files/{identifier}")
async def get_file(identifier: str, response: Response) -> dict:
    if len(identifier) not in HASH_LENGTHS:
        return _not_found(response, "File")
    if _unseen_file(identifier):
        return _not_found(response, "File")
    return {"data": _file_report(identifier)}


@router.get("/api/v3/urls/{identifier}")
async def get_url(identifier: str, response: Response) -> dict:
    """URLs with ``unseen`` in them are unknown until submitted."""
    if "unseen" in _b64_decode(identifier) and identifier not in SEEN:
        return _not_found(response, "URL")
    if "unseen" not in _b64_decode(identifier) and identifier not in SEEN:
        decoded = _b64_decode(identifier)
        if not decoded.startswith("http"):
            return _not_found(response, "URL")
    url = _b64_decode(identifier) or f"https://{fake.domain_name()}/dropper.exe"
    return {
        "data": _ioc_report("urls", identifier, {"last_final_url": url, "url": url})
    }


@router.get("/api/v3/domains/{identifier}")
async def get_domain(identifier: str) -> dict:
    return {"data": _ioc_report("domains", identifier)}


@router.get("/api/v3/ip_addresses/{identifier}")
async def get_ip(identifier: str) -> dict:
    return {"data": _ioc_report("ip_addresses", identifier)}


@router.get("/api/v3/{kind}/{identifier}/resolutions")
async def resolutions(kind: str, identifier: str, cursor: str = "") -> dict:
    """Domains seen on the address, newest first: two pages."""
    page = 1 if not cursor else 2
    now = int(time.time())
    data = [
        {
            "id": f"{identifier}{fake.domain_name()}",
            "type": "resolution",
            "attributes": {
                "host_name": fake.domain_name(),
                "ip_address": identifier,
                "date": now - 86400 * (page * 3 + n),
                "resolver": "VirusTotal",
            },
        }
        for n in range(3)
    ]
    path = f"/{kind}/{identifier}/resolutions"
    body: dict = {"data": data, "meta": {"count": 6}, "links": {}}
    if page == 1:
        body["meta"]["cursor"] = "page2"
        body["links"]["next"] = f"https://www.virustotal.com/api/v3{path}?cursor=page2"
    return body


@router.get("/api/v3/{kind}/{identifier}/last_serving_ip_address")
async def last_serving_ip(kind: str, identifier: str) -> dict:  # noqa: ARG001
    return {"data": _ioc_report("ip_addresses", fake.ipv4_public())}


GTI_RELATIONSHIPS = {
    "malware_families": "malware_family",
    "threat_actors": "threat_actor",
    "campaigns": "campaign",
    "reports": "report",
}


@router.get("/api/v3/{kind}/{identifier}/{relationship}")
async def gti_relationship(kind: str, identifier: str, relationship: str) -> dict:
    """Collections linked to an IOC (the shared GTI samples)."""
    if kind == "collections" or relationship not in GTI_RELATIONSHIPS:
        return _page([], f"/{kind}/{identifier}/{relationship}")
    objects = _of_type(GTI_RELATIONSHIPS[relationship].replace("_", "-"))
    return _page(objects, f"/{kind}/{identifier}/{relationship}")


@router.get("/api/v3/yara_rulesets/{ruleset_id}")
async def get_yara_ruleset(ruleset_id: str) -> dict:
    return await get_ruleset(ruleset_id)


def _multipart_file(content_type: str, body: bytes) -> bytes:
    """The content of the first file part of a multipart body."""
    boundary = content_type.split("boundary=")[-1].strip('"').encode()
    part = body.split(b"--" + boundary)[1]
    return part.split(b"\r\n\r\n", 1)[1].removesuffix(b"\r\n")


@router.post("/api/v3/files")
async def upload_file(request: Request) -> dict:
    """A sample submitted for analysis: its hashes become known."""
    content = _multipart_file(request.headers["content-type"], await request.body())
    SEEN.update({hashlib.sha256(content).hexdigest(), hashlib.md5(content).hexdigest()})
    analysis_id = base64.b64encode(fake.md5().encode()).decode().rstrip("=")
    ANALYSES[analysis_id] = "completed"
    return {"data": {"type": "analysis", "id": analysis_id}}


@router.post("/api/v3/urls")
async def upload_url(request: Request) -> dict:
    """A URL submitted for analysis: it becomes known under both of its ids."""
    form = parse_qs((await request.body()).decode())
    url = form.get("url", [""])[0]
    SEEN.add(base64.urlsafe_b64encode(url.encode()).decode().rstrip("="))
    SEEN.add(hashlib.sha256(url.encode()).hexdigest())
    analysis_id = f"u-{hashlib.sha256(url.encode()).hexdigest()}-{int(time.time())}"
    ANALYSES[analysis_id] = "completed"
    return {"data": {"type": "analysis", "id": analysis_id}}


@router.get("/api/v3/analyses/{analysis_id}")
async def get_analysis(analysis_id: str) -> dict:
    now = int(time.time())
    return {
        "data": {
            "type": "analysis",
            "id": analysis_id,
            "attributes": {
                "status": ANALYSES.get(analysis_id, "completed"),
                "date": now,
                "stats": {"malicious": 12, "harmless": 50, "undetected": 20},
                "results": _scan_results(12),
            },
        }
    }


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
