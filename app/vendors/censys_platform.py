"""Censys Platform API v3: collections, global assets and search, read by the Censys
connectors (censys-collections, censys-enrichment, censys-enrichmentapis).

Hosts and certificates come from the factories of app.api.censys, extended with what
connectors read: threats, vulnerabilities, software, reputation and web properties.
"""

import re
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.api.censys import CertificateFactory, HostFactory, ServiceFactory
from app.fake import fake

HOSTS = ["api.platform.censys.io"]
router = APIRouter(prefix="/censys-platform", tags=["Censys Platform"])

HOST_TYPE = "application/vnd.censys.api.v3.host.v1+json"
ENRICHMENT_TYPE = "application/vnd.censys.api.v3.host-enrichment.v1+json"
WEBPROPERTY_TYPE = "application/vnd.censys.api.v3.webproperty.v1+json"
TACTICS = ["command_and_control", "initial_access", "persistence"]


def _clean(value: Any) -> Any:
    """The API leaves out what is not set: drop the nulls of the factories' models."""
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _asset(resource: dict) -> dict:
    return {"extensions": {}, "resource": resource}


def _threat() -> dict:
    malware = fake.malware_family()
    return {
        "id": f"censys.{malware.lower().replace(' ', '_')}",
        "name": f"{malware} C2",
        "confidence": 90.0,
        "source": "censys",
        "type": ["backdoor", "remote_access_trojan"],
        "tactic": fake.random_elements(TACTICS, length=2, unique=True),
        "malware": {
            "primary_name": malware,
            "all_names": [malware, f"{malware}Loader"],
            "last_updated_at": "2026-11-01T00:00:00Z",
        },
        "actors": [
            {
                "primary_name": fake.intrusion_set(),
                "all_names": [fake.intrusion_set()],
            }
        ],
        "evidence": [{"data_path": "banner", "found_value": fake.sha1()}],
    }


def _vuln(cpe: str) -> dict:
    return {
        "id": fake.cve_id(),
        "severity": "high",
        "source": "censys",
        "risk_source": "cve",
        "cwes": [{"entry": "CWE-79"}],
        "kev": [{"date_added": "2024-01-01", "source": "cisa"}],
        "metrics": {
            "cvss_v31": {
                "score": 8.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "components": {
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "privileges_required": "LOW",
                    "user_interaction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentiality": "HIGH",
                    "integrity": "HIGH",
                    "availability": "HIGH",
                },
            },
            "epss": {"score": 0.42, "percentile": 0.97},
        },
        "evidence": [{"data_path": "software.cpe", "found_value": cpe}],
    }


def _service(index: int) -> dict:
    service = _clean(ServiceFactory().model_dump(mode="json"))
    vendor, product = fake.word(), fake.word()
    cpe = f"cpe:2.3:a:{vendor}:{product}:1.{index}:*:*:*:*:*:*:*"
    service["protocol"] = "HTTP"
    service["labels"] = [{"value": "LOGIN_PAGE", "source": "censys"}]
    service["software"] = [
        {"vendor": vendor, "product": product, "version": f"1.{index}", "cpe": cpe}
    ]
    service["threats"] = [_threat()]
    service["vulns"] = [_vuln(cpe)]
    return service


def _host(ip: str | None = None, names: list[str] | None = None) -> dict:
    host = _clean(HostFactory().model_dump(mode="json"))
    host["ip"] = ip or fake.ipv4_public()
    host["dns"] = {"names": names or [fake.domain_name(), fake.domain_name()]}
    host["services"] = [_service(i) for i in range(2)]
    host["labels"] = [{"value": "REMOTE_ACCESS", "source": "censys"}]
    host["reputation"] = {
        "score": 0.82,
        "label": "malicious",
        "model_version": "2026.1",
        "evidence": [
            {
                "feature": {
                    "name": "Open ports",
                    "value": "22,443",
                    "category": "Exposure",
                    "contribution": 12.5,
                }
            }
        ],
    }
    return host


def _certificate(fingerprint: str | None = None, name: str | None = None) -> dict:
    cert = _clean(CertificateFactory().model_dump(mode="json"))
    if fingerprint:
        cert["fingerprint_sha256"] = fingerprint
    cert["names"] = [name or fake.domain_name()]
    return cert


def _webproperty(hostname: str, port: int = 443) -> dict:
    vendor, product = fake.word(), fake.word()
    cpe = f"cpe:2.3:a:{vendor}:{product}:2.0:*:*:*:*:*:*:*"
    return {
        "hostname": hostname,
        "port": port,
        "scan_time": fake.date_time_this_month(tzinfo=None).isoformat() + "Z",
        "endpoints": [{"endpoint_type": "HTML"}],
        "labels": [{"value": "LOGIN_PAGE"}],
        "threats": [_threat()],
        "vulns": [_vuln(cpe)],
        "software": [{"vendor": vendor, "product": product, "version": "2.0"}],
        "cert": _certificate(name=hostname),
    }


@router.get("/v3/collections")
async def collections() -> dict:
    """Two collections, one page."""
    return {
        "result": {
            "collections": [
                {
                    "id": fake.uuid4(),
                    "name": f"{fake.word().capitalize()} infrastructure",
                    "description": fake.sentence(),
                    "query": "host.services.threats.name: *",
                    "status": "active",
                    "status_reason": None,
                    "create_time": "2026-10-01T00:00:00Z",
                    "total_assets": 5,
                    "added_assets_24_hours": 2,
                    "removed_assets_24_hours": 0,
                }
                for _ in range(2)
            ],
            "next_page_token": "",
        }
    }


@router.post("/v3/collections/{collection_uid}/search/query")
async def collection_assets(request: Request) -> dict:
    """The assets of a collection in two pages: hosts and a web property, then a
    certificate."""
    body = await request.json()
    if body.get("page_token"):
        hits = [{"certificate_v1": _asset(_certificate())}]
        next_page = ""
    else:
        hits = [
            {"host_v1": _asset(_host())},
            {"host_v1": _asset(_host())},
            {"webproperty_v1": _asset(_webproperty(fake.domain_name()))},
        ]
        next_page = "page-2"
    return {
        "result": {
            "hits": hits,
            "next_page_token": next_page,
            "previous_page_token": "",
            "query_duration_millis": 12,
            "total_hits": 4,
        }
    }


@router.get("/v3/collections/{collection_uid}/events")
async def collection_events() -> dict:
    return {"result": {"events": [], "next_page": ""}}


@router.get("/v3/global/asset/host/{host_id}")
async def host(host_id: str) -> JSONResponse:
    return JSONResponse({"result": _asset(_host(ip=host_id))}, media_type=HOST_TYPE)


@router.get("/v3/global/asset/enrichment/host/{host_ip}")
async def host_enrichment(host_ip: str) -> JSONResponse:
    """The enrichment view of a host: its services carry threats, and also (as the real
    API does) software and vulnerabilities."""
    full = _host(ip=host_ip)
    keys = ("ip", "location", "autonomous_system", "dns", "labels", "reputation")
    resource = {k: full[k] for k in keys} | {
        "services": [
            {
                k: service[k]
                for k in (
                    "port",
                    "protocol",
                    "scan_time",
                    "labels",
                    "threats",
                    "software",
                    "vulns",
                )
            }
            for service in full["services"]
        ]
    }
    return JSONResponse({"result": _asset(resource)}, media_type=ENRICHMENT_TYPE)


@router.get("/v3/global/asset/webproperty/{webproperty_id}")
async def webproperty(webproperty_id: str) -> JSONResponse:
    """A web property exists for HTTPS only: the plain HTTP one is a 404."""
    hostname, _, port = webproperty_id.rpartition(":")
    if port != "443":
        return JSONResponse(
            {
                "type": "about:blank",
                "title": "Not Found",
                "status": 404,
                "detail": f"web property {webproperty_id} not found",
            },
            status_code=404,
            media_type="application/problem+json",
        )
    return JSONResponse(
        {"result": _asset(_webproperty(hostname, 443))}, media_type=WEBPROPERTY_TYPE
    )


@router.post("/v3/global/search/query")
async def search(request: Request) -> dict:
    """Hosts for a hostname query, certificates for fingerprint or name queries."""
    query = (await request.json()).get("query", "")
    if query.startswith("host.dns.names"):
        name = re.search(r"'([^']+)'", query)
        names = [name.group(1)] if name else None
        hits = [{"host_v1": _asset(_host(names=names))} for _ in range(2)]
    else:
        fingerprints = re.findall(r'fingerprint_\w+ = "([0-9a-fA-F]+)"', query)
        name = re.search(r"cert\.names = '([^']+)'", query)
        sha256 = next((f for f in fingerprints if len(f) == 64), None)
        hits = [
            {
                "certificate_v1": _asset(
                    _certificate(
                        fingerprint=sha256, name=name.group(1) if name else None
                    )
                )
            },
            {"certificate_v1": _asset(_certificate())},
        ]
    return {
        "result": {
            "hits": hits,
            "next_page_token": "",
            "previous_page_token": "",
            "query_duration_millis": 8,
            "total_hits": len(hits),
        }
    }
