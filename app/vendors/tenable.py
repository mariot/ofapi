"""Tenable: Vulnerability Management (cloud.tenable.com: vulnerability export and
findings search, read through pyTenable) and Security Center (an on-premises host
chosen by its user, ``tsc.staticfire.test`` here), read by the OpenCTI
tenable-vuln-management and tenable-security-center connectors."""

import time
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["cloud.tenable.com", "tsc.staticfire.test"]
router = APIRouter(prefix="/tenable", tags=["Tenable"])

CHUNKS = 2
PER_CHUNK = 3
PAGE = 4


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _asset() -> dict:
    host = fake.domain_name().split(".")[0]
    return {
        "bios_uuid": str(uuid.uuid4()),
        "device_type": "general-purpose",
        "fqdn": f"{host}.corp.example.com",
        "hostname": host,
        "uuid": str(uuid.uuid4()),
        "ipv4": fake.ipv4_private(),
        "ipv6": fake.ipv6(),
        "last_authenticated_results": _iso(datetime.now(UTC)),
        "mac_address": fake.mac_address(),
        "netbios_name": host.upper(),
        "operating_system": ["Microsoft Windows Server 2016 Standard"],
        "network_id": "00000000-0000-0000-0000-000000000000",
        "tracked": True,
        "last_scan_target": fake.ipv4_private(),
    }


def _plugin() -> dict:
    cves = [fake.cve_id() for _ in range(fake.random_int(1, 3))]
    modified = datetime.now(UTC) - timedelta(days=fake.random_int(20, 200))
    published = modified - timedelta(days=fake.random_int(30, 300))
    vector = {
        "access_complexity": "Low",
        "access_vector": "Network",
        "availability_impact": "High",
        "confidentiality_impact": "High",
        "integrity_impact": "High",
        "raw": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    }
    temporal = {
        "exploitability": "Unproven",
        "remediation_level": "Official Fix",
        "report_confidence": "Confirmed",
        "raw": "E:U/RL:O/RC:C",
    }
    return {
        "bid": [fake.random_int(10000, 99999)],
        "checks_for_default_account": False,
        "checks_for_malware": False,
        "cpe": ["cpe:/a:microsoft:sharepoint_server"],
        "cvss3_base_score": 8.8,
        "cvss3_temporal_score": 7.7,
        "cvss3_temporal_vector": temporal,
        "cvss3_vector": vector,
        "cvss_base_score": 9,
        "cvss_temporal_score": 6.7,
        "cvss_temporal_vector": {**temporal, "raw": "E:U/RL:OF/RC:C"},
        "cvss_vector": {
            "access_complexity": "Low",
            "access_vector": "Network",
            "authentication": "Single",
            "availability_impact": "Complete",
            "confidentiality_impact": "Complete",
            "integrity_impact": "Complete",
            "raw": "AV:N/AC:L/Au:S/C:C/I:C/A:C",
        },
        "description": f"The host is missing security updates ({', '.join(cves)}).",
        "exploit_available": False,
        "exploit_framework_canvas": False,
        "exploit_framework_core": False,
        "exploit_framework_d2_elliot": False,
        "exploit_framework_exploithub": False,
        "exploit_framework_metasploit": False,
        "exploitability_ease": "No known exploits are available",
        "exploited_by_malware": False,
        "exploited_by_nessus": False,
        "family": "Windows : Microsoft Bulletins",
        "family_id": 41,
        "has_patch": True,
        "has_workaround": False,
        "id": fake.random_int(100000, 999999),
        "in_the_news": False,
        "ms_bulletin": ["5002113"],
        "name": f"Security Updates for Microsoft SharePoint Server ({cves[0]})",
        "patch_publication_date": _iso(published),
        "modification_date": _iso(modified),
        "publication_date": _iso(published),
        "risk_factor": "high",
        "see_also": ["https://support.microsoft.com/en-us/help/5002113"],
        "solution": "Microsoft has released a security update to address this issue.",
        "stig_severity": "I",
        "synopsis": "The installation on the remote host is missing security updates.",
        "unsupported_by_vendor": False,
        "version": "1.6",
        "vuln_publication_date": _iso(published),
        "xrefs": [{"type": "CVE", "id": cve.removeprefix("CVE-")} for cve in cves],
        "vpr": {
            "score": 6.7,
            "drivers": {
                "age_of_vuln": {"lower_bound": 731},
                "exploit_code_maturity": "UNPROVEN",
                "cvss_impact_score_predicted": False,
                "cvss3_impact_score": 5.9,
                "threat_intensity_last28": "VERY_LOW",
                "threat_sources_last28": ["No recorded events"],
                "product_coverage": "LOW",
            },
            "updated": _iso(modified),
        },
        "cve": cves,
        "type": "local",
    }


def _finding(asset: dict, plugin: dict) -> dict:
    now = datetime.now(UTC)
    return {
        "asset": asset,
        "output": "\n\n  Product : Microsoft SharePoint Server\n  Fixed : 16.0.5\n",
        "plugin": plugin,
        "port": {"port": 445, "protocol": "TCP", "service": "cifs"},
        "scan": {
            "schedule_uuid": f"{uuid.uuid4()}{uuid.uuid4().hex[:20]}",
            "started_at": _iso(now - timedelta(hours=3)),
            "uuid": str(uuid.uuid4()),
            "target": asset["last_scan_target"],
        },
        "severity": "high",
        "severity_id": 3,
        "severity_default_id": 3,
        "severity_modification_type": "NONE",
        "first_found": _iso(now - timedelta(days=30)),
        "last_found": _iso(now - timedelta(hours=2)),
        "state": "OPEN",
        "indexed": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "source": "NESSUS",
    }


# the findings of every export, and of the latest one (the findings search joins on it)
_exports: dict[str, list[list[dict]]] = {}
_latest: list[dict] = []


@router.post("/vulns/export")
async def start_export() -> dict:
    """Starts an export of CHUNKS chunks of findings over a few assets."""
    global _latest
    assets = [_asset() for _ in range(3)]
    plugins = [_plugin() for _ in range(2)]
    findings = [_finding(a, p) for a in assets for p in plugins]
    _latest = findings
    export_id = str(uuid.uuid4())
    size = len(findings) // CHUNKS
    _exports[export_id] = [findings[i * size : (i + 1) * size] for i in range(CHUNKS)]
    return {"export_uuid": export_id}


@router.get("/vulns/export/{export_id}/status")
async def export_status(export_id: str) -> dict:
    chunks = _exports.get(export_id, [])
    return {
        "uuid": export_id,
        "status": "FINISHED",
        "chunks_available": list(range(1, len(chunks) + 1)),
        "chunks_failed": [],
        "chunks_cancelled": [],
        "total_chunks": len(chunks),
        "chunks_available_count": len(chunks),
        "empty_chunks_count": 0,
        "finished_chunks": len(chunks),
        "filters": {},
        "num_assets_per_chunk": 50,
        "created": int(time.time() * 1000),
    }


@router.get("/vulns/export/{export_id}/chunks/{chunk_id}")
async def export_chunk(export_id: str, chunk_id: int) -> list[dict]:
    return _exports.get(export_id, [[]] * chunk_id)[chunk_id - 1]


@router.post("/api/v3/findings/vulnerabilities/host/search")
async def search_findings(request: Request) -> dict:
    """The ids of the latest export's findings, PAGE per page (cursor ``next``)."""
    body = await request.json()
    cursor = int(body["next"]) if body.get("next") else 0
    page = _latest[cursor : cursor + PAGE]
    more = cursor + PAGE < len(_latest)
    return {
        "findings": [
            {
                "id": str(uuid.uuid4()),
                "asset": {"id": f["asset"]["uuid"]},
                "definition": {"id": f["plugin"]["id"]},
            }
            for f in page
        ],
        "pagination": {
            "total": len(_latest),
            "next": str(cursor + PAGE) if more else None,
        },
    }


# Security Center: its REST API wraps every answer in an envelope, except the CVE one
_scan_assets: list[dict] = []


def _envelope(response: object) -> dict:
    return {
        "type": "regular",
        "response": response,
        "error_code": 0,
        "error_msg": "",
        "warnings": [],
        "timestamp": int(time.time()),
    }


def _stamp() -> str:
    return str(int(time.time()) - fake.random_int(600, 7200))


def _tsc_asset() -> dict:
    host = fake.domain_name().split(".")[0]
    repository = {"id": "1", "name": "Staticfire", "description": ""}
    return {
        "id": str(fake.random_int(100, 99999)),
        "uuid": str(uuid.uuid4()),
        "tenableUUID": str(uuid.uuid4()),
        "name": f"{host}.corp.example.com",
        "ipAddress": fake.ipv4_private(),
        "os": "Microsoft Windows Server 2016 Standard",
        "firstSeen": str(int(time.time()) - 86400 * 20),
        "lastSeen": _stamp(),
        "macAddress": fake.mac_address(),
        "source": "nessus",
        "repository": repository,
        "netBios": host.upper(),
        "netBiosWorkgroup": "WORKGROUP",
        "createdTime": str(int(time.time()) - 86400 * 20),
        "modifiedTime": _stamp(),
    }


def _tsc_finding(asset: dict, cves: list[str]) -> dict:
    plugin_id = str(fake.random_int(100000, 999999))
    return {
        "pluginID": plugin_id,
        "pluginName": f"Security Updates for Microsoft SharePoint Server ({cves[0]})",
        "ip": asset["ipAddress"],
        "dnsName": asset["name"],
        "macAddress": asset["macAddress"],
        "netbiosName": asset["netBios"],
        "operatingSystem": asset["os"],
        "port": "445",
        "protocol": "TCP",
        "severity": {"id": "3", "name": "High", "description": "High Severity"},
        "family": {
            "id": "41",
            "name": "Windows : Microsoft Bulletins",
            "type": "active",
        },
        "repository": asset["repository"],
        "firstSeen": str(int(time.time()) - 86400 * 15),
        "lastSeen": _stamp(),
        "hasBeenMitigated": "0",
        "acceptRisk": "0",
        "recastRisk": "0",
        "exploitAvailable": "No",
        "exploitEase": "",
        "exploitFrameworks": "",
        "synopsis": "The remote host is missing security updates.",
        "description": f"The remote host is affected by {', '.join(cves)}.",
        "solution": "Apply the latest cumulative update.",
        "seeAlso": "https://support.microsoft.com/en-us/help/5002113",
        "riskFactor": "High",
        "stigSeverity": "I",
        "baseScore": "9.0",
        "temporalScore": "6.7",
        "cvssVector": "AV:N/AC:L/Au:S/C:C/I:C/A:C",
        "cvssV3BaseScore": "8.8",
        "cvssV3TemporalScore": "7.7",
        "cvssV3Vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "vulnPubDate": str(int(time.time()) - 86400 * 400),
        "patchPubDate": str(int(time.time()) - 86400 * 390),
        "pluginPubDate": str(int(time.time()) - 86400 * 380),
        "pluginModDate": str(int(time.time()) - 86400 * 100),
        "checkType": "remote",
        "version": "1.6",
        "cpe": "cpe:/a:microsoft:sharepoint_server",
        "cve": ",".join(cves),
        "bid": "156641",
        "xref": f"IAVA #2022-A-{fake.random_int(1000, 9999)}-S",
        "seolDate": "-1",
        "pluginText": "<plugin_output>Fixed version : 16.0.5</plugin_output>",
        "vprScore": "6.7",
        "hostUniqueness": "repositoryID,ip,dnsName",
        "vulnUniqueness": "repositoryID,ip,port,protocol,pluginID",
        "uniqueness": "repositoryID,ip,port,protocol,pluginID",
    }


@router.get("/rest/system")
async def tsc_system() -> dict:
    return _envelope(
        {
            "version": "5.23.1",
            "buildID": "202307091250",
            "banner": "",
            "releaseID": "202307091250",
            "uuid": str(uuid.uuid4()),
            "logo": "",
            "serverAuth": "any",
            "serverClassification": "",
            "sessionTimeout": "3600",
            "licenseStatus": "Valid",
        }
    )


@router.get("/rest/scanResult")
async def tsc_scan_results() -> dict:
    """The usable completed scan results; a new set of assets is scanned."""
    _scan_assets[:] = [_tsc_asset() for _ in range(3)]
    return _envelope({"usable": [{"id": "42"}], "manageable": []})


@router.get("/rest/scanResult/{scan_id}")
async def tsc_scan_result(scan_id: str) -> dict:
    ips = ",".join(asset["ipAddress"] for asset in _scan_assets)
    return _envelope(
        {
            "id": scan_id,
            "name": "Weekly credentialed scan",
            "repository": {"id": "1", "name": "Staticfire", "description": ""},
            "progress": {"scannedIPs": ips, "completedIPs": ips},
        }
    )


@router.post("/rest/hosts/search")
async def tsc_hosts(request: Request) -> dict:
    """The scanned assets, ``startOffset`` to ``endOffset``."""
    start = int(request.query_params.get("startOffset", 0))
    end = int(request.query_params.get("endOffset", start + 10))
    page = _scan_assets[start:end]
    return _envelope(
        {
            "totalRecords": str(len(_scan_assets)),
            "returnedRecords": len(page),
            "startOffset": start,
            "endOffset": end,
            "results": page,
        }
    )


@router.post("/rest/analysis")
async def tsc_analysis(request: Request) -> dict:
    """The findings of the assets (of the one whose ``ip`` the filters name)."""
    query = (await request.json()).get("query", {})
    wanted = {
        f["value"]
        for f in query.get("filters", [])
        if f.get("filterName") == "ip" and f.get("value")
    }
    findings = [
        _tsc_finding(asset, [fake.cve_id() for _ in range(2)])
        for asset in _scan_assets
        if not wanted or asset["ipAddress"] in wanted
        for _ in range(2)
    ]
    start = int(query.get("startOffset", 0))
    end = int(query.get("endOffset", start + 100))
    return _envelope(
        {
            "totalRecords": str(len(findings)),
            "returnedRecords": len(findings[start:end]),
            "startOffset": start,
            "endOffset": end,
            "results": findings[start:end],
        }
    )


@router.get("/rest/cve/{cve_id}")
async def tsc_cve(cve_id: str) -> dict:
    """The CVE details (an answer without envelope)."""
    published = datetime.now(UTC) - timedelta(days=fake.random_int(100, 400))
    return {
        "primary_vuln_id": cve_id,
        "descriptions": [
            {
                "description_text": f"{cve_id} allows remote code execution.",
                "publication_date": _iso(published),
            },
            {
                "description_text": f"{cve_id} allows remote code execution.",
                "publication_date": _iso(published + timedelta(days=20)),
            },
        ],
        "cpe_metrics": ["cpe:2.3:a:microsoft:sharepoint_server:2016:*:*:*:*:*:*:*"],
        "cvss_metrics": [
            {
                "cvss3_base_score": 8.8,
                "cvss3_base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            }
        ],
        "epss_metrics": [{"epss": 0.01234, "percentile": 0.45}],
    }
