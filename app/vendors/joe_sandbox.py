"""Joe Sandbox Cloud: the web API v2 (submissions, analyses, report downloads), read by
the OpenCTI joe-sandbox enrichment connector through the jbxapi client."""

import json

from fastapi import APIRouter, Form, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["jbxcloud.joesecurity.org", "joesandbox.com"]
router = APIRouter(prefix="/joe-sandbox", tags=["Joe Sandbox"])

# submission id -> {"webid", "threat", "calls"}
SUBMISSIONS: dict[str, dict] = {}

REPORT_FILES = {
    "executive": ("executive.html", "text/html"),
    "html": ("report.html", "text/html"),
    "iochtml": ("ioc.html", "text/html"),
    "iocjson": ("ioc.json", "application/json"),
    "iocxml": ("ioc.xml", "application/xml"),
    "json": ("report.json", "application/json"),
    "lightjsonfixed": ("lightreport.json", "application/json"),
    "xml": ("report.xml", "application/xml"),
    "lightxml": ("lightreport.xml", "application/xml"),
    "stix": ("stix.json", "application/json"),
    "misp": ("misp.xml", "application/xml"),
    "maec": ("maec.xml", "application/xml"),
    "pdf": ("report.pdf", "application/pdf"),
    "pdfexecutive": ("executive.pdf", "application/pdf"),
    "pcap": ("capture.pcap", "application/vnd.tcpdump.pcap"),
    "pcapunified": ("unified.pcap", "application/vnd.tcpdump.pcap"),
    "pcapsslinspection": ("ssl.pcap", "application/vnd.tcpdump.pcap"),
    "unpackpe": ("unpack.zip", "application/zip"),
    "ida": ("ida.zip", "application/zip"),
    "memdumps": ("memdumps.zip", "application/zip"),
}


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(
        {"errors": [{"code": status, "message": message}]}, status_code=status
    )


def _json_report(threat: str) -> dict:
    """The parts of a Joe Sandbox JSON report the connector reads."""
    return {
        "analysis": {
            "malware_configs": {
                "config": [
                    {
                        "@threatname": threat,
                        "@type": "Config",
                        "c2": [f"https://{fake.domain_name()}/gate.php"],
                    }
                ]
            },
            "yara": {
                "memorydumps": {"hit": [{"rule": f"{threat}_memory", "@id": "1"}]},
                "unpackedpes": {"hit": [{"rule": f"{threat}_unpacked", "@id": "2"}]},
            },
            "domaininfo": {
                "domain": [{"@name": fake.domain_name(), "@ip": fake.ipv4_public()}]
            },
            "urlinfo": {"url": [{"@name": fake.url(), "@method": "GET"}]},
            "ipinfo": {
                "ip": [
                    {"@ip": fake.ipv4_public(), "@port": "443"},
                    {"@ip": "192.168.2.5", "@port": "49703"},
                ]
            },
        }
    }


@router.post("/api/v2/submission/new")
async def submission_new() -> dict:
    """Queues the analysis of a URL, a URL to download or an uploaded sample."""
    submission_id = str(fake.random_int(100000, 999999))
    SUBMISSIONS[submission_id] = {
        "webid": str(fake.random_int(1000000, 9999999)),
        "threat": fake.malware_family(),
        "calls": 0,
    }
    return {"data": {"submission_id": submission_id}}


@router.post("/api/v2/submission/chunked-sample")
async def chunked_sample() -> dict:
    """Accepts a chunk of the sample of a submission made with ``chunked-sample``."""
    return {"data": {}}


@router.post("/api/v2/submission/info")
async def submission_info(submission_id: str = Form()) -> Response:
    """Running on the first call, finished after, with one analysis."""
    submission = SUBMISSIONS.get(submission_id)
    if submission is None:
        return _error(404, "Submission not found.")
    submission["calls"] += 1
    if submission["calls"] < 2:
        return JSONResponse(
            {
                "data": {
                    "submission_id": submission_id,
                    "status": "submitted",
                    "analyses": [],
                }
            }
        )
    analysis = {
        "webid": submission["webid"],
        "time": "2026-05-13T09:30:00+00:00",
        "runs": [{"detection": "malicious", "error": None, "system": "w10x64_office"}],
        "comments": "",
        "analysisid": submission["webid"][::-1],
        "md5": fake.md5(),
        "sha1": fake.sha1(),
        "sha256": fake.sha256(),
        "filename": "sample.exe",
        "scriptname": "",
        "status": "finished",
        "score": 98,
        "detection": "malicious",
        "threatname": submission["threat"],
        "classification": "Trojan",
        "encrypted": False,
        "tags": [],
    }
    return JSONResponse(
        {
            "data": {
                "submission_id": submission_id,
                "name": "sample.exe",
                "status": "finished",
                "time": "2026-05-13T09:30:00+00:00",
                "analyses": [analysis],
                "most_relevant_analysis": {
                    "webid": submission["webid"],
                    "detection": "malicious",
                    "score": 98,
                },
            }
        }
    )


@router.post("/api/v2/analysis/download")
async def analysis_download(webid: str = Form(), type: str = Form()) -> Response:
    """A report of an analysis, in the format asked."""
    if type not in REPORT_FILES:
        return _error(404, f"Unknown resource type {type}.")
    name, media_type = REPORT_FILES[type]
    submission = next((s for s in SUBMISSIONS.values() if s["webid"] == webid), None)
    threat = submission["threat"] if submission else "Unknown"
    if type in ("json", "lightjsonfixed"):
        body = json.dumps(_json_report(threat)).encode()
    elif type == "iocjson":
        body = json.dumps({"ioc": {"ips": [fake.ipv4_public()]}}).encode()
    elif type == "stix":
        body = json.dumps({"type": "bundle", "id": f"bundle--{fake.uuid4()}"}).encode()
    elif media_type in ("text/html", "application/xml"):
        body = f"<html><body>{threat} {webid}</body></html>".encode()
    else:
        body = b"PK\x05\x06" + bytes(18)
    return Response(
        body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{webid}_{name}";'},
    )
