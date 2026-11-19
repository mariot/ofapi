"""Cofense Intelligence (ThreatHQ API v1): the threat update log, malware threat reports
and their PDF, read by the OpenCTI cofense and cofense-threathq connectors."""

import time
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request, Response

from app.fake import fake
from app.vendors.fixtures import _pdf

HOSTS = ["www.threathq.com"]
router = APIRouter(prefix="/cofense-threathq", tags=["Cofense ThreatHQ"])

THREATS = 3
# A position handed out less than this long ago has no update after it
POSITION_QUIET_SECONDS = 15
KINDS = ["Credential Phishing", "Loader"]


def _ms(hours_ago: int) -> int:
    return int((datetime.now(UTC) - timedelta(hours=hours_ago)).timestamp() * 1000)


def _family() -> dict:
    return {"familyName": fake.malware_family(), "description": fake.sentence()}


def _threat(threat_id: int) -> dict:
    """A malware threat report, as ``threat/malware/{id}`` describes it."""
    delivery = {
        "mechanismName": fake.random_element(["Office Macro", "Script", "Archive"])
    }
    block_set = [
        {
            "blockType": "URL",
            "data": (url := fake.url()),
            "data_1": {
                "url": url,
                "host": fake.domain_name(),
                "path": "/payload",
                "protocol": "https",
                "domain": fake.domain_name(),
            },
            "role": "C2",
            "roleDescription": "Command and control host",
            "impact": "Major",
            "malwareFamily": _family(),
            "deliveryMechanism": delivery,
        },
        {
            "blockType": "IPv4 Address",
            "data": (ip := fake.ipv4_public()),
            "data_1": ip,
            "role": "Payload",
            "roleDescription": "Payload distribution",
            "impact": "Major",
            "malwareFamily": _family(),
            "deliveryMechanism": delivery,
        },
        {
            "blockType": "Domain Name",
            "data": (domain := fake.domain_name()),
            "data_1": domain,
            "role": "C2",
            "roleDescription": "Command and control host",
            "impact": "Moderate",
            "malwareFamily": _family(),
        },
        {
            "blockType": "Email",
            "data": (email := fake.email()),
            "data_1": email,
            "role": "Exfil",
            "roleDescription": "Exfiltration mailbox",
            "impact": "Minor",
            "malwareFamily": _family(),
        },
    ]
    executable_set = [
        {
            "fileName": fake.file_name(extension="exe"),
            "type": "Attachment",
            "md5Hex": fake.md5(),
            "sha1Hex": fake.sha1(),
            "sha256Hex": fake.sha256(),
            "sha512Hex": fake.sha256() + fake.sha256(),
            "severityLevel": "Major",
            "malwareFamily": _family(),
            "deliveryMechanisms": [delivery],
        }
    ]
    return {
        "id": threat_id,
        "threatType": "malware",
        "label": f"{fake.malware_family()} {fake.random_element(KINDS)}",
        "threatDetailURL": f"https://www.threathq.com/p42/search/default?m={threat_id}",
        "executiveSummary": fake.paragraph(),
        "firstPublished": _ms(30),
        "lastPublished": _ms(2),
        "naicsCodes": [
            {"code": "52", "label": "Finance and Insurance"},
            {"code": "62", "label": "Health Care and Social Assistance"},
        ],
        "malwareFamilySet": [_family()],
        "deliveryMechanisms": [delivery],
        "campaignBrandSet": [{"brand": {"text": fake.company()}}],
        "campaignLanguageSet": [{"languageDefinition": {"name": "English"}}],
        "secureEmailGatewaySet": [{"segName": "Proofpoint"}],
        "subjectSet": [{"subject": fake.sentence(), "totalCount": 12}],
        "blockSet": block_set,
        "executableSet": executable_set,
        "domainSet": [{"domain": fake.domain_name(), "totalCount": 3}],
        "senderIpSet": [{"ip": fake.ipv4_public(), "totalCount": 2}],
        "senderEmailSet": [{"senderEmail": fake.email(), "totalCount": 2}],
        "spamUrlSet": [{"url_1": {"url": fake.url(), "host": fake.domain_name()}}],
    }


@router.post("/apiv1/threat/updates")
async def updates(request: Request) -> dict:
    """The update log: a ``timestamp`` (first call) or a ``position`` (the next ones).

    A position handed out a few seconds ago has no update after it; an older one (one
    stored by a previous run) gets the updates again.
    """
    position = request.query_params.get("position", "")
    now = int(time.time())
    fresh = (
        position.startswith("pos-") and now - int(position[4:]) < POSITION_QUIET_SECONDS
    )
    changelog = (
        []
        if fresh
        else [
            {
                "threatId": 1000 + index,
                "threatType": "malware",
                "occurredOn": _ms(index + 1),
                "deleted": False,
            }
            for index in range(THREATS)
        ]
    )
    next_position = position if fresh else f"pos-{now}"
    return {
        "success": True,
        "data": {"nextPosition": next_position, "changelog": changelog},
    }


@router.get("/apiv1/threat/malware/{threat_id}")
async def malware_threat(threat_id: int) -> dict:
    return {"success": True, "data": _threat(threat_id)}


@router.post("/apiv1/threat/search")
async def search(request: Request) -> dict:
    """Threat reports by ``threatId`` (``m_<id>``, repeated), one page of results."""
    ids = [
        int(value.split("_")[-1])
        for value in request.query_params.getlist("threatId")
        if value.split("_")[-1].isdigit()
    ] or [1000 + index for index in range(THREATS)]
    threats = [_threat(threat_id) for threat_id in ids]
    page = {"currentPage": 0, "totalPages": 1, "totalReturned": len(threats)}
    return {"success": True, "data": {"page": page, "threats": threats}}


@router.get("/apiv1/t3/malware/{threat_id}/pdf")
async def report_pdf(threat_id: int) -> Response:
    return Response(
        _pdf(f"Cofense threat report {threat_id}"), media_type="application/pdf"
    )
