"""Microsoft Graph (graph.microsoft.com) for the connectors reading a Microsoft 365
mailbox (email-intel-microsoft), with room for the routes of other Graph connectors
(Defender, Sentinel, Graph security...): add them to this module under ``/v1.0``.

The Graph Python SDK sends ``/v1.0//users/...`` (a doubled slash Graph accepts): the
routes are declared both ways.

Tokens come from ``microsoft_identity``. The routes below answer what the Graph SDKs
expect: ``@odata.type`` discriminators, ``@odata.nextLink`` paging and base64
``contentBytes``. The prefix is the one of the OpenAEV routes of ``app/main.py``
(sendMail, Teams messages, security alerts), which therefore answer the real host too:
they are not duplicated here.
"""

import base64
import re
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["graph.microsoft.com"]
router = APIRouter(prefix="/microsoft-graph", tags=["Microsoft Graph"])

GRAPH = "https://graph.microsoft.com/v1.0"
PAGES = 2
MESSAGES_PER_PAGE = 2
# attachment id -> its detail, for the attachments of the messages served
ATTACHMENTS: dict[str, dict] = {}


def graph_date(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def file_attachment(name: str, mime: str, content: bytes, moment: datetime) -> dict:
    attachment = {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "id": "AAMkAD" + uuid.uuid4().hex,
        "name": name,
        "contentType": mime,
        "size": len(content),
        "isInline": False,
        "lastModifiedDateTime": graph_date(moment),
    }
    ATTACHMENTS[attachment["id"]] = {
        **attachment,
        "contentBytes": base64.b64encode(content).decode(),
    }
    return attachment


def message(moment: datetime) -> dict:
    """A threat intelligence email with a PDF, a CSV and an image attachment."""
    sender = fake.company_email()
    iocs = "\n".join(f"{fake.domain_name()},{fake.ipv4_public()}" for _ in range(4))
    return {
        "@odata.etag": f'W/"{uuid.uuid4().hex}"',
        "id": "AAMkAD" + uuid.uuid4().hex,
        "receivedDateTime": graph_date(moment),
        "subject": f"Threat advisory: {fake.malware_family()} campaign",
        "hasAttachments": True,
        "from": {"emailAddress": {"name": fake.company(), "address": sender}},
        "body": {
            "contentType": "html",
            "content": f"<html><body><p>{fake.paragraph()}</p></body></html>",
        },
        "attachments": [
            file_attachment(
                "advisory.pdf",
                "application/pdf",
                b"%PDF-1.4 " + fake.binary(64),
                moment,
            ),
            file_attachment(
                "iocs.csv", "text/csv", f"domain,ip\n{iocs}".encode(), moment
            ),
            file_attachment("banner.png", "image/png", fake.binary(32), moment),
        ],
    }


@router.get("/v1.0/users/{user_id}/mailFolders")
@router.get("/v1.0//users/{user_id}/mailFolders")
async def mail_folders(user_id: str, filter: str = Query("", alias="$filter")) -> dict:
    """The folder named in a ``displayName eq '...'`` filter."""
    name = filter.split("'")[1] if "'" in filter else "Inbox"
    return {
        "@odata.context": f"{GRAPH}/$metadata#users('{user_id}')/mailFolders",
        "value": [{"id": "AAMkAD" + uuid.uuid4().hex, "displayName": name}],
    }


@router.get("/v1.0/users/{user_id}/mailFolders/{folder_id}/messages")
@router.get("/v1.0//users/{user_id}/mailFolders/{folder_id}/messages")
async def messages(
    user_id: str,
    folder_id: str,
    skiptoken: int = Query(0, alias="$skiptoken"),
) -> dict:
    """Pages of recent messages with their attachments listed (without content)."""
    page = skiptoken + 1
    now = datetime.now(UTC)
    value = [
        message(now - timedelta(days=page, hours=3 * index))
        for index in range(MESSAGES_PER_PAGE)
    ]
    answer = {
        "@odata.context": f"{GRAPH}/$metadata#users('{user_id}')/mailFolders/messages",
        "value": value,
    }
    if page < PAGES:
        link = f"{GRAPH}/users/{user_id}/mailFolders/{folder_id}/messages"
        answer["@odata.nextLink"] = f"{link}?%24skiptoken={page}&%24top=50"
    return answer


@router.get(
    "/v1.0/users/{user_id}/mailFolders/{folder_id}/messages/{message_id}"
    "/attachments/{attachment_id}"
)
@router.get(
    "/v1.0//users/{user_id}/mailFolders/{folder_id}/messages/{message_id}"
    "/attachments/{attachment_id}"
)
async def attachment(user_id: str, attachment_id: str) -> dict:
    """An attachment with its content."""
    found = ATTACHMENTS[attachment_id]
    return {
        "@odata.context": f"{GRAPH}/$metadata#users('{user_id}')/attachments/$entity",
        **found,
    }


# -- Security: incidents with their alerts (microsoft-defender-incidents) --

INCIDENT_PAGES = 2
INCIDENTS_PER_PAGE = 2
DETAILED_DATE = "%Y-%m-%dT%H:%M:%S.%f0Z"


def graph_detailed_date(moment: datetime) -> str:
    """The seven fractional digits Graph security resources use."""
    return moment.strftime(DETAILED_DATE)


def _file_details(name: str, path: str) -> dict:
    return {
        "sha1": fake.sha1(),
        "sha256": fake.sha256(),
        "md5": fake.md5(),
        "fileName": name,
        "filePath": path,
        "fileSize": fake.random_int(2048, 4_000_000),
        "filePublisher": None,
        "signer": None,
        "issuer": None,
    }


def _evidence(moment: datetime) -> list[dict]:
    """One piece of evidence of every type the connector maps."""
    created = graph_detailed_date(moment)
    common = {
        "createdDateTime": created,
        "verdict": "suspicious",
        "remediationStatus": "none",
        "remediationStatusDetails": None,
        "roles": [],
        "detailedRoles": [],
        "tags": [],
    }
    dropper = _file_details("invoice_scan.exe", r"C:\Users\Public\Downloads")
    user = fake.user_name()
    return [
        {
            "@odata.type": "#microsoft.graph.security.ipEvidence",
            **common,
            "ipAddress": fake.ipv4_public(),
            "countryLetterCode": "NL",
        },
        {
            "@odata.type": "#microsoft.graph.security.ipEvidence",
            **common,
            "ipAddress": fake.ipv6(),
            "countryLetterCode": None,
        },
        {
            "@odata.type": "#microsoft.graph.security.urlEvidence",
            **common,
            "url": f"https://{fake.domain_name()}/{fake.slug()}.php",
        },
        {
            "@odata.type": "#microsoft.graph.security.userEvidence",
            **common,
            "userAccount": {
                "accountName": user,
                "domainName": "CONTOSO",
                "userSid": f"S-1-5-21-{fake.random_int(10**8, 10**9)}-1104",
                "azureAdUserId": fake.uuid4(),
                "userPrincipalName": f"{user}@contoso.com",
                "displayName": fake.name(),
            },
        },
        {
            "@odata.type": "#microsoft.graph.security.deviceEvidence",
            **common,
            "azureAdDeviceId": fake.uuid4(),
            "deviceDnsName": f"wks-{fake.random_int(100, 999)}.contoso.com",
            "osPlatform": "Windows11",
            "osBuild": 22631,
            "healthStatus": "active",
            "riskScore": "high",
            "mdeDeviceId": fake.sha1(),
        },
        {
            "@odata.type": "#microsoft.graph.security.processEvidence",
            **common,
            "processId": fake.random_int(1000, 9000),
            "parentProcessId": 4120,
            "processCommandLine": "invoice_scan.exe /silent",
            "imageFile": dropper,
        },
        {
            "@odata.type": "#microsoft.graph.security.fileEvidence",
            **common,
            "fileDetails": _file_details("update.dll", r"C:\Windows\Temp"),
        },
        {
            "@odata.type": "#microsoft.graph.security.fileHashEvidence",
            **common,
            "value": fake.sha256(),
            "algorithm": "sha256",
        },
        {
            "@odata.type": "#microsoft.graph.security.malwareEvidence",
            **common,
            "name": f"Trojan:Win32/{fake.word().capitalize()}!rfn",
            "category": "Trojan",
            "files": [
                {
                    "@odata.type": "#microsoft.graph.security.fileEvidence",
                    **common,
                    "fileDetails": dropper,
                }
            ],
        },
    ]


def _alert(incident_id: str, moment: datetime) -> dict:
    alert_id = (
        f"da{fake.numerify('###################')}_{fake.random_int(10**8, 10**9)}"
    )
    return {
        "id": alert_id,
        "providerAlertId": alert_id,
        "incidentId": incident_id,
        "status": "new",
        "severity": "high",
        "classification": None,
        "determination": None,
        "serviceSource": "microsoftDefenderForEndpoint",
        "detectionSource": "microsoftDefenderForEndpoint",
        "detectorId": fake.uuid4(),
        "tenantId": fake.uuid4(),
        "title": f"Suspicious {fake.word()} activity by {fake.word()}.exe",
        "description": fake.paragraph(),
        "recommendedActions": "Collect an investigation package and isolate "
        "the device.",
        "category": "Execution",
        "assignedTo": None,
        "alertWebUrl": f"https://security.microsoft.com/alerts/{alert_id}",
        "incidentWebUrl": f"https://security.microsoft.com/incidents/{incident_id}",
        "actorDisplayName": None,
        "threatDisplayName": None,
        "threatFamilyName": None,
        "mitreTechniques": ["T1059.001", "T1204.002"],
        "createdDateTime": graph_detailed_date(moment),
        "lastUpdateDateTime": graph_detailed_date(moment),
        "resolvedDateTime": None,
        "firstActivityDateTime": graph_detailed_date(moment),
        "lastActivityDateTime": graph_detailed_date(moment),
        "comments": [],
        "evidence": _evidence(moment),
    }


def _incident(number: int, moment: datetime) -> dict:
    incident_id = str(number)
    return {
        "id": incident_id,
        "incidentWebUrl": f"https://security.microsoft.com/incidents/{incident_id}",
        "redirectIncidentId": None,
        "displayName": f"Multi-stage incident on {fake.word()} endpoint "
        f"({fake.random_int(1000, 9999)})",
        "createdDateTime": graph_detailed_date(moment - timedelta(hours=2)),
        "lastUpdateDateTime": graph_detailed_date(moment),
        "assignedTo": fake.company_email() if number % 2 else None,
        "classification": "truePositive" if number % 2 else "unknown",
        "determination": "malware" if number % 2 else "unknown",
        "status": ["active", "inProgress", "resolved", "active"][number % 4],
        "severity": ["high", "medium", "low", "informational"][number % 4],
        "tags": [],
        "systemTags": [],
        "description": None,
        "customTags": [],
        "comments": [],
        "alerts": [_alert(incident_id, moment - timedelta(hours=1))],
    }


@router.get("/v1.0/security/incidents")
async def security_incidents(
    skiptoken: int = Query(0, alias="$skiptoken"),
) -> dict:
    """Pages of incidents (newest first) with their alerts expanded."""
    page = skiptoken + 1
    now = datetime.now(UTC)
    value = [
        _incident(
            400 - (page - 1) * INCIDENTS_PER_PAGE - index,
            now - timedelta(hours=3 * ((page - 1) * INCIDENTS_PER_PAGE + index) + 1),
        )
        for index in range(INCIDENTS_PER_PAGE)
    ]
    answer = {"@odata.context": f"{GRAPH}/$metadata#security/incidents", "value": value}
    if page < INCIDENT_PAGES:
        link = f"{GRAPH}/security/incidents"
        answer["@odata.nextLink"] = f"{link}?%24expand=alerts&%24skiptoken={page}"
    return answer


# -- Security: threat intelligence indicators (microsoft-graph-security-intel) --

# indicator id -> tiIndicator
TI_INDICATORS: dict[str, dict] = {}
TI_FIELDS = (
    "domainName",
    "url",
    "networkIPv4",
    "networkIPv6",
    "emailSenderAddress",
    "fileHashValue",
    "externalId",
)


def _unauthorized() -> JSONResponse:
    """What Graph answers to a request without a well-formed bearer token."""
    return JSONResponse(
        {
            "error": {
                "code": "InvalidAuthenticationToken",
                "message": "Access token is empty.",
                "innerError": {"request-id": str(uuid.uuid4())},
            }
        },
        status_code=401,
    )


def _bearer(request: Request) -> bool:
    authorization = request.headers.get("authorization", "")
    return authorization.startswith("Bearer ") and len(authorization) > 7


@router.get("/beta/security/tiIndicators")
async def ti_indicators_list(request: Request) -> Response:
    """The indicators, or those matching a ``field eq 'value'`` filter."""
    if not _bearer(request):
        return _unauthorized()
    found = list(TI_INDICATORS.values())
    filter_text = request.query_params.get("$filter", "")
    match = re.fullmatch(r"\s*(\w+) eq '((?:[^']|'')*)'\s*", filter_text)
    if match:
        field, value = match.group(1), match.group(2).replace("''", "'")
        found = [i for i in found if str(i.get(field)) == value]
    return JSONResponse(
        {
            "@odata.context": "https://graph.microsoft.com/beta/$metadata#security/tiIndicators",
            "value": found,
        }
    )


@router.post("/beta/security/tiIndicators")
async def ti_indicator_create(request: Request) -> Response:
    """Creates an indicator: the answer holds its identifier and ingestion time."""
    if not _bearer(request):
        return _unauthorized()
    body = await request.json()
    if not any(body.get(field) for field in TI_FIELDS if field != "externalId"):
        return JSONResponse(
            {
                "error": {
                    "code": "BadRequest",
                    "message": "At least one observable must be set.",
                }
            },
            status_code=400,
        )
    indicator = {
        "id": str(uuid.uuid4()),
        "azureTenantId": str(uuid.uuid4()),
        "isActive": True,
        "ingestedDateTime": graph_date(datetime.now(UTC)),
        "activityGroupNames": [],
        "killChain": [],
        "malwareFamilyNames": [],
        "knownFalsePositives": None,
        **body,
    }
    TI_INDICATORS[indicator["id"]] = indicator
    return JSONResponse(
        {
            "@odata.context": "https://graph.microsoft.com/beta/$metadata#security/tiIndicators/$entity",
            **indicator,
        },
        status_code=201,
    )


@router.patch("/beta/security/tiIndicators/{indicator_id}")
async def ti_indicator_update(indicator_id: str, request: Request) -> Response:
    if not _bearer(request):
        return _unauthorized()
    if indicator_id not in TI_INDICATORS:
        return JSONResponse(
            {"error": {"code": "NotFound", "message": "Indicator not found."}}, 404
        )
    TI_INDICATORS[indicator_id].update(await request.json())
    return Response(status_code=204)


@router.delete("/beta/security/tiIndicators/{indicator_id}")
async def ti_indicator_delete(indicator_id: str, request: Request) -> Response:
    if not _bearer(request):
        return _unauthorized()
    TI_INDICATORS.pop(indicator_id, None)
    return Response(status_code=204)
