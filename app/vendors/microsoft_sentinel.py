"""Microsoft Sentinel: the Log Analytics query API (incidents and alerts of a
workspace), the Sentinel threat intelligence upload API and the Azure management
API (indicator queries and deletions), read by the OpenCTI
microsoft-sentinel-incidents and microsoft-sentinel-intel connectors.

The tokens come from ``microsoft_identity``. ``SecurityIncident`` and ``SecurityAlert``
queries answer Log Analytics tables (``columns`` and ``rows``), honouring the time
filters and alert identifiers of the KQL text the connector sends. Indicators uploaded
to the threat intelligence API are kept to answer the management queries.
"""

import json
import re
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request, Response

from app.fake import fake

HOSTS = [
    "api.loganalytics.azure.com",
    "api.loganalytics.io",
    "api.ti.sentinel.azure.com",
    "management.azure.com",
]
router = APIRouter(prefix="/microsoft-sentinel", tags=["Microsoft Sentinel"])

INCIDENT_COLUMNS = [
    "TenantId",
    "TimeGenerated",
    "IncidentName",
    "Title",
    "Description",
    "Severity",
    "Status",
    "Classification",
    "ClassificationComment",
    "ClassificationReason",
    "Owner",
    "ProviderName",
    "ProviderIncidentId",
    "FirstActivityTime",
    "LastActivityTime",
    "FirstModifiedTime",
    "LastModifiedTime",
    "CreatedTime",
    "ClosedTime",
    "IncidentNumber",
    "RelatedAnalyticRuleIds",
    "AlertIds",
    "BookmarkIds",
    "Comments",
    "Tasks",
    "Labels",
    "IncidentUrl",
    "AdditionalData",
    "ModifiedBy",
    "SourceSystem",
    "Type",
]
ALERT_COLUMNS = [
    "TenantId",
    "TimeGenerated",
    "DisplayName",
    "AlertName",
    "AlertSeverity",
    "Description",
    "ProviderName",
    "VendorName",
    "VendorOriginalId",
    "SystemAlertId",
    "ResourceId",
    "SourceComputerId",
    "AlertType",
    "ConfidenceLevel",
    "ConfidenceScore",
    "IsIncident",
    "StartTime",
    "EndTime",
    "ProcessingEndTime",
    "RemediationSteps",
    "ExtendedProperties",
    "Entities",
    "SourceSystem",
    "WorkspaceSubscriptionId",
    "WorkspaceResourceGroup",
    "ExtendedLinks",
    "ProductName",
    "ProductComponentName",
    "AlertLink",
    "Status",
    "CompromisedEntity",
    "Tactics",
    "Techniques",
    "SubTechniques",
    "Type",
]
# alert id -> (alert row as a dict), for the alerts of the incidents served
ALERTS: dict[str, dict] = {}


def log_date(moment: datetime) -> str:
    """The seven fractional digits Log Analytics uses."""
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f0Z")


def parse_date(text: str) -> datetime:
    base, _, fraction = text.rstrip("Z").partition(".")
    moment = datetime.fromisoformat(f"{base}.{(fraction + '000000')[:6]}")
    return moment.replace(tzinfo=UTC)


def _entities() -> str:
    """The Entities column: a JSON document of entities referencing each other."""
    dropper = fake.sha256()
    entities = [
        {
            "$id": "3",
            "HostName": f"wks-{fake.random_int(100, 999)}",
            "DnsDomain": "contoso.com",
            "OSFamily": "Windows",
            "OSVersion": "11",
            "IsDomainJoined": True,
            "Type": "host",
        },
        {
            "$id": "4",
            "Name": fake.user_name(),
            "NTDomain": "CONTOSO",
            "Host": {"$ref": "3"},
            "Sid": "S-1-5-21-1004336348-1177238915-682003330-512",
            "IsDomainJoined": True,
            "Type": "account",
        },
        {"$id": "5", "Address": fake.ipv4_public(), "Type": "ip"},
        {"$id": "6", "Address": fake.ipv6(), "Type": "ip"},
        {
            "$id": "7",
            "Url": f"https://{fake.domain_name()}/{fake.slug()}.php",
            "Type": "url",
        },
        {
            "$id": "8",
            "Directory": r"C:\Users\Public\Downloads",
            "Name": "invoice_scan.exe",
            "FileHashes": [
                {
                    "$id": "9",
                    "Algorithm": "SHA256",
                    "Value": dropper,
                    "Type": "filehash",
                },
                {
                    "$id": "10",
                    "Algorithm": "MD5",
                    "Value": fake.md5(),
                    "Type": "filehash",
                },
            ],
            "Type": "file",
        },
        {
            "$id": "11",
            "ProcessId": str(fake.random_int(1000, 9000)),
            "CommandLine": "invoice_scan.exe /silent",
            "ImageFile": {"$ref": "8"},
            "Host": {"$ref": "3"},
            "Type": "process",
        },
        {
            "$id": "12",
            "Name": f"Trojan:Win32/{fake.word().capitalize()}!rfn",
            "Category": "Trojan",
            "CreatedTimeUtc": "2026-11-18T09:14:52.0000000",
            "Files": [{"$ref": "8"}],
            "Type": "malware",
        },
    ]
    return json.dumps(entities)


def _alert(moment: datetime) -> dict:
    alert_id = str(uuid.uuid4())
    alert = {
        "TenantId": "0b9a2c6e-6d1f-4c0e-9a57-3f2f1d7c8e11",
        "TimeGenerated": log_date(moment),
        "DisplayName": f"Suspicious {fake.word()} activity on {fake.word()} host",
        "AlertName": "Suspicious process execution",
        "AlertSeverity": "High",
        "Description": fake.paragraph(),
        "ProviderName": "MDATP",
        "VendorName": "Microsoft",
        "VendorOriginalId": f"da{fake.numerify('####################')}_1",
        "SystemAlertId": alert_id,
        "AlertType": "WindowsDefenderAv",
        "ConfidenceLevel": "Unknown",
        "IsIncident": False,
        "StartTime": log_date(moment - timedelta(minutes=20)),
        "EndTime": log_date(moment - timedelta(minutes=5)),
        "ProcessingEndTime": log_date(moment),
        "RemediationSteps": json.dumps(["Isolate the device.", "Reset credentials."]),
        "ExtendedProperties": json.dumps(
            {"Alert Link": "https://security.microsoft.com"}
        ),
        "Entities": _entities(),
        "SourceSystem": "Detection",
        "ProductName": "Microsoft Defender Advanced Threat Protection",
        "AlertLink": f"https://security.microsoft.com/alerts/{alert_id}",
        "Status": "New",
        "Tactics": "Execution, Persistence",
        "Techniques": json.dumps(["T1059", "T1547"]),
        "SubTechniques": json.dumps(["T1059.001"]),
        "Type": "SecurityAlert",
    }
    ALERTS[alert_id] = alert
    return alert


def _incident(number: int, moment: datetime) -> dict:
    alerts = [_alert(moment - timedelta(minutes=10)) for _ in range(2)]
    severity = ["High", "Medium", "Low"][number % 3]
    return {
        "TenantId": "0b9a2c6e-6d1f-4c0e-9a57-3f2f1d7c8e11",
        "TimeGenerated": log_date(moment),
        "IncidentName": str(uuid.uuid4()),
        "Title": f"Suspicious activity on {fake.word()} endpoint ({number})",
        "Description": fake.sentence(),
        "Severity": severity,
        "Status": "New",
        "Classification": "Undetermined",
        "ClassificationComment": "",
        "ClassificationReason": "",
        "Owner": json.dumps({"objectId": None, "email": None, "assignedTo": None}),
        "ProviderName": "Microsoft XDR",
        "ProviderIncidentId": str(number),
        "FirstActivityTime": log_date(moment - timedelta(hours=1)),
        "LastActivityTime": log_date(moment - timedelta(minutes=5)),
        "FirstModifiedTime": log_date(moment - timedelta(hours=1)),
        "LastModifiedTime": log_date(moment),
        "CreatedTime": log_date(moment - timedelta(hours=1)),
        "ClosedTime": "",
        "IncidentNumber": number,
        "RelatedAnalyticRuleIds": json.dumps([str(uuid.uuid4())]),
        "AlertIds": json.dumps([alert["SystemAlertId"] for alert in alerts]),
        "BookmarkIds": "[]",
        "Comments": "[]",
        "Tasks": "[]",
        "Labels": json.dumps([{"labelName": "phishing", "labelType": "User"}]),
        "IncidentUrl": f"https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/{number}",
        "AdditionalData": json.dumps(
            {
                "alertsCount": len(alerts),
                "bookmarksCount": 0,
                "commentsCount": 0,
                "alertProductNames": ["Microsoft Defender Advanced Threat Protection"],
                "tactics": ["Execution"],
                "techniques": ["T1059"],
            }
        ),
        "ModifiedBy": "Microsoft XDR",
        "SourceSystem": "Azure",
        "Type": "SecurityIncident",
    }


def _table(columns: list[str], items: list[dict]) -> dict:
    types = {"IncidentNumber": "int", "IsIncident": "bool"}
    return {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": name, "type": types.get(name, "string")}
                    for name in columns
                ],
                "rows": [[item.get(name, "") for name in columns] for item in items],
            }
        ]
    }


@router.post("/v1/workspaces/{workspace_id}/query")
async def query(request: Request) -> dict:
    """A KQL query on ``SecurityIncident`` (3 incidents modified after the given time)
    or ``SecurityAlert`` (the alerts asked by id, generated after the given time)."""
    text = (await request.json()).get("query", "")
    after = re.search(r"todatetime\('([^']+)'\)", text)
    threshold = (
        parse_date(after.group(1)) if after else datetime.min.replace(tzinfo=UTC)
    )
    if text.startswith("SecurityAlert"):
        ids = re.findall(r'"([0-9a-f-]{36})"', text)
        alerts = [
            ALERTS[key]
            for key in ids
            if key in ALERTS and parse_date(ALERTS[key]["TimeGenerated"]) > threshold
        ]
        return _table(ALERT_COLUMNS, alerts)
    now = datetime.now(UTC)
    incidents = [
        _incident(1100 + index, now - timedelta(hours=6 * (3 - index)))
        for index in range(3)
    ]
    return _table(
        INCIDENT_COLUMNS,
        [i for i in incidents if parse_date(i["LastModifiedTime"]) > threshold],
    )


# indicator id (resource endpoint) -> the STIX indicator uploaded
INDICATORS: dict[str, dict] = {}


@router.post("/workspaces/{workspace_id}/threat-intelligence-stix-objects:upload")
async def upload_stix_objects(request: Request) -> dict:
    """Keeps the indicators of the upload to answer later queries."""
    body = await request.json()
    for stix_object in body.get("stixobjects", []):
        if stix_object.get("type") == "indicator":
            endpoint = (
                "/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/"
                "default/providers/Microsoft.OperationalInsights/workspaces/"
                f"staticfire/providers/Microsoft.SecurityInsights/threatIntelligence/"
                f"main/indicators/{uuid.uuid4()}"
            )
            INDICATORS[endpoint] = {
                "stix_id": stix_object.get("id"),
                "source": body.get("sourcesystem"),
            }
    return {"errors": []}


@router.post(
    "/subscriptions/{subscription_id}/resourceGroups/{group}/providers/"
    "Microsoft.OperationalInsights/workspaces/{workspace}/providers/"
    "Microsoft.SecurityInsights/threatIntelligence/main/query"
)
async def query_indicators(request: Request) -> dict:
    """The indicators of the clauses (a STIX id and a source system)."""
    clauses = (await request.json()).get("condition", {}).get("clauses", [])
    wanted = {c["field"]: c["values"][0] for c in clauses if c.get("values")}
    return {
        "value": [
            {
                "id": endpoint,
                "name": endpoint.rsplit("/", 1)[-1],
                "type": "Microsoft.SecurityInsights/threatIntelligence",
                "kind": "indicator",
                "properties": {"source": found["source"]},
            }
            for endpoint, found in INDICATORS.items()
            if found["stix_id"] == wanted.get("id")
            and found["source"] == wanted.get("source")
        ]
    }


@router.delete(
    "/subscriptions/{subscription_id}/resourceGroups/{group}/providers/"
    "Microsoft.OperationalInsights/workspaces/{workspace}/providers/"
    "Microsoft.SecurityInsights/threatIntelligence/main/indicators/{indicator}"
)
async def delete_indicator(request: Request) -> Response:
    indicator = request.path_params["indicator"]
    for endpoint in list(INDICATORS):
        if endpoint.endswith(indicator):
            del INDICATORS[endpoint]
    return Response(status_code=200)
