"""Microsoft Defender for Endpoint (api.securitycenter.microsoft.com): the custom
indicators API (``/api/indicators``) and the machine groups (RBAC) of the exposure
score, read by the OpenCTI microsoft-defender-intel and
microsoft-defender-intel-synchronizer connectors.

Indicators are kept in memory: created through ``POST /api/indicators`` or
``/import``, listed and filtered by value with OData, deleted one by one or in batches.
The tokens come from ``microsoft_identity``.
"""

import json
import re
from datetime import UTC, datetime
from urllib.parse import unquote

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["api.securitycenter.microsoft.com", "api.security.microsoft.com"]
router = APIRouter(prefix="/microsoft-defender", tags=["Microsoft Defender"])

MACHINE_GROUPS = [(0, "UnassignedGroup"), (3, "Default Group"), (7, "Production")]
# indicator id -> indicator
INDICATORS: dict[str, dict] = {}


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _indicator(body: dict) -> dict:
    """The stored form of an indicator sent by an application."""
    indicator = {
        "id": str(fake.random_int(10_000, 9_999_999)),
        "indicatorValue": body.get("indicatorValue"),
        "indicatorType": body.get("indicatorType"),
        "action": body.get("action"),
        "application": body.get("application"),
        "source": "staticfire-app",
        "sourceType": "AadApp",
        "title": body.get("title"),
        "creationTimeDateTimeUtc": now(),
        "createdBy": fake.uuid4(),
        "createdByDisplayName": "staticfire-app",
        "createdByExternalId": None,
        "expirationTime": body.get("expirationTime"),
        "lastUpdateTime": body.get("lastUpdateTime") or now(),
        "lastUpdatedBy": "staticfire-app",
        "severity": body.get("severity"),
        "description": body.get("description"),
        "recommendedActions": body.get("recommendedActions"),
        "rbacGroupNames": body.get("rbacGroupNames", []),
        "rbacGroupIds": body.get("rbacGroupIds", []),
        "generateAlert": body.get("generateAlert", False),
        "educateUrl": body.get("educateUrl"),
        "externalId": body.get("externalId"),
        "historicalDetectionAction": None,
        "mitreTechniques": [],
        "category": None,
    }
    if body.get("id") in INDICATORS:
        indicator["id"] = body["id"]
    INDICATORS[indicator["id"]] = indicator
    return indicator


@router.get("/api/indicators")
async def list_indicators(
    filter: str = Query("", alias="$filter"),
    top: int = Query(10000, alias="$top"),
) -> dict:
    """The indicators, or those whose value equals the one of an ``$filter``."""
    found = list(INDICATORS.values())
    match = re.search(r"indicatorValue eq '((?:[^']|'')*)'", unquote(filter))
    if match:
        value = match.group(1).replace("''", "'")
        found = [i for i in found if i["indicatorValue"] == value]
    return {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Indicators",
        "value": found[:top],
    }


@router.post("/api/indicators")
async def submit_indicator(request: Request) -> Response:
    """Creates (or, with a known ``id``, updates) an indicator; 400 without a body."""
    raw = await request.body()
    if not raw.strip():
        return JSONResponse(
            {
                "error": {
                    "code": "BadRequest",
                    "message": "Request body is missing or not a valid indicator.",
                }
            },
            status_code=400,
        )
    body = json.loads(raw)
    return JSONResponse(
        {
            "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Indicators/$entity",
            **_indicator(body),
        }
    )


@router.post("/api/indicators/import")
async def import_indicators(request: Request) -> dict:
    """Creates a list of indicators, each reported with its identifier."""
    items = (await request.json()).get("Indicators", [])
    value = []
    for item in items:
        indicator = _indicator(item)
        value.append(
            {
                "id": indicator["id"],
                "indicator": indicator["indicatorValue"],
                "isFailed": False,
                "failureReason": None,
            }
        )
    return {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Collection(microsoft.windowsDefenderATP.api.ImportIndicatorResult)",
        "value": value,
    }


@router.post("/api/indicators/BatchDelete")
async def batch_delete(request: Request) -> dict:
    ids = (await request.json()).get("IndicatorIds", [])
    for indicator_id in ids:
        INDICATORS.pop(str(indicator_id), None)
    return {"value": [{"id": str(i), "isFailed": False} for i in ids]}


@router.delete("/api/indicators/{indicator_id}")
async def delete_indicator(indicator_id: str) -> Response:
    INDICATORS.pop(indicator_id, None)
    return Response(status_code=204)


@router.get("/api/exposureScore/ByMachineGroups")
async def machine_groups(
    top: int = Query(10, alias="$top"), skip: int = Query(0, alias="$skip")
) -> dict:
    """The machine groups with their exposure score; the connector reads the groups."""
    groups = MACHINE_GROUPS[skip : skip + top]
    return {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#ExposureScore",
        "@odata.count": len(MACHINE_GROUPS),
        "value": [
            {
                "time": now(),
                "score": 38.4,
                "rbacGroupName": name,
                "rbacGroupId": str(group_id),
            }
            for group_id, name in groups
        ],
    }
