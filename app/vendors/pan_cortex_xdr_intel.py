"""Palo Alto Cortex XDR IOC API (insert, get and delete indicators), read by the OpenCTI
pan-cortex-xdr-intel stream connector. The alert routes of the OpenAEV collectors live
elsewhere, under another host and prefix."""

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["api-staticfire.xdr.us.paloaltonetworks.com"]
router = APIRouter(prefix="/pan-cortex-xdr-intel", tags=["Palo Alto Cortex XDR IOCs"])

# IOCs inserted since the last reset, by indicator: the rule id Cortex XDR assigned
_iocs: dict[str, dict] = {}


@router.post("/public_api/v1/indicators/get")
async def get_iocs(request: Request) -> dict:
    """The IOCs already inserted among the indicators asked."""
    body = await request.json()
    values: list[str] = []
    for item in body["request_data"]["filters"]:
        value = item["value"]
        values.extend(value if isinstance(value, list) else [value])
    objects = [_iocs[v] for v in values if v in _iocs]
    return {"objects_count": len(objects), "objects": objects}


@router.post("/public_api/v1/indicators/insert")
async def insert_iocs(request: Request) -> dict:
    """Created, or updated when the request carries the rule id of an existing IOC."""
    body = await request.json()
    added, updated = [], []
    for ioc in body["request_data"]:
        rule_id = ioc.get("rule_id")
        if rule_id is None:
            rule_id = fake.random_int(10_000, 99_999)
            added.append({"id": rule_id, "status": "Created"})
        else:
            updated.append({"id": rule_id, "status": "Updated"})
        _iocs[ioc["indicator"]] = {
            "rule_id": rule_id,
            "indicator": ioc["indicator"],
            "type": ioc["type"],
            "severity": ioc.get("severity"),
            "reputation": ioc.get("reputation"),
        }
    return {"added_objects": added, "updated_objects": updated}


@router.post("/public_api/v1/indicators/delete")
async def delete_iocs(request: Request) -> dict:
    body = await request.json()
    deleted = 0
    for item in body["request_data"]["filters"]:
        value = item["value"]
        for v in value if isinstance(value, list) else [value]:
            deleted += _iocs.pop(v, None) is not None
    return {"deleted_objects": deleted}
