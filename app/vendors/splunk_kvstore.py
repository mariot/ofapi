"""Splunk KV store REST API (management port): collections and their records, read by
the OpenCTI splunk stream connector. The journal holds what the connector wrote."""

from fastapi import APIRouter, Request

HOSTS = ["splunk.staticfire.test"]
router = APIRouter(prefix="/splunk-kvstore", tags=["Splunk KV store"])

BASE = "/servicesNS/{owner}/{app}/storage/collections"


@router.post(BASE + "/config", status_code=201)
async def create_collection(owner: str, app: str, request: Request) -> dict:
    """A collection (form field ``name``); the connector only checks the status code."""
    form = await request.form()
    name = str(form.get("name", ""))
    return {
        "links": {"create": "/services/storage/collections/config/_new"},
        "entry": [{"name": name, "author": owner, "acl": {"app": app, "owner": owner}}],
    }


@router.post(BASE + "/data/{collection}", status_code=201)
async def create_record(collection: str, request: Request) -> dict:  # noqa: ARG001
    """A record; Splunk answers its key."""
    record = await request.json()
    return {"_key": record.get("_key")}


@router.put(BASE + "/data/{collection}/{key}")
async def update_record(
    collection: str,  # noqa: ARG001
    key: str,
    request: Request,
) -> dict:
    record = await request.json()
    return {"_key": record.get("_key", key)}


@router.delete(BASE + "/data/{collection}/{key}")
async def delete_record(collection: str, key: str) -> str:  # noqa: ARG001
    return ""
