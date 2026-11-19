"""Metras EDR API (``X-API-KEY`` header): EDR alerts, binary inventory, endpoints and
custom blocklists, read by the OpenCTI metras-feed, metras-enrichment and metras-stream
connectors."""

import uuid

from fastapi import APIRouter, Query, Request

from app.fake import fake

HOSTS = ["api.metras.sa"]
router = APIRouter(prefix="/metras", tags=["Metras"])

TOTAL = 7
# the datasets of the paged lists, drawn at the first page so that pages agree
DATA: dict[str, list[dict]] = {}
BLOCKLISTS: dict[str, dict] = {}


def _endpoint(ip: str | None = None) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "name": f"{fake.word()}-{fake.random_int(10, 99)}.corp.local",
        "os": fake.random_element(["windows", "linux", "darwin"]),
        "serial": fake.bothify("SN-########"),
        "status": "activated",
        "sc_connection_info": {"tunnel_ip": fake.ipv4_private()},
        "nw_info": {
            "interfaces": [{"name": "eth0", "ips": [ip or fake.ipv4_private()]}]
        },
    }


def _alert(agent_ip: str | None = None) -> dict:
    name = fake.random_element(
        ["Suspicious PowerShell", "Credential dumping", "Ransomware behaviour"]
    )
    return {
        "id": str(uuid.uuid4()),
        "alert_name": name,
        "alert_source_name": "EDR 2.0",
        "type": "Behavioral",
        "endpoint_id": str(uuid.uuid4()),
        "endpoint_name": f"{fake.word()}-{fake.random_int(10, 99)}.corp.local",
        "agent_ip": agent_ip or fake.ipv4_private(),
        "occurrence_count": fake.random_int(1, 20),
        "risk_score": fake.random_int(40, 100),
        "severity": fake.random_element(["critical", "high", "medium", 4, 3]),
        "process": {"name": "powershell.exe", "guid": str(uuid.uuid4())},
        "mitre_ids": ["T1059.001", "T1003"],
        "tags": ["edr", "staticfire"],
        "url": fake.url(),
        "last_occurrence_time": fake.date_time_between("-3h", "now").strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    }


def _binary(sha256: str | None = None, sha1: str | None = None) -> dict:
    seen = fake.date_time_between("-3d", "now").strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "md5": fake.md5(),
        "sha1": sha1 or fake.sha1(),
        "sha256": sha256 or fake.sha256(),
        "name": f"{fake.word()}.exe",
        "file_size_bytes": fake.random_int(8192, 4_000_000),
        "runnability_status": fake.random_element(["banned", "allowed"]),
        "signature_status": fake.random_element(["unsigned", "signed"]),
        "publisher": fake.company(),
        "signer": fake.company(),
        "first_endpoint_name": f"{fake.word()}-{fake.random_int(10, 99)}.corp.local",
        "first_seen": seen,
        "last_seen": seen,
    }


def _page(name: str, make, limit: int, skip: int) -> list[dict]:
    if skip == 0 or name not in DATA:
        DATA[name] = [make() for _ in range(TOTAL)]
    return DATA[name][skip : skip + limit]


@router.get("/api/v1/endpoints")
async def endpoints(interface_ip: str | None = Query(None)) -> dict:
    """The inventory; with ``interface_ip``, the endpoint holding that address."""
    if interface_ip:
        return {"endpoints": [_endpoint(interface_ip)]}
    return {"endpoints": [_endpoint() for _ in range(4)]}


@router.get("/api/v1/edr/alerts")
async def alerts(
    limit: int = Query(50),
    skip: int = Query(0),
    agent_ip: str | None = Query(None),
) -> dict:
    """Pages of alerts, ``more`` telling whether another page follows."""
    if agent_ip:
        return {
            "totalCount": 2,
            "more": False,
            "data": [_alert(agent_ip), _alert(agent_ip)],
        }
    data = _page("alerts", _alert, limit, skip)
    return {"totalCount": TOTAL, "more": skip + limit < TOTAL, "data": data}


@router.get("/api/v1/edr/binary/list")
async def binaries(
    limit: int = Query(50),
    skip: int = Query(0),
    query: str | None = Query(None),
) -> dict:
    """Pages of binaries; ``query=sha256:<hash>`` looks one up."""
    if query and ":" in query:
        algo, value = query.split(":", 1)
        found = _binary(**{algo: value}) if algo in ("sha256", "sha1") else _binary()
        return {"totalCount": 1, "data": [found]}
    return {"totalCount": TOTAL, "data": _page("binaries", _binary, limit, skip)}


@router.get("/api/v1/edr/binary/details")
async def binary_details(md5: str | None = Query(None)) -> dict:
    return {"totalCount": 1, "data": [{**_binary(), "md5": md5 or fake.md5()}]}


@router.get("/api/v1/custom-blocklist")
async def list_blocklists(name: str | None = Query(None)) -> dict:
    return {
        "data": [item for item in BLOCKLISTS.values() if name in (None, item["name"])]
    }


@router.post("/api/v1/custom-blocklist")
async def create_blocklists(request: Request) -> dict:
    created = []
    for item in await request.json():
        item = {**item, "id": str(uuid.uuid4())}
        BLOCKLISTS[item["id"]] = item
        created.append(item)
    return {"data": created}


@router.patch("/api/v1/custom-blocklist/{blocklist_id}")
async def update_blocklist(blocklist_id: str, request: Request) -> dict:
    item = BLOCKLISTS.setdefault(blocklist_id, {"id": blocklist_id})
    item.update(await request.json())
    return {"data": [item]}


@router.delete("/api/v1/custom-blocklist/{blocklist_id}")
async def delete_blocklist(blocklist_id: str) -> dict:
    BLOCKLISTS.pop(blocklist_id, None)
    return {}
