"""FortiEDR Central Manager: IP Sets (fortiedr stream connector)."""

from fastapi import APIRouter, HTTPException, Request

HOSTS = ["*.console.ensilo.com"]
router = APIRouter(prefix="/fortiedr", tags=["FortiEDR"])

IP_SETS: dict[str, dict] = {}


def _check_auth(request: Request) -> None:
    if not request.headers.get("authorization", "").startswith("Basic "):
        raise HTTPException(401, "authentication required")


@router.get("/management-rest/ip-sets/list-ip-sets")
async def list_ip_sets(request: Request) -> list[dict]:
    """The IP sets of the organization, each with its included addresses."""
    _check_auth(request)
    return list(IP_SETS.values())


@router.post("/management-rest/ip-sets/create-ip-set")
async def create_ip_set(request: Request) -> dict:
    _check_auth(request)
    body = await request.json()
    if body["name"] in IP_SETS:
        raise HTTPException(409, "IP set already exists")
    IP_SETS[body["name"]] = {
        "name": body["name"],
        "description": "",
        "include": body.get("include", []),
        "exclude": body.get("exclude", []),
    }
    return {"name": body["name"]}


@router.put("/management-rest/ip-sets/update-ip-set")
async def update_ip_set(request: Request) -> dict:
    _check_auth(request)
    body = await request.json()
    if body["name"] not in IP_SETS:
        raise HTTPException(404, "IP set not found")
    IP_SETS[body["name"]]["include"] = body.get("include", [])
    return {"name": body["name"]}
