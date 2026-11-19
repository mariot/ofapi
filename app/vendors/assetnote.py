"""Assetnote: the GraphQL API (assets, exposures) for the assetnote-import connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["*.assetnotecloud.com"]
router = APIRouter(prefix="/assetnote", tags=["Assetnote"])

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
TRIAGE_STATES = ["UNRESOLVED", "TRIAGED", "RESOLVED", "IGNORED"]
SIGNATURE_CLASSES = ["VULNERABILITY", "TPPE", "IOC", "HYGIENE"]


def _iso(days_ago: int) -> str:
    when = datetime.now(UTC) - timedelta(days=days_ago, minutes=fake.random_int(0, 600))
    return when.replace(microsecond=0).isoformat()


def _asset() -> dict:
    host = fake.domain_name()
    asset_id = fake.uuid4()
    return {
        "id": asset_id,
        "host": host,
        "assetType": fake.random_element(["DOMAIN", "SUBDOMAIN", "IP", "URL"]),
        "created": _iso(5),
        "onlineLastUpdated": _iso(0),
        "platformUrl": f"https://acme.assetnotecloud.com/assets/{asset_id}",
    }


def _interaction(tppe: bool) -> dict:
    if tppe:
        return {
            "created": _iso(0),
            "repository": f"{fake.user_name()}/{fake.word()}",
            "repositoryOwner": fake.user_name(),
            "commitHash": fake.sha1(),
            "patch": "@@ -1 +1 @@\n-token = 'x'\n+token = os.environ['TOKEN']",
        }
    return {
        "created": _iso(0),
        "request": "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nadmin panel",
    }


def _exposure(index: int) -> dict:
    signature_class = SIGNATURE_CLASSES[index % len(SIGNATURE_CLASSES)]
    cve = fake.cve_id() if signature_class == "VULNERABILITY" else None
    # Some exposures cite a known exploited product, mapped to software
    exploited = (
        {"product": fake.word().capitalize(), "vendorProject": fake.company()}
        if index % 2 == 0
        else None
    )
    return {
        "id": str(fake.random_int(1000, 99999)),
        "exposureType": "INDICATOR" if index == 3 else "VULNERABILITY",
        "created": _iso(3),
        "triageState": TRIAGE_STATES[index % len(TRIAGE_STATES)],
        "severityString": SEVERITIES[index % len(SEVERITIES)],
        "signature": {
            "name": f"{fake.word().capitalize()} {fake.word()} exposure {index}",
            "cve": cve,
            "signatureClass": signature_class,
            "description": fake.paragraph(),
            "recommendations": fake.paragraph(),
        },
        "asset": _asset(),
        "knownExploitation": exploited,
        "exposureData": {
            "edges": [
                {"node": _interaction(signature_class == "TPPE")}
                for _ in range(1 + index % 2)
            ]
        },
    }


@router.post("/api/v2/graphql")
async def graphql(request: Request) -> dict:
    """Assets or exposures, one short page (the last one)."""
    body = await request.json()
    query = body.get("query", "")
    if "exposures(" in query:
        nodes = [_exposure(i) for i in range(5)]
        return {"data": {"exposures": {"edges": [{"node": n} for n in nodes]}}}
    nodes = [_asset() for _ in range(5)]
    return {"data": {"assets": {"edges": [{"node": n} for n in nodes]}}}
