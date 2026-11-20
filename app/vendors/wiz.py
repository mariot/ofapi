"""Wiz: the public cloud threat landscape STIX feed (www.wiz.io), read by the OpenCTI
wiz connector, and the tenant GraphQL API with its OAuth2 token endpoint, read by the
wiz-cloud connector."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["www.wiz.io", "auth.app.wiz.io", "api.*.app.wiz.io"]
router = APIRouter(prefix="/wiz", tags=["Wiz"])

ISSUES = 5
RESOURCES = [
    ("VIRTUAL_MACHINE", "AWS"),
    ("SERVICE_ACCOUNT", "GCP"),
    ("CONTAINER_IMAGE", "Azure"),
    ("ACCESS_KEY", "AWS"),
    ("SUBSCRIPTION", "Azure"),
]
TACTICS = [
    ("TA0042", "Resource Development", "T1587.001", "Develop Capabilities: Malware"),
    ("TA0001", "Initial Access", "T1078", "Valid Accounts"),
    ("TA0006", "Credential Access", "T1552.001", "Credentials In Files"),
]
STATE: dict[str, list] = {"issues": []}


@router.get("/api/feed/cloud-threat-landscape/stix.json")
async def threat_landscape() -> dict:
    """The cloud threat landscape: actors, malware, tools and techniques."""
    actors = [fake.stix_threat_actor() for _ in range(2)]
    malwares = [fake.stix_malware() for _ in range(2)]
    # a malware without type comes with an empty string in this feed
    malwares[1]["malware_types"] = [""]
    tool = fake.stix_tool()
    pattern = fake.stix_attack_pattern()
    objects = [*actors, *malwares, tool, pattern]
    objects += [
        fake.stix_relationship(actors[0]["id"], malwares[0]["id"], "uses"),
        fake.stix_relationship(actors[1]["id"], tool["id"], "uses"),
        fake.stix_relationship(actors[1]["id"], pattern["id"], "uses"),
    ]
    return fake.stix_bundle(objects)


@router.post("/oauth/token")
async def token() -> dict:
    """OAuth2 client credentials."""
    return {
        "access_token": fake.sha256(),
        "token_type": "Bearer",
        "expires_in": 86399,
        "scope": "read:all",
    }


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _issue(index: int) -> dict:
    kind, cloud = RESOURCES[index % len(RESOURCES)]
    created = datetime.now(UTC) - timedelta(hours=ISSUES - index)
    issue_id = str(uuid4())
    account = fake.numerify("############")
    sub_categories = []
    for tactic_id, tactic, technique_id, title in TACTICS[: 1 + index % 3]:
        sub_categories.append(
            {
                "title": title,
                "externalId": f"{tactic_id}-{technique_id}",
                "description": title,
                "category": {
                    "name": tactic,
                    "description": tactic,
                    "framework": {"name": "MITRE ATT&CK Matrix"},
                },
            }
        )
    sub_categories.append(
        {
            "title": "Cloud Risk",
            "externalId": "3.1",
            "description": "",
            "category": {
                "name": "Threat",
                "description": "",
                "framework": {"name": "Wiz Risk Model"},
            },
        }
    )
    rule = {
        "name": f"Suspicious {fake.word()} activity",
        "securitySubCategories": sub_categories,
    }
    return {
        "id": issue_id,
        "type": "THREAT_DETECTION",
        "severity": ["CRITICAL", "HIGH"][index % 2],
        "status": "OPEN" if index % 2 else "IN_PROGRESS",
        "createdAt": _stamp(created),
        "updatedAt": _stamp(created + timedelta(minutes=5)),
        "firstEventAt": _stamp(created - timedelta(minutes=30)),
        "lastEventAt": _stamp(created - timedelta(minutes=2)),
        "description": "" if index == 2 else "A resource showed suspicious activity.",
        "openReason": None,
        "url": f"https://app.wiz.io/issues#~(issue~'{issue_id})",
        "entitySnapshot": {
            "id": str(uuid4()),
            "name": f"{fake.word()}-{fake.random_int(10, 99)}",
            "type": kind,
            "externalId": f"arn:aws:ec2:eu-west-1:{account}:instance/{fake.md5()[:8]}",
            "cloudPlatform": cloud,
            "cloudProviderURL": "",
            "providerId": "",
            "region": "eu-west-1",
            "tags": {"env": "prod", "Wiz/wz": "1"},
        },
        "sourceRules": None if index == 4 else [rule],
        "threatDetectionDetails": {
            "actors": [
                {
                    "id": str(uuid4()),
                    "name": fake.user_name(),
                    "externalId": fake.user_name(),
                    "providerUniqueId": fake.user_name(),
                    "type": "USER_ACCOUNT",
                }
            ]
        },
    }


def _finding(asset: str, name: str) -> dict:
    return {
        "id": str(uuid4()),
        "name": fake.cve_id(),
        "description": "The package is vulnerable.",
        "CVEDescription": fake.sentence(),
        "CVSSSeverity": "HIGH",
        "score": 8.1,
        "severity": "HIGH",
        "status": "OPEN",
        "hasCisaKevExploit": False,
        "hasExploit": True,
        "isEffectiveSsvcAutomatable": True,
        "effectiveSsvcTechnicalImpact": "TOTAL",
        "portalUrl": "https://app.wiz.io/vulnerability-findings",
        "firstDetectedAt": _stamp(datetime.now(UTC) - timedelta(days=2)),
        "lastDetectedAt": _stamp(datetime.now(UTC) - timedelta(hours=3)),
        "epssPercentile": 72.4,
        "epssProbability": 3.2,
        "cvssv2": None,
        "cvssv3": {
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "HIGH",
            "exploitCodeMaturity": "FUNCTIONAL",
            "userInteractionRequired": False,
            "scope": "UNCHANGED",
        },
        "cvssv4": None,
        "vulnerableAsset": {
            "id": asset,
            "type": "VIRTUAL_MACHINE",
            "name": name,
            "region": "eu-west-1",
            "providerUniqueId": None,
            "cloudProviderURL": "",
            "cloudPlatform": "AWS",
            "status": "Active",
            "tags": {},
        },
    }


def _connection(nodes: list[dict], variables: dict, key: str) -> dict:
    """One cursor page: the cursor is the offset of the next node."""
    size = variables.get("first") or 50
    start = int(variables.get("after") or 0)
    end = start + size
    page = {"hasNextPage": end < len(nodes), "endCursor": str(end)}
    connection = {"nodes": nodes[start:end], "pageInfo": page, "totalCount": len(nodes)}
    return {key: connection}


# the connector posts to the URL with a trailing slash
@router.post("/graphql/")
@router.post("/graphql")
async def graphql(request: Request) -> dict:
    """The issues and vulnerability findings queries of the connector."""
    body = await request.json()
    variables = body.get("variables") or {}
    if "VulnerabilityFindingsPage" in body.get("query", ""):
        asset = variables["filterBy"]["assetIdV2"]["equals"][0]
        findings = [_finding(asset, "asset") for _ in range(2)]
        return {"data": _connection(findings, variables, "vulnerabilityFindings")}
    if not variables.get("after"):
        STATE["issues"] = [_issue(index) for index in range(ISSUES)]
    return {"data": _connection(STATE["issues"], variables, "issues")}
