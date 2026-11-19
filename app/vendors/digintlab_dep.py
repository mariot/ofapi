"""DigIntLab Double Extortion Platform: Cognito USER_PASSWORD_AUTH login and the
ransomware announcements list, read by the OpenCTI digintlab-dep connector.

The connector's login endpoint is set to ``cognito.digintlab.staticfire.test``: the real
Cognito host answers the SRP flow of another vendor's fake.
"""

import base64
import json
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Header, HTTPException, Request

from app.fake import fake

HOSTS = ["api.eu-ep1.doubleextortion.com", "cognito.digintlab.staticfire.test"]
router = APIRouter(prefix="/digintlab-dep", tags=["DigIntLab DEP"])

DATA_TYPES = ["CUSTOMERS", "EMPLOYEES", "FINANCIAL", "PII", "SENSITIVES"]


def _jwt(claims: dict) -> str:
    def part(data: dict) -> str:
        raw = json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{part({'alg': 'none'})}.{part(claims)}.{secrets.token_urlsafe(16)}"


@router.post("/")
async def cognito(request: Request) -> dict:
    """InitiateAuth with USER_PASSWORD_AUTH answers the tokens directly."""
    action = request.headers.get("X-Amz-Target", "").rsplit(".", 1)[-1]
    body = await request.json()
    if action != "InitiateAuth" or body.get("AuthFlow") != "USER_PASSWORD_AUTH":
        raise HTTPException(400, "Unsupported action")
    now = int(datetime.now(UTC).timestamp())
    claims = {"sub": fake.uuid4(), "token_use": "id", "iat": now, "exp": now + 3600}
    return {
        "ChallengeParameters": {},
        "AuthenticationResult": {
            "AccessToken": _jwt({**claims, "token_use": "access"}),
            "IdToken": _jwt(claims),
            "RefreshToken": secrets.token_urlsafe(48),
            "ExpiresIn": 3600,
            "TokenType": "Bearer",
        },
    }


def _announcement(index: int) -> dict:
    day = datetime.now(UTC) - timedelta(days=index % 5)
    domain = fake.domain_name()
    return {
        "date": day.strftime("%Y-%m-%d"),
        "hashid": fake.sha256() if index % 2 else fake.md5(),
        "victim": fake.company(),
        "sector": fake.industry_sector(),
        "actor": "Unknown" if index == 4 else fake.intrusion_set(),
        "country": fake.country(),
        "revenue": f"${fake.random_int(1, 900)}M",
        "site": f"https://{domain}/",
        "annLink": f"https://leaks.example.org/post/{fake.uuid4()}",
        "annTitle": f"{domain} data published",
        "victimDomain": domain,
        "annDescription": fake.paragraph(nb_sentences=2),
        "annDataTypes": fake.random_elements(DATA_TYPES, length=2, unique=True),
    }


@router.get("/v1/dbtr/privlist")
async def privlist(
    ts: str,
    te: str,
    dset: str = "ext",
    full: str = "false",  # noqa: ARG001
    extended: str = "false",  # noqa: ARG001
    x_api_key: str | None = Header(None),
    authorization: str | None = Header(None),
) -> list[dict]:
    """Announcements between two dates: a JSON array, the dataset ``ext`` only."""
    if not x_api_key or not authorization:
        raise HTTPException(403, "Forbidden")
    if dset != "ext" or te < ts:
        return []
    items = [_announcement(i) for i in range(6)]
    # a leak whose victim is unknown: skipped by the connector
    items.append({**_announcement(6), "victim": "N/A"})
    return items
