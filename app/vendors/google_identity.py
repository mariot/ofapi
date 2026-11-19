"""Google identity endpoints shared by every connector using a Google client library:
the OAuth2 token endpoint (service account JWT-bearer grant, refresh and authorization
code grants) at ``oauth2.googleapis.com`` and ``accounts.google.com``.

An ID token is answered when the assertion asks for a ``target_audience``. The
OpenAEV Gmail fake (``/google-oauth2`` in ``app/main.py``) is a separate route."""

import base64
import json
import time

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["oauth2.googleapis.com", "accounts.google.com"]
router = APIRouter(prefix="/google-identity", tags=["Google identity"])


def _b64(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _claims(assertion: str) -> dict:
    """The (unverified) claims of a JWT assertion."""
    try:
        payload = assertion.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return {}


async def _grant(request: Request) -> dict:
    form = await request.form()
    claims = _claims(str(form.get("assertion", "")))
    token = {
        "access_token": f"ya29.{fake.pystr(60, 60)}",
        "expires_in": 3599,
        "token_type": "Bearer",
    }
    if scope := claims.get("scope") or form.get("scope"):
        token["scope"] = scope
    if form.get("grant_type") == "authorization_code":
        token["refresh_token"] = f"1//{fake.pystr(60, 60)}"
    if audience := claims.get("target_audience"):
        now = int(time.time())
        token["id_token"] = ".".join(
            [
                _b64({"alg": "RS256", "typ": "JWT"}),
                _b64(
                    {
                        "iss": "https://accounts.google.com",
                        "aud": audience,
                        "sub": claims.get("sub", claims.get("iss", "")),
                        "iat": now,
                        "exp": now + 3599,
                    }
                ),
                fake.pystr(40, 40),
            ]
        )
    return token


@router.post("/token")
async def token(request: Request) -> dict:
    """oauth2.googleapis.com/token: every grant type gets a fresh bearer token."""
    return await _grant(request)


@router.post("/o/oauth2/token")
async def legacy_token(request: Request) -> dict:
    """accounts.google.com/o/oauth2/token, the legacy token URI of old key files."""
    return await _grant(request)


@router.get("/oauth2/v1/certs")
async def certs() -> dict:
    """The (empty) public certificates of the service accounts."""
    return {}


@router.get("/.well-known/openid-configuration")
async def openid_configuration() -> dict:
    return {
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
    }
