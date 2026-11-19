"""Microsoft identity platform (login.microsoftonline.com): what MSAL and azure-identity
ask before calling an API: instance discovery, OpenID discovery and the token endpoints.

Shared by every connector authenticating to Microsoft (email-intel-microsoft, and the
Defender, Sentinel or Graph security connectors to come). The discovery documents point
back at the real host, so the token requests go through the proxy too. Tokens are
unsigned JWTs, accepted by the Graph fake (``microsoft_graph``).

The older ``/microsoft-identity`` routes of ``app/main.py`` (OpenAEV injectors) build
their discovery document from the request URL and are not reachable by host: they stay
as they are.
"""

from dataclasses import asdict

from fastapi import APIRouter, Form, Request

from app.api.microsoft import (
    TokenResponseFactory,
    fake_access_token,
    openid_configuration,
)

HOSTS = ["login.microsoftonline.com", "login.windows.net", "login.microsoft.com"]
router = APIRouter(prefix="/microsoft-login", tags=["Microsoft Identity"])

AUTHORITY = "https://login.microsoftonline.com"


def audience_of(scope: str) -> str:
    """The resource a scope such as ``https://graph.microsoft.com/.default`` is for."""
    first = (scope or "https://graph.microsoft.com/.default").split(" ")[0]
    return first.removesuffix("/.default").rstrip("/")


@router.get("/{tenant_id}/v2.0/.well-known/openid-configuration")
@router.get("/{tenant_id}/.well-known/openid-configuration")
async def openid_discovery(tenant_id: str) -> dict:
    """The OpenID Connect discovery document of a tenant, pointing at the real host."""
    return openid_configuration(AUTHORITY, tenant_id)


@router.get("/{tenant_id}/discovery/instance")
async def instance_discovery(request: Request) -> dict:
    """The instance metadata MSAL fetches to validate an authority."""
    endpoint = request.query_params.get("authorization_endpoint", "")
    tenant = endpoint.split("/")[3] if endpoint.count("/") >= 4 else "common"
    return {
        "tenant_discovery_endpoint": (
            f"{AUTHORITY}/{tenant}/v2.0/.well-known/openid-configuration"
        ),
        "api-version": "1.1",
        "metadata": [
            {
                "preferred_network": "login.microsoftonline.com",
                "preferred_cache": "login.windows.net",
                "aliases": [
                    "login.microsoftonline.com",
                    "login.windows.net",
                    "login.microsoft.com",
                    "sts.windows.net",
                ],
            }
        ],
    }


@router.get("/{tenant_id}/discovery/v2.0/keys")
async def signing_keys() -> dict:
    """No signing key: the tokens are never validated."""
    return {"keys": []}


@router.post("/{tenant_id}/oauth2/v2.0/token")
@router.post("/{tenant_id}/oauth2/token")
async def token(tenant_id: str, scope: str = Form("")) -> dict:
    """A fresh token for any grant (client credentials, refresh token...) and secret."""
    resource = audience_of(scope)
    return asdict(
        TokenResponseFactory(
            scope=scope or f"{resource}/.default",
            access_token=fake_access_token(tenant_id, resource),
        )
    )
