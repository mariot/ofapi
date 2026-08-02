"""Factories for the Microsoft identity platform and Microsoft Graph.

Two OpenAEV injectors rely on these:

* ``email-m365`` acquires an application token through MSAL and then calls
  ``POST /users/{id}/sendMail``.
* ``teams`` exchanges a refresh token directly against the token endpoint and then
  posts channel or chat messages.

MSAL performs OIDC discovery before anything else and refuses non-HTTPS
authorities, so :func:`openid_configuration` is built from the incoming request
URL rather than hard-coded.
"""

import base64
import json
import time
import uuid
from dataclasses import dataclass

import factory


@dataclass
class TokenResponse:
    token_type: str
    scope: str
    expires_in: int
    ext_expires_in: int
    access_token: str
    refresh_token: str


@dataclass
class ChatMessage:
    id: str
    etag: str
    messageType: str  # noqa: N815
    createdDateTime: str  # noqa: N815
    webUrl: str  # noqa: N815
    importance: str
    locale: str
    body: dict
    fromUser: dict  # noqa: N815

    def to_dict(self) -> dict:
        """Graph names the sender ``from``, which is a Python keyword."""
        payload = {
            "id": self.id,
            "etag": self.etag,
            "messageType": self.messageType,
            "createdDateTime": self.createdDateTime,
            "webUrl": self.webUrl,
            "importance": self.importance,
            "locale": self.locale,
            "body": self.body,
            "from": self.fromUser,
        }
        return payload


def fake_access_token(tenant_id: str, audience: str) -> str:
    """Build a syntactically valid, unsigned JWT.

    Injectors only forward the token as a bearer credential, but returning
    something that decodes like a real token keeps debugging sane.
    """
    now = int(time.time())
    header = {"typ": "JWT", "alg": "none"}
    payload = {
        "aud": audience,
        "iss": f"https://sts.windows.net/{tenant_id}/",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "appid": str(uuid.uuid4()),
        "tid": tenant_id,
        "ver": "1.0",
    }

    def _segment(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_segment(header)}.{_segment(payload)}.{'ofapi'}"


class TokenResponseFactory(factory.Factory):
    class Meta:
        model = TokenResponse

    token_type = "Bearer"
    scope = "https://graph.microsoft.com/.default"
    expires_in = 3599
    ext_expires_in = 3599
    access_token = factory.Faker("sha256")
    refresh_token = factory.Faker("sha256")


class ChatMessageFactory(factory.Factory):
    class Meta:
        model = ChatMessage

    id = factory.Faker("numerify", text="#############")
    etag = factory.Faker("numerify", text="#############")
    messageType = "message"
    createdDateTime = factory.Faker("iso8601")
    webUrl = factory.Faker("uri")
    importance = "normal"
    locale = "en-us"
    body = factory.Dict({"contentType": "html", "content": "<p>ofapi</p>"})
    fromUser = factory.Dict(
        {
            "user": factory.Dict(
                {
                    "id": factory.Faker("uuid4"),
                    "displayName": factory.Faker("name"),
                    "userIdentityType": "aadUser",
                }
            )
        }
    )


def openid_configuration(base_url: str, tenant_id: str) -> dict:
    """Minimal OIDC discovery document accepted by MSAL."""
    authority = f"{base_url.rstrip('/')}/{tenant_id}"
    return {
        "token_endpoint": f"{authority}/oauth2/v2.0/token",
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "private_key_jwt",
            "client_secret_basic",
        ],
        "jwks_uri": f"{authority}/discovery/v2.0/keys",
        "response_modes_supported": ["query", "fragment", "form_post"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": [
            "code",
            "id_token",
            "code id_token",
            "id_token token",
        ],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "issuer": f"{authority}/v2.0",
        "authorization_endpoint": f"{authority}/oauth2/v2.0/authorize",
        "device_authorization_endpoint": f"{authority}/oauth2/v2.0/devicecode",
        "http_logout_supported": True,
        "frontchannel_logout_supported": True,
        "end_session_endpoint": f"{authority}/oauth2/v2.0/logout",
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "tid"],
        "tenant_region_scope": "EU",
        "cloud_instance_name": "ofapi",
        "cloud_graph_host_name": "graph.windows.net",
        "msgraph_host": "graph.microsoft.com",
    }
