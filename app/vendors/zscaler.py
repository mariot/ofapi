"""Zscaler: ZIdentity token endpoint and the ZIA API (URL lookup, URL categories,
configuration activation), read by the OpenCTI zscaler stream connector (OneAPI)."""

from fastapi import APIRouter, Header, HTTPException, Request

from app.fake import fake

HOSTS = ["*.zslogin.net", "api.zsapi.net", "api.*.zsapi.net"]
router = APIRouter(prefix="/zscaler", tags=["Zscaler"])

CATEGORY = "BLACK_LIST_DYNDNS"


def _auth(authorization: str | None) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")


@router.post("/oauth2/v1/token")
async def token() -> dict:
    """ZIdentity client credentials grant."""
    return {
        "access_token": fake.sha256(),
        "token_type": "Bearer",
        "expires_in": 3600,
    }


@router.post("/zia/api/v1/urlLookup")
async def url_lookup(
    request: Request, authorization: str | None = Header(None)
) -> list[dict]:
    """Classification of each URL of the body."""
    _auth(authorization)
    urls = await request.json()
    return [
        {
            "url": url,
            "urlClassifications": ["DYNAMIC_DNS", "NEWLY_REGISTERED_DOMAINS"],
            "urlClassificationsWithSecurityAlert": [],
        }
        for url in urls
    ]


@router.get("/zia/api/v1/urlCategories/{category_id}")
async def url_category(
    category_id: str, authorization: str | None = Header(None)
) -> dict:
    """A custom URL category with the URLs it holds."""
    _auth(authorization)
    return {
        "id": category_id,
        "configuredName": category_id,
        "superCategory": "SECURITY",
        "keywords": [],
        "urls": ["old-blocked.example.net", ".dyndns.example.org"],
        "customCategory": True,
        "type": "URL_CATEGORY",
        "urlsRetainingParentCategoryCount": 0,
        "totalUrlCount": 2,
    }


@router.put("/zia/api/v1/urlCategories/{category_id}")
async def update_category(
    category_id: str,
    request: Request,
    action: str = "",
    authorization: str | None = Header(None),
) -> dict:
    """Add the URLs of the body to the category, or remove them."""
    _auth(authorization)
    if action not in ("ADD_TO_LIST", "REMOVE_FROM_LIST"):
        raise HTTPException(400, "invalid action")
    body = await request.json()
    return {
        "id": category_id,
        "configuredName": body.get("configuredName", category_id),
        "urls": body.get("urls", []),
        "customCategory": True,
    }


@router.get("/zia/api/v1/status")
async def status(authorization: str | None = Header(None)) -> dict:
    """Activation status of the configuration."""
    _auth(authorization)
    return {"status": "INACTIVE"}


@router.post("/zia/api/v1/status/activate")
async def activate(authorization: str | None = Header(None)) -> dict:
    """Activate the pending configuration changes."""
    _auth(authorization)
    return {"status": "ACTIVE"}
