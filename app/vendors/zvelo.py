"""zvelo: OAuth token and the threat, phish and malicious collections (paged JSON),
read by the OpenCTI zvelo connector."""

from fastapi import APIRouter, Header, HTTPException

from app.fake import fake

HOSTS = ["oauth.zvelo.io", "api.zvelo.io"]
router = APIRouter(prefix="/zvelo", tags=["zvelo"])

PAGES = 2
PER_PAGE = 3
FAMILIES = ["emotet", "mirai", "agenttesla"]


def _seen() -> str:
    return fake.date_time_between("-3d", "-1h").strftime("%Y-%m-%dT%H:%M:%SZ")


def _ips() -> list[dict]:
    return [{"ip": fake.ipv4_public()}, {"ip": fake.ipv6()}]


def _part(page: int) -> dict:
    return {"page": page, "num_pages": PAGES, "page_size": PER_PAGE}


def _auth(authorization: str | None) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")


@router.post("/oauth/token")
async def token() -> dict:
    """OAuth2 client credentials, JSON body."""
    return {"access_token": fake.sha256(), "token_type": "Bearer", "expires_in": 86400}


def _threat(kind: str) -> dict:
    value = {
        "url": fake.url(),
        "domain": fake.domain_name(),
        "ip": f"{fake.ipv4_public()}:{fake.random_element([80, 443, 8080])}",
    }[kind]
    return {
        "ioc": value,
        "ioc_type": kind,
        "threat_type": fake.random_element(["malware", "botnet", "c2"]),
        "confidence_level": fake.random_int(50, 100),
        "malware_family": fake.random_element(FAMILIES),
        "discovered_date": _seen(),
        "ip_info": _ips(),
    }


@router.get("/v1/threat")
async def threat(page: int = 0, authorization: str | None = Header(None)) -> dict:
    """One page of threat IOCs: a URL, a domain and an address."""
    _auth(authorization)
    items = [_threat(kind) for kind in ("url", "domain", "ip")]
    return {"_response_part": _part(page), "threat_info": {"threat": items}}


@router.get("/v1/phish")
async def phish(page: int = 0, authorization: str | None = Header(None)) -> dict:
    """One page of phishing URLs."""
    _auth(authorization)
    items = [
        {
            "url": fake.url(),
            "brand": fake.company(),
            "confidence_level": fake.random_int(50, 100),
            "discovered_date": _seen(),
            "ip_info": _ips(),
        }
        for _ in range(PER_PAGE)
    ]
    return {"_response_part": _part(page), "phish_info": {"phish": items}}


@router.get("/v1/malicious")
async def malicious(page: int = 0, authorization: str | None = Header(None)) -> dict:
    """One page of malicious URLs."""
    _auth(authorization)
    items = [
        {
            "url": fake.url(),
            "confidence_level": fake.random_int(50, 100),
            "discovered_date": _seen(),
            "ip_info": _ips(),
        }
        for _ in range(PER_PAGE)
    ]
    return {"_response_part": _part(page), "malicious_info": {"malicious": items}}
