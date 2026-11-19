"""OSINT Industries: the digital footprint search (``POST /v2/request``), read by the
OpenCTI osint-industries connector. Answers a list of per-module results whose
``spec_format`` fields are ``{proper_key, value, type}`` triplets."""

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["api.osint.industries"]
router = APIRouter(prefix="/osint-industries", tags=["OSINT Industries"])


def _field(key: str, value: object, kind: str = "str") -> dict:
    return {"proper_key": key.replace("_", " ").title(), "value": value, "type": kind}


def _module(name: str, query: str, status: str, *specs: dict) -> dict:
    return {
        "module": name,
        "query": query,
        "status": status,
        "reliable_source": True,
        "data": {},
        "spec_format": list(specs),
    }


@router.post("/v2/request")
async def request(request: Request) -> list[dict]:
    """A profile on a social network, a code hosting account, a breach, a module without
    result and one without any field."""
    body = await request.json()
    query = body.get("query", "")
    first, last = fake.first_name(), fake.last_name()
    handle = f"{first}{last}".lower()
    return [
        _module(
            "okru",
            query,
            "found",
            {
                "registered": _field("registered", True, "bool"),
                "id": _field("id", str(fake.random_int(10**6, 10**8))),
                "name": _field("name", f"{first} {last}"),
                "first_name": _field("first_name", first),
                "last_name": _field("last_name", last),
                "location": _field("location", fake.city()),
                "profile_url": _field("profile_url", f"https://ok.ru/{handle}"),
                "platform_variables": [
                    {
                        **_field("friends", str(fake.random_int(1, 500)), "int"),
                        "key": "friends",
                    }
                ],
            },
        ),
        _module(
            "github",
            query,
            "found",
            {
                "registered": _field("registered", True, "bool"),
                "id": _field("id", str(fake.random_int(10**5, 10**7))),
                "username": _field("username", handle),
                "email": _field("email", fake.email()),
                "phone": _field("phone", f"+33{fake.random_int(600000000, 799999999)}"),
                "wallet": _field("wallet", "0x" + fake.sha1()),
                "profile_url": _field("profile_url", f"https://github.com/{handle}"),
                "creation_date": _field("creation_date", "2015-03-10"),
                "platform_variables": [
                    {
                        **_field("public_repos", str(fake.random_int(1, 90)), "int"),
                        "key": "public_repos",
                    }
                ],
            },
        ),
        _module(
            "hibp",
            query,
            "found",
            {
                "registered": _field("registered", True, "bool"),
                "breach": _field("breach", True, "bool"),
                "verified": _field("verified", True, "bool"),
                "platform_variables": [
                    {**_field("title", "LinkedIn (2012)"), "key": "title"},
                    {**_field("added_date", "2016-05-21"), "key": "added_date"},
                    {
                        **_field("data_classes", "Email addresses, Passwords"),
                        "key": "data_classes",
                    },
                ],
            },
        ),
        _module("pinterest", query, "not_found"),
        _module(
            "emailchecker",
            query,
            "found",
            {"registered": _field("registered", True, "bool")},
        ),
    ]
