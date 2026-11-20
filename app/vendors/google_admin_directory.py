"""Google Workspace Admin SDK Directory API (admin.googleapis.com): users, groups and
group members, read by the OpenAEV google-workspace collector (groups become teams,
their members users; or every user when it syncs all users).

Tokens come from ``google_identity`` (service account with domain-wide delegation).
The answers follow the Directory API: ``kind`` and ``etag`` on every resource, the
``query`` filter on ``isSuspended``, ``orderBy=email``, ``maxResults`` and
``nextPageToken`` paging, ``404 Resource Not Found: userKey`` for an address that is
not a user of the domain.

One domain, generated once from a seeded Faker (with the CTI providers) so a test can
read it back and compare it with what the collector imported:

* group ``security``: two active users (one an admin, one a delegated admin), a
  suspended user, a nested group, an outside address;
* group ``finance``: two active users;
* a user in no group.
"""

import base64
import hashlib

from faker import Faker
from faker_cti import CtiProvider
from fastapi import APIRouter, Query
from starlette.responses import JSONResponse

HOSTS = ["admin.googleapis.com"]
router = APIRouter(prefix="/google-admin", tags=["Google Admin Directory"])

_faker = Faker()
_faker.add_provider(CtiProvider)
_faker.seed_instance(7311)
DOMAIN = f"{_faker.domain_word()}-corp.com"
CUSTOMER = "C0" + _faker.bothify("??####?#").lower()


def _etag(*parts: str) -> str:
    digest = hashlib.sha1("".join(parts).encode()).digest()
    return '"' + base64.urlsafe_b64encode(digest).decode().rstrip("=") + '"'


def _user(org_unit: str, suspended: bool = False, admin: bool = False, **extra) -> dict:
    first, last = _faker.first_name(), _faker.last_name()
    email = f"{first}.{last}".lower() + f"@{DOMAIN}"
    user_id = _faker.numerify("1#####################")
    created = _faker.date_time_between("-4y", "-60d")
    return {
        "kind": "admin#directory#user",
        "id": user_id,
        "etag": _etag(user_id),
        "primaryEmail": email,
        "name": {"givenName": first, "familyName": last, "fullName": f"{first} {last}"},
        "isAdmin": admin,
        "isDelegatedAdmin": False,
        "lastLoginTime": _faker.date_time_between("-20d", "now").isoformat() + ".000Z",
        "creationTime": created.isoformat() + ".000Z",
        "agreedToTerms": True,
        "suspended": suspended,
        **({"suspensionReason": "ADMIN"} if suspended else {}),
        "archived": False,
        "changePasswordAtNextLogin": False,
        "ipWhitelisted": False,
        "emails": [{"address": email, "primary": True}],
        "languages": [{"languageCode": "en", "preference": "preferred"}],
        "customerId": CUSTOMER,
        "orgUnitPath": org_unit,
        "isMailboxSetup": True,
        "isEnrolledIn2Sv": True,
        "isEnforcedIn2Sv": False,
        "includeInGlobalAddressList": True,
        **extra,
    }


def _group(name: str, local: str, description: str) -> dict:
    group_id = _faker.bothify("0##??###?##??##").lower()
    return {
        "kind": "admin#directory#group",
        "id": group_id,
        "etag": _etag(group_id),
        "email": f"{local}@{DOMAIN}",
        "name": name,
        "directMembersCount": "0",
        "description": description,
        "adminCreated": True,
        "nonEditableAliases": [f"{local}@{DOMAIN}.test-google-a.com"],
    }


def _member(email: str, kind: str = "USER", member_id: str | None = None) -> dict:
    member_id = member_id or _faker.numerify("1#####################")
    return {
        "kind": "admin#directory#member",
        "etag": _etag(email, member_id),
        "id": member_id,
        "email": email,
        "role": "MEMBER",
        "type": kind,
        "status": "ACTIVE",
    }


SECURITY = [
    _user("/Engineering/Security", admin=True),
    _user("/Engineering/Security", isDelegatedAdmin=True),
    _user("/Engineering/Security", suspended=True),
]
FINANCE = [_user("/Finance"), _user("/Finance")]
LONER = _user("/")
USERS = SECURITY + FINANCE + [LONER]

GROUPS = [
    _group("Security Team", "security", "Security operations and incident response"),
    _group("Finance", "finance", "Finance department"),
]
OUTSIDER = f"{_faker.user_name()}@{_faker.free_email_domain()}"
MEMBERS = {
    GROUPS[0]["email"]: [
        _member(u["primaryEmail"], member_id=u["id"]) for u in SECURITY
    ]
    + [
        _member(GROUPS[1]["email"], "GROUP", GROUPS[1]["id"]),
        _member(OUTSIDER),
    ],
    GROUPS[1]["email"]: [
        _member(u["primaryEmail"], member_id=u["id"]) for u in FINANCE
    ],
}
for _group_item in GROUPS:
    _group_item["directMembersCount"] = str(len(MEMBERS[_group_item["email"]]))


def _page(kind: str, field: str, items: list, size: int, token: str) -> dict:
    start = int(token) if token.isdigit() else 0
    answer = {
        "kind": kind,
        "etag": _etag(kind, str(start)),
        field: items[start : start + size],
    }
    if start + size < len(items):
        answer["nextPageToken"] = str(start + size)
    return answer


def _not_found(what: str) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={
            "error": {
                "code": 404,
                "message": f"Resource Not Found: {what}",
                "errors": [
                    {
                        "message": f"Resource Not Found: {what}",
                        "domain": "global",
                        "reason": "notFound",
                    }
                ],
            }
        },
    )


def _bad_request() -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"error": {"code": 400, "message": "Bad Request"}},
    )


def _group_by_key(key: str) -> dict | None:
    key = key.lower()
    return next((g for g in GROUPS if key in (g["email"], g["id"])), None)


@router.get("/admin/directory/v1/users")
async def users(
    customer: str = "",
    domain: str = "",
    query: str = "",
    order_by: str = Query("", alias="orderBy"),
    max_results: int = Query(100, alias="maxResults"),
    page_token: str = Query("", alias="pageToken"),
):
    """Users of the customer, ``isSuspended=false/true`` honoured, by email if asked."""
    if not customer and not domain:
        return _bad_request()
    found = list(USERS)
    if "isSuspended=false" in query.replace(" ", ""):
        found = [u for u in found if not u["suspended"]]
    elif "isSuspended=true" in query.replace(" ", ""):
        found = [u for u in found if u["suspended"]]
    if order_by == "email":
        found.sort(key=lambda u: u["primaryEmail"])
    size = min(max(max_results, 1), 500)
    return _page("admin#directory#users", "users", found, size, page_token)


@router.get("/admin/directory/v1/users/{user_key}")
async def user(user_key: str):
    key = user_key.lower()
    found = next((u for u in USERS if key in (u["primaryEmail"], u["id"])), None)
    return found or _not_found("userKey")


@router.get("/admin/directory/v1/groups")
async def groups(
    customer: str = "",
    max_results: int = Query(200, alias="maxResults"),
    page_token: str = Query("", alias="pageToken"),
):
    """Groups of the customer (or of a domain)."""
    if not customer:
        return _bad_request()
    size = min(max(max_results, 1), 200)
    return _page("admin#directory#groups", "groups", GROUPS, size, page_token)


@router.get("/admin/directory/v1/groups/{group_key}/members")
async def members(
    group_key: str,
    max_results: int = Query(200, alias="maxResults"),
    page_token: str = Query("", alias="pageToken"),
):
    group = _group_by_key(group_key)
    if group is None:
        return _not_found("groupKey")
    size = min(max(max_results, 1), 200)
    items = MEMBERS[group["email"]]
    return _page("admin#directory#members", "members", items, size, page_token)
