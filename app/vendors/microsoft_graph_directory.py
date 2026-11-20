"""Microsoft Graph directory and Intune routes (graph.microsoft.com): groups, their
members and Intune managed devices, read by the OpenAEV microsoft-entra (groups become
teams, members users) and microsoft-intune (managed devices become endpoints)
collectors.

The routes live under the prefix of ``microsoft_graph``, which claims the host: the
proxy sends graph.microsoft.com here too. They answer what Graph does:
``@odata.type`` on directory objects, ``$select`` honoured, server-driven paging through
``@odata.nextLink`` (small pages, so clients must follow it), and the
``resourceProvisioningOptions/Any(x:x eq '...')`` group filter.

One tenant, generated once from a seeded Faker (with the CTI providers) so that a test
can read the dataset back from these routes and compare it with what the collector
imported, run after run:

* three security groups (the third one on the second page): one of people (three
  internal users, a guest ``#EXT#``, a service account without mailbox, a device),
  one of devices, one more of people;
* three managed devices (Windows, macOS, iOS), two of them in the device group.
"""

import re
import uuid

from faker import Faker
from faker_cti import CtiProvider
from fastapi import APIRouter, Query
from starlette.responses import JSONResponse

router = APIRouter(prefix="/microsoft-graph", tags=["Microsoft Graph directory"])

GRAPH = "https://graph.microsoft.com/v1.0"
PAGE = 2
MEMBERS_PAGE = 4

_faker = Faker()
_faker.add_provider(CtiProvider)
_faker.seed_instance(20261119)
DOMAIN = "contoso-" + _faker.domain_word() + ".com"


def _uuid() -> str:
    return str(uuid.UUID(int=_faker.random.getrandbits(128), version=4))


def _user(department: str) -> dict:
    first, last = _faker.first_name(), _faker.last_name()
    login = f"{first}.{last}".lower()
    return {
        "@odata.type": "#microsoft.graph.user",
        "id": _uuid(),
        "businessPhones": [],
        "displayName": f"{first} {last}",
        "givenName": first,
        "surname": last,
        "jobTitle": _faker.job(),
        "department": department,
        "mail": f"{login}@{DOMAIN}",
        "mobilePhone": None,
        "officeLocation": _faker.city(),
        "preferredLanguage": "en-US",
        "userPrincipalName": f"{login}@{DOMAIN}",
    }


def _guest() -> dict:
    first, last = _faker.first_name(), _faker.last_name()
    external = f"{first}.{last}".lower() + "@" + _faker.free_email_domain()
    return {
        **_user("External"),
        "displayName": f"{first} {last} (Guest)",
        "givenName": first,
        "surname": last,
        "mail": external,
        "userPrincipalName": external.replace("@", "_") + f"#EXT#@{DOMAIN}",
        "department": None,
        "jobTitle": None,
    }


def _service_account() -> dict:
    name = "svc-" + _faker.domain_word()
    return {
        **_user("IT"),
        "displayName": name,
        "givenName": None,
        "surname": None,
        "mail": None,
        "userPrincipalName": f"{name}@{DOMAIN}",
        "jobTitle": None,
    }


def _device_object(managed: dict) -> dict:
    """The directory object of a device (what group membership lists)."""
    return {
        "@odata.type": "#microsoft.graph.device",
        "id": _uuid(),
        "accountEnabled": True,
        "deviceId": managed["azureADDeviceId"],
        "displayName": managed["deviceName"],
        "operatingSystem": managed["operatingSystem"],
        "operatingSystemVersion": managed["osVersion"],
        "trustType": "AzureAd",
        "isCompliant": managed["complianceState"] == "compliant",
        "isManaged": True,
    }


def _mac() -> str:
    return _faker.mac_address().replace(":", "").upper()


def _managed_device(os_name: str, version: str, model: str, maker: str) -> dict:
    owner = _faker.first_name().lower()
    enrolled = _faker.date_time_between("-2y", "-30d")
    return {
        "id": _uuid(),
        "userId": _uuid(),
        "deviceName": f"{maker.split()[0].upper()}-{_faker.bothify('??####').upper()}",
        "managedDeviceOwnerType": "company",
        "enrolledDateTime": enrolled.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lastSyncDateTime": _faker.date_time_between("-2d", "now").strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "operatingSystem": os_name,
        "complianceState": "compliant" if os_name != "iOS" else "noncompliant",
        "jailBroken": "False" if os_name == "iOS" else "Unknown",
        "managementAgent": "mdm",
        "osVersion": version,
        "azureADRegistered": True,
        "deviceEnrollmentType": {
            "Windows": "windowsAzureADJoin",
            "macOS": "appleBulkWithUser",
            "iOS": "appleBulkWithUser",
        }[os_name],
        "emailAddress": f"{owner}@{DOMAIN}",
        "azureADDeviceId": _uuid(),
        "deviceRegistrationState": "registered",
        "deviceCategoryDisplayName": "Corporate",
        "isSupervised": os_name == "iOS",
        "isEncrypted": True,
        "userPrincipalName": f"{owner}@{DOMAIN}",
        "model": model,
        "manufacturer": maker,
        "imei": _faker.numerify("35#############") if os_name == "iOS" else "",
        "serialNumber": _faker.bothify("??##?###??#").upper(),
        "userDisplayName": owner.title(),
        "wiFiMacAddress": _mac(),
        "ethernetMacAddress": _mac() if os_name == "Windows" else None,
    }


def _group(name: str, members: list[dict], description: str) -> dict:
    created = _faker.date_time_between("-3y", "-1y").strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "id": _uuid(),
        "createdDateTime": created,
        "description": description,
        "displayName": name,
        "groupTypes": [],
        "mail": None,
        "mailEnabled": False,
        "mailNickname": re.sub(r"[^a-z0-9]", "", name.lower()),
        "onPremisesSyncEnabled": None,
        "resourceProvisioningOptions": [],
        "securityEnabled": True,
        "securityIdentifier": "S-1-12-1-" + _faker.numerify("##########-##########"),
        "visibility": None,
        "members": members,
    }


MANAGED_DEVICES = [
    _managed_device("Windows", "10.0.22631.4460", "Latitude 7440", "Dell Inc."),
    _managed_device("macOS", "14.6.1", "MacBook Pro (14-inch, 2023)", "Apple"),
    _managed_device("iOS", "17.6.1", "iPhone 15", "Apple"),
]
_SOC = _faker.word().title()
GROUPS = [
    _group(
        f"SG-{_SOC} Security Operations",
        [
            _user("Security"),
            _user("Security"),
            _guest(),
            _service_account(),
            _user("Security"),
            _device_object(MANAGED_DEVICES[0]),
        ],
        "Security operations analysts",
    ),
    _group(
        "SG-Intune Corporate Laptops",
        [_device_object(MANAGED_DEVICES[0]), _device_object(MANAGED_DEVICES[1])],
        "Corporate laptops managed by Intune",
    ),
    _group(
        f"SG-{_faker.word().title()} Finance",
        [_user("Finance"), _user("Finance")],
        "Finance department",
    ),
]


def _select(item: dict, select: str) -> dict:
    """Only the ``$select``ed properties (and the type of directory objects)."""
    if not select:
        return {k: v for k, v in item.items() if k != "members"}
    wanted = {name.strip() for name in select.split(",")}
    return {k: v for k, v in item.items() if k in wanted or k == "@odata.type"}


def _page(items: list, skip: int, size: int, link: str, context: str) -> dict:
    answer = {
        "@odata.context": f"{GRAPH}/$metadata#{context}",
        "value": items[skip : skip + size],
    }
    if skip + size < len(items):
        separator = "&" if "?" in link else "?"
        answer["@odata.nextLink"] = f"{link}{separator}$skiptoken={skip + size}"
    return answer


def _provisioning(filter_: str) -> str | None:
    pattern = r"resourceProvisioningOptions/Any\(\w+:\w+ eq '([^']+)'\)"
    found = re.search(pattern, filter_)
    return found.group(1) if found else None


@router.get("/v1.0/groups")
@router.get("/v1.0//groups")
async def groups(
    select: str = Query("", alias="$select"),
    filter_: str = Query("", alias="$filter"),
    skiptoken: int = Query(0, alias="$skiptoken"),
) -> dict:
    """Security groups, ``PAGE`` per page."""
    found = GROUPS
    if option := _provisioning(filter_):
        found = [g for g in GROUPS if option in g["resourceProvisioningOptions"]]
    link = f"{GRAPH}/groups"
    if select:
        link += f"?$select={select}"
    items = [_select(g, select) for g in found]
    return _page(items, skiptoken, PAGE, link, "groups")


@router.get("/v1.0/groups/{group_id}/members")
@router.get("/v1.0//groups/{group_id}/members")
async def group_members(
    group_id: str,
    select: str = Query("", alias="$select"),
    filter_: str = Query("", alias="$filter"),
    skiptoken: int = Query(0, alias="$skiptoken"),
) -> dict:
    """Members of a group (users and devices), ``MEMBERS_PAGE`` per page."""
    group = next((g for g in GROUPS if g["id"] == group_id), None)
    if group is None:
        return _not_found(group_id)
    members = group["members"]
    if "deviceId ne null" in filter_:
        members = [m for m in members if m.get("deviceId")]
    link = f"{GRAPH}/groups/{group_id}/members"
    if select:
        link += f"?$select={select}"
    items = [_select(m, select) for m in members]
    return _page(items, skiptoken, MEMBERS_PAGE, link, "directoryObjects")


@router.get("/v1.0/deviceManagement/managedDevices")
@router.get("/v1.0//deviceManagement/managedDevices")
async def managed_devices(
    select: str = Query("", alias="$select"),
    skiptoken: int = Query(0, alias="$skiptoken"),
) -> dict:
    """Intune managed devices, ``PAGE`` per page."""
    link = f"{GRAPH}/deviceManagement/managedDevices"
    if select:
        link += f"?$select={select}"
    items = [_select(d, select) for d in MANAGED_DEVICES]
    return _page(items, skiptoken, PAGE, link, "deviceManagement/managedDevices")


def _not_found(item: str) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={
            "error": {
                "code": "Request_ResourceNotFound",
                "message": f"Resource '{item}' does not exist or one of its queried "
                "reference-property objects are not present.",
                "innerError": {"request-id": str(uuid.uuid4())},
            }
        },
    )
