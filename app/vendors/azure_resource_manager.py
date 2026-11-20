"""Azure Resource Manager compute and network (management.azure.com): virtual machines,
their network interfaces and public IP addresses, read by the OpenAEV microsoft-azure
collector (running VMs become endpoints).

management.azure.com is claimed by ``microsoft_sentinel`` (prefix
``/microsoft-sentinel``, for the Sentinel indicator API): these routes use the same
prefix, so the proxy brings the compute and network requests here.

One subscription, generated once from a seeded Faker (with the CTI providers) so a test
can read it back and compare it with what the collector imported:

* resource group ``rg-staticfire-prod``: a Linux VM with a private and a public IP, a
  Windows VM with a private IP only, a VM whose provisioning failed;
* resource group ``rg-staticfire-dev``: a Linux VM (outside a prod-only collection).

API versions are not checked; resource group names match case-insensitively (as ARM
does).
"""

import uuid

from faker import Faker
from faker_cti import CtiProvider
from fastapi import APIRouter
from starlette.responses import JSONResponse

router = APIRouter(prefix="/microsoft-sentinel", tags=["Azure Resource Manager"])

SUBSCRIPTION = "1a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
GROUPS = ["rg-staticfire-prod", "rg-staticfire-dev"]

_faker = Faker()
_faker.add_provider(CtiProvider)
_faker.seed_instance(4242)


def _rid(group: str, provider: str, kind: str, name: str) -> str:
    return (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{group}"
        f"/providers/{provider}/{kind}/{name}"
    )


def _public_ip(group: str, name: str, location: str) -> dict:
    return {
        "name": name,
        "id": _rid(group, "Microsoft.Network", "publicIPAddresses", name),
        "etag": f'W/"{uuid.UUID(int=_faker.random.getrandbits(128))}"',
        "location": location,
        "type": "Microsoft.Network/publicIPAddresses",
        "sku": {"name": "Standard", "tier": "Regional"},
        "properties": {
            "provisioningState": "Succeeded",
            "resourceGuid": str(uuid.UUID(int=_faker.random.getrandbits(128))),
            "ipAddress": _faker.ipv4_public(),
            "publicIPAddressVersion": "IPv4",
            "publicIPAllocationMethod": "Static",
            "idleTimeoutInMinutes": 4,
        },
    }


def _nic(group: str, vm: str, location: str, public: dict | None) -> dict:
    name = f"{vm}-nic01"
    config = {
        "privateIPAddress": _faker.ipv4_private(network=False, address_class="a"),
        "privateIPAllocationMethod": "Dynamic",
        "privateIPAddressVersion": "IPv4",
        "subnet": {
            "id": _rid(group, "Microsoft.Network", "virtualNetworks", "vnet-main")
            + "/subnets/default"
        },
        "primary": True,
        "provisioningState": "Succeeded",
    }
    if public:
        config["publicIPAddress"] = {"id": public["id"]}
    nic_id = _rid(group, "Microsoft.Network", "networkInterfaces", name)
    return {
        "name": name,
        "id": nic_id,
        "location": location,
        "type": "Microsoft.Network/networkInterfaces",
        "properties": {
            "provisioningState": "Succeeded",
            "ipConfigurations": [
                {
                    "name": "ipconfig1",
                    "id": f"{nic_id}/ipConfigurations/ipconfig1",
                    "type": "Microsoft.Network/networkInterfaces/ipConfigurations",
                    "properties": config,
                }
            ],
            "macAddress": _faker.mac_address().replace(":", "-").upper(),
            "enableAcceleratedNetworking": False,
            "primary": True,
            "virtualMachine": {
                "id": _rid(group, "Microsoft.Compute", "virtualMachines", vm)
            },
        },
    }


def _vm(group: str, os_type: str, size: str, state: str, public: bool) -> dict:
    name = f"vm-{_faker.domain_word()}-{_faker.random_int(1, 99):02d}"
    location = _faker.random_element(["westeurope", "francecentral", "eastus2"])
    ip = _public_ip(group, f"{name}-pip", location) if public else None
    nic = _nic(group, name, location, ip)
    image = (
        {"publisher": "Canonical", "offer": "ubuntu-24_04-lts", "sku": "server"}
        if os_type == "Linux"
        else {
            "publisher": "MicrosoftWindowsServer",
            "offer": "WindowsServer",
            "sku": "2022-datacenter-azure-edition",
        }
    )
    vm = {
        "name": name,
        "id": _rid(group, "Microsoft.Compute", "virtualMachines", name),
        "type": "Microsoft.Compute/virtualMachines",
        "location": location,
        "tags": {"Environment": group.rsplit("-", 1)[-1], "Owner": _faker.last_name()},
        "properties": {
            "vmId": str(uuid.UUID(int=_faker.random.getrandbits(128))),
            "hardwareProfile": {"vmSize": size},
            "storageProfile": {
                "imageReference": {**image, "version": "latest"},
                "osDisk": {
                    "osType": os_type,
                    "name": f"{name}_OsDisk_1",
                    "createOption": "FromImage",
                    "caching": "ReadWrite",
                    "managedDisk": {"storageAccountType": "Premium_LRS"},
                    "diskSizeGB": 30 if os_type == "Linux" else 127,
                },
                "dataDisks": [],
            },
            "osProfile": {"computerName": name, "adminUsername": "azureuser"},
            "networkProfile": {
                "networkInterfaces": [
                    {"id": nic["id"], "properties": {"primary": True}}
                ]
            },
            "provisioningState": state,
            "timeCreated": _faker.date_time_between("-1y", "-1d").isoformat() + "Z",
        },
    }
    return {"vm": vm, "nic": nic, "public_ip": ip}


MACHINES = [
    _vm("rg-staticfire-prod", "Linux", "Standard_D2s_v5", "Succeeded", True),
    _vm("rg-staticfire-prod", "Windows", "Standard_B2ms", "Succeeded", False),
    _vm("rg-staticfire-prod", "Linux", "Standard_B1s", "Failed", False),
    _vm("rg-staticfire-dev", "Linux", "Standard_B2s", "Succeeded", True),
]


def _group_of(resource: dict) -> str:
    return resource["id"].split("/")[4].lower()


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"error": {"code": code, "message": message}}
    )


def _subscription_missing(subscription: str) -> JSONResponse | None:
    if subscription.lower() == SUBSCRIPTION:
        return None
    return _error(
        404,
        "SubscriptionNotFound",
        f"The subscription '{subscription}' could not be found.",
    )


@router.get("/subscriptions/{subscription}/providers/Microsoft.Compute/virtualMachines")
async def virtual_machines(subscription: str):
    """Every VM of the subscription."""
    return _subscription_missing(subscription) or {"value": [m["vm"] for m in MACHINES]}


@router.get(
    "/subscriptions/{subscription}/resourceGroups/{group}"
    "/providers/Microsoft.Compute/virtualMachines"
)
async def group_virtual_machines(subscription: str, group: str):
    """The VMs of one resource group."""
    if missing := _subscription_missing(subscription):
        return missing
    if group.lower() not in GROUPS:
        return _error(
            404,
            "ResourceGroupNotFound",
            f"Resource group '{group}' could not be found.",
        )
    return {"value": [m["vm"] for m in MACHINES if _group_of(m["vm"]) == group.lower()]}


def _find(kind: str, group: str, name: str):
    for machine in MACHINES:
        resource = machine[kind]
        if (
            resource
            and resource["name"].lower() == name.lower()
            and _group_of(resource) == group.lower()
        ):
            return resource
    provider = {"nic": "networkInterfaces", "public_ip": "publicIPAddresses"}[kind]
    return _error(
        404,
        "ResourceNotFound",
        f"The Resource 'Microsoft.Network/{provider}/{name}' under resource group "
        f"'{group}' was not found.",
    )


@router.get(
    "/subscriptions/{subscription}/resourceGroups/{group}"
    "/providers/Microsoft.Network/networkInterfaces/{name}"
)
async def network_interface(subscription: str, group: str, name: str):
    return _subscription_missing(subscription) or _find("nic", group, name)


@router.get(
    "/subscriptions/{subscription}/resourceGroups/{group}"
    "/providers/Microsoft.Network/publicIPAddresses/{name}"
)
async def public_ip_address(subscription: str, group: str, name: str):
    return _subscription_missing(subscription) or _find("public_ip", group, name)
