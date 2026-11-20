"""OVHcloud API v1 (eu/ca/us API hosts and their OAuth2 token endpoints): dedicated
servers, Public Cloud projects and instances, VPS and Hosted Private Cloud (VMware) VMs,
read by the OpenAEV ovhcloud collector (machines become agentless endpoints).

Authentication is checked as OVHcloud does:

* application key, consumer key and ``X-Ovh-Signature``
  (``$1$`` + SHA-1 of ``AS+CK+METHOD+URL+BODY+TIMESTAMP``), the URL being the one the
  client called (rebuilt from the proxy's ``X-Original-*`` headers); the application
  keys this fake knows are in ``APPLICATIONS``, any other is ``INVALID_KEY``;
* or an OAuth2 bearer from ``POST /auth/oauth2/token`` (client credentials).

Answers follow the API schemas: ``GET /cloud/project/{id}/instance`` lists
``cloud.instance.Instance`` objects (``flavorId``, ``imageId``, no flavor or image
details), ``GET /cloud/project/{id}/instance/{instanceId}`` the
``cloud.instance.InstanceDetail`` with its ``flavor`` and ``image``; IP blocks are CIDR
strings; IAM metadata (``iam.displayName``, ``state``, ``tags``) on IAM resources.

One account, generated once from a seeded Faker (with the CTI providers) so a test can
read it back (through an OAuth2 token) and compare it with what the collector imported:
a Linux and a Windows dedicated server and a suspended one; a Public Cloud project with
a Linux and a Windows instance and a deleted one; a VPS; a Hosted Private Cloud with a
powered-on VM and a deleted one.
"""

import hashlib
import time
import uuid
from urllib.parse import quote

from faker import Faker
from faker_cti import CtiProvider
from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

HOSTS = [
    "eu.api.ovh.com",
    "ca.api.ovh.com",
    "api.us.ovhcloud.com",
    "www.ovh.com",
    "ca.ovh.com",
    "us.ovhcloud.com",
]
router = APIRouter(prefix="/ovhcloud", tags=["OVHcloud"])

# application key -> application secret
APPLICATIONS = {"staticfireOvhAppKey1": "staticfireOvhAppSecret1"}
TOKENS: set[str] = set()

_faker = Faker()
_faker.add_provider(CtiProvider)
_faker.seed_instance(5151)


def _iam(kind: str, name: str, display: str, state: str = "OK", **tags) -> dict:
    return {
        "id": str(uuid.UUID(int=_faker.random.getrandbits(128), version=4)),
        "urn": f"urn:v1:eu:resource:{kind}:{name}",
        "displayName": display,
        "state": state,
        "tags": {"ovh:type": kind, **tags},
    }


def _server_name() -> tuple[str, str]:
    ip = _faker.ipv4_public()
    octets = ip.split(".")
    return f"ns{_faker.numerify('3######')}.ip-{'-'.join(octets[:3])}.eu", ip


def _dedicated(os_name: str, display: str | None, iam_state: str = "OK") -> dict:
    name, ip = _server_name()
    datacenter = _faker.random_element(["rbx8", "gra3", "sbg5"])
    region = {"rbx8": "eu-west-rbx", "gra3": "eu-west-gra", "sbg5": "eu-west-sbg"}
    server = {
        "name": name,
        "serverId": _faker.random_int(1000000, 9999999),
        "commercialRange": _faker.random_element(["advance-1", "rise-2", "scale-a3"]),
        "datacenter": datacenter,
        "region": region[datacenter],
        "availabilityZone": region[datacenter] + "-a",
        "rack": _faker.bothify("?##?##").upper(),
        "os": os_name,
        "ip": ip,
        "reverse": f"{display}.{_faker.domain_name()}." if display else None,
        "state": "ok",
        "powerState": "poweron",
        "monitoring": True,
        "professionalUse": False,
        "linkSpeed": 1000,
        "bootId": 1,
        "noIntervention": False,
        "supportLevel": "pro",
        "iam": _iam(
            "dedicatedServer",
            name,
            display or name,
            iam_state,
            environment=_faker.random_element(["production", "staging"]),
        ),
    }
    ips = [
        f"{ip}/32",
        f"2001:41d0:{_faker.hexify('^^^')}:{_faker.hexify('^^^^')}::/64",
        f"{_faker.ipv4_private()}/32",
        f"{_faker.ipv4_public(network=True).rsplit('.', 1)[0]}.0/28",
    ]
    return {"server": server, "ips": ips}


DEDICATED = [
    _dedicated("debian12_64", "web-01"),
    _dedicated("win2022-std_64", None),
    _dedicated("debian12_64", "old-01", iam_state="SUSPENDED"),
]

PROJECT_ID = _faker.hexify("^" * 32)
PROJECT = {
    "project_id": PROJECT_ID,
    "projectName": "prod",
    "description": "Production",
    "planCode": "project.2018",
    "unleash": False,
    "creationDate": "2024-02-12T09:41:17Z",
    "orderId": _faker.random_int(100000000, 999999999),
    "access": "full",
    "status": "ok",
    "manualQuota": False,
    "iam": _iam(
        "publicCloudProject", PROJECT_ID, "Production", environment="production"
    ),
}
FLAVORS = {
    "b3-8": {"name": "b3-8", "osType": "linux", "vcpus": 2, "ram": 8000, "disk": 50},
    "win-b3-16": {"name": "win-b3-16", "osType": "windows", "vcpus": 4, "ram": 16000},
}
IMAGES = {
    "ubuntu": {"name": "Ubuntu 24.04", "type": "linux", "user": "ubuntu"},
    "windows": {"name": "Windows Server 2022 Standard (Desktop)", "type": "windows"},
}


def _instance(name: str, flavor: str, image: str, status: str = "ACTIVE") -> dict:
    instance_id = str(uuid.UUID(int=_faker.random.getrandbits(128), version=4))
    image_id = str(uuid.UUID(int=_faker.random.getrandbits(128), version=4))
    flavor_id = str(uuid.UUID(int=_faker.random.getrandbits(128), version=4))
    region = _faker.random_element(["GRA11", "SBG5", "BHS5"])
    addresses = []
    if status == "ACTIVE":
        addresses = [
            {
                "ip": _faker.ipv4_public(),
                "type": "public",
                "version": 4,
                "networkId": _faker.hexify("^" * 64),
                "gatewayIp": None,
            },
            {
                "ip": _faker.ipv4_private(network=False, address_class="c"),
                "type": "private",
                "version": 4,
                "networkId": _faker.hexify("^" * 64),
                "gatewayIp": None,
            },
        ]
    listed = {
        "id": instance_id,
        "name": name,
        "ipAddresses": addresses,
        "flavorId": flavor_id,
        "imageId": image_id,
        "sshKeyId": None,
        "created": "2025-06-03T14:22:09Z",
        "region": region,
        "monthlyBilling": None,
        "status": status,
        "planCode": f"{flavor}.consumption",
        "operationIds": [],
        "currentMonthOutgoingTraffic": None,
    }
    detail = {
        **listed,
        "flavor": {
            "id": flavor_id,
            "region": region,
            "type": "ovh.ssd.eg",
            "available": True,
            **FLAVORS[flavor],
        },
        "image": {
            "id": image_id,
            "region": region,
            "visibility": "public",
            "status": "active",
            "minDisk": 0,
            "size": 3.5,
            "creationDate": "2025-05-01T00:00:00Z",
            **IMAGES[image],
        },
        "sshKey": None,
        "monthlyBilling": None,
    }
    return {"listed": listed, "detail": detail}


INSTANCES = [
    _instance("k8s-node-1", "b3-8", "ubuntu"),
    _instance("win-bastion", "win-b3-16", "windows"),
    _instance("decommissioned", "b3-8", "ubuntu", status="DELETED"),
]

VPS_NAME = f"vps-{_faker.hexify('^' * 8)}.vps.ovh.net"
VPS = {
    "name": VPS_NAME,
    "displayName": "monitoring",
    "zone": "Region OpenStack: os-sbg5",
    "state": "running",
    "netbootMode": "local",
    "offerType": "ssd",
    "slaMonitoring": True,
    "vcore": 2,
    "memoryLimit": 4096,
    "keymap": None,
    "cluster": "pcs-sbg5",
    "monitoringIpBlocks": [],
    "model": {
        "name": "vps-value-1-2-40",
        "offer": "VPS Value",
        "datacenter": ["sbg"],
        "version": "2019v1",
        "disk": 40,
        "memory": 2048,
        "vcore": 1,
        "maximumAdditionnalIp": 16,
        "availableOptions": [],
    },
    "iam": _iam("vps", VPS_NAME, "monitoring", team="infra"),
}
VPS_IPS = [
    _faker.ipv4_public(),
    f"2001:41d0:{_faker.hexify('^^^')}:{_faker.hexify('^^^')}::{_faker.hexify('^^^')}",
]
VPS_IMAGE = {
    "id": str(uuid.UUID(int=_faker.random.getrandbits(128))),
    "name": "Rocky Linux 9",
}

PCC = "pcc-" + "-".join(_faker.ipv4_public().split("."))
PCC_SERVICE = {
    "serviceName": PCC,
    "description": "VMware cluster",
    "location": "rbx2",
    "state": "delivered",
    "iam": _iam("dedicatedCloud", PCC, PCC),
}
PCC_DATACENTER = {
    "datacenterId": 1,
    "name": f"{PCC}_datacenter1",
    "commercialName": "SDDC",
}


def _vm(vm_id: int, name: str, family: str, power: str) -> dict:
    return {
        "vmId": vm_id,
        "moRef": f"vm-{vm_id}",
        "name": name,
        "hostName": f"esx-0{vm_id % 3 + 1}.{PCC}.ovh.de",
        "clusterName": "Cluster1",
        "guestOsFamily": family,
        "powerState": power,
        "networks": [{"label": "VM Network", "macAddress": _faker.mac_address()}]
        if power != "deleted"
        else [],
    }


PCC_VMS = {
    101: _vm(101, "erp-db", "linuxGuest", "poweredOn"),
    102: _vm(102, "old-template", "windowsGuest", "deleted"),
}


# -- authentication --------------------------------------------------------------------


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "class": f"Client::{code.title().replace('_', '')}",
            "message": message,
            "errorCode": code,
            "httpCode": f"{status} {'Bad Request' if status == 400 else 'Forbidden'}",
        },
    )


def _called_url(request: Request) -> str:
    scheme = request.headers.get("x-original-scheme", request.url.scheme)
    host = request.headers.get("x-original-host", request.url.netloc)
    path = request.url.path.removeprefix("/ovhcloud")
    query = f"?{request.url.query}" if request.url.query else ""
    return f"{scheme}://{host}{path}{query}"


def _denied(request: Request) -> JSONResponse | None:
    """Why the request is not authenticated, or None."""
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        if authorization.removeprefix("Bearer ") in TOKENS:
            return None
        return _error(401, "INVALID_CREDENTIAL", "Invalid credentials")
    key = request.headers.get("x-ovh-application", "")
    if key not in APPLICATIONS:
        return _error(403, "INVALID_KEY", "Invalid application key")
    consumer = request.headers.get("x-ovh-consumer", "")
    timestamp = request.headers.get("x-ovh-timestamp", "")
    if not consumer or not timestamp.isdigit():
        return _error(403, "NOT_CREDENTIAL", "This call has not been granted")
    if abs(int(timestamp) - int(time.time())) > 180:
        return _error(400, "QUERY_TIME_OUT", "Query out of time")
    payload = "+".join(
        [
            APPLICATIONS[key],
            consumer,
            request.method,
            _called_url(request),
            "",
            timestamp,
        ]
    )
    digest = hashlib.sha1(payload.encode(), usedforsecurity=False).hexdigest()
    if request.headers.get("x-ovh-signature") != f"$1${digest}":
        return _error(400, "INVALID_SIGNATURE", "Invalid signature")
    return None


@router.post("/auth/oauth2/token")
async def oauth2_token(request: Request):
    """Client credentials grant of a service account."""
    form = await request.form()
    if form.get("grant_type") != "client_credentials" or not form.get("client_id"):
        return JSONResponse(status_code=400, content={"error": "invalid_request"})
    token = "eyJhbGciOiJFUzI1NiJ9." + _faker.pystr(80, 80)
    TOKENS.add(token)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3599,
        "scope": form.get("scope") or "all",
    }


@router.get("/1.0/auth/time")
async def server_time() -> int:
    return int(time.time())


def _guarded(request: Request, answer):
    return _denied(request) or answer


def _missing(path: str) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={
            "class": "Client::NotFound",
            "message": f"The requested object ({path}) does not exist",
        },
    )


# -- dedicated servers -----------------------------------------------------------------


def _server(name: str) -> dict | None:
    return next((d for d in DEDICATED if d["server"]["name"] == name), None)


@router.get("/1.0/dedicated/server")
async def dedicated_servers(request: Request):
    return _guarded(request, [d["server"]["name"] for d in DEDICATED])


@router.get("/1.0/dedicated/server/{name}")
async def dedicated_server(request: Request, name: str):
    found = _server(name)
    return _guarded(request, found["server"] if found else _missing(name))


@router.get("/1.0/dedicated/server/{name}/ips")
async def dedicated_server_ips(request: Request, name: str):
    found = _server(name)
    return _guarded(request, found["ips"] if found else _missing(name))


# -- Public Cloud ----------------------------------------------------------------------


@router.get("/1.0/cloud/project")
async def cloud_projects(request: Request):
    return _guarded(request, [PROJECT_ID])


@router.get("/1.0/cloud/project/{project_id}")
async def cloud_project(request: Request, project_id: str):
    return _guarded(
        request, PROJECT if project_id == PROJECT_ID else _missing(project_id)
    )


@router.get("/1.0/cloud/project/{project_id}/instance")
async def cloud_instances(request: Request, project_id: str):
    """``cloud.instance.Instance`` items: no flavor or image details."""
    if project_id != PROJECT_ID:
        return _guarded(request, _missing(project_id))
    return _guarded(request, [i["listed"] for i in INSTANCES])


@router.get("/1.0/cloud/project/{project_id}/instance/{instance_id}")
async def cloud_instance(request: Request, project_id: str, instance_id: str):
    """``cloud.instance.InstanceDetail``: with its flavor and image."""
    found = next((i for i in INSTANCES if i["listed"]["id"] == instance_id), None)
    if project_id != PROJECT_ID or found is None:
        return _guarded(request, _missing(instance_id))
    return _guarded(request, found["detail"])


# -- VPS -------------------------------------------------------------------------------


@router.get("/1.0/vps")
async def vps_list(request: Request):
    return _guarded(request, [VPS_NAME])


@router.get("/1.0/vps/{name}")
async def vps(request: Request, name: str):
    return _guarded(request, VPS if name == VPS_NAME else _missing(name))


@router.get("/1.0/vps/{name}/ips")
async def vps_ips(request: Request, name: str):
    return _guarded(request, VPS_IPS if name == VPS_NAME else _missing(name))


@router.get("/1.0/vps/{name}/images/current")
async def vps_image(request: Request, name: str):
    return _guarded(request, VPS_IMAGE if name == VPS_NAME else _missing(name))


# -- Hosted Private Cloud --------------------------------------------------------------


@router.get("/1.0/dedicatedCloud")
async def dedicated_clouds(request: Request):
    return _guarded(request, [PCC])


@router.get("/1.0/dedicatedCloud/{service}")
async def dedicated_cloud(request: Request, service: str):
    return _guarded(request, PCC_SERVICE if service == PCC else _missing(service))


@router.get("/1.0/dedicatedCloud/{service}/datacenter")
async def datacenters(request: Request, service: str):
    return _guarded(request, [1] if service == PCC else _missing(service))


@router.get("/1.0/dedicatedCloud/{service}/datacenter/{datacenter_id}")
async def datacenter(request: Request, service: str, datacenter_id: int):
    found = service == PCC and datacenter_id == 1
    return _guarded(request, PCC_DATACENTER if found else _missing(quote(service)))


@router.get("/1.0/dedicatedCloud/{service}/datacenter/{datacenter_id}/vm")
async def vms(request: Request, service: str, datacenter_id: int):
    found = service == PCC and datacenter_id == 1
    return _guarded(request, list(PCC_VMS) if found else _missing(service))


@router.get("/1.0/dedicatedCloud/{service}/datacenter/{datacenter_id}/vm/{vm_id}")
async def vm(request: Request, service: str, datacenter_id: int, vm_id: int):
    found = service == PCC and datacenter_id == 1 and vm_id in PCC_VMS
    return _guarded(request, PCC_VMS[vm_id] if found else _missing(str(vm_id)))
