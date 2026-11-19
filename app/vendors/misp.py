"""MISP: the REST API of an instance (PyMISP) and a public feed (manifest plus event
files), read by the OpenCTI misp (events search), misp-feed (feed URL) and misp-intel
(events written from OpenCTI containers) connectors.

The instance answers what PyMISP asks when it connects (version, current user,
attribute types), ``POST /events/restSearch`` with two pages (the second one is empty)
and the event calls of the stream connector (add, view, edit, delete, publish). The
events carry what the connectors map: threat level, TLP and galaxy tags, galaxies
(intrusion set, attack pattern, malware, sector, country, region), attributes of the
handled types, a link, objects with references and an event report. The feed serves
the same events as ``manifest.json`` and ``<uuid>.json``.
"""

import time
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["misp.staticfire.test", "feed.misp.staticfire.test"]
router = APIRouter(prefix="/misp", tags=["MISP"])

VERSION = "2.5.21"
TLP = ["tlp:clear", "tlp:green", "tlp:amber"]
# event uuid -> event, for the events written by the stream connector and the feed
CREATED: dict[str, dict] = {}
FEED: dict[str, dict] = {}
FEED_BUILT = [0.0]


def _tag(name: str, galaxy: bool = False) -> dict:
    return {
        "id": str(fake.random_int(1, 900)),
        "name": name,
        "colour": "#" + fake.hex_color()[1:],
        "exportable": True,
        "user_id": "0",
        "hide_tag": False,
        "numerical_value": None,
        "is_galaxy": galaxy,
        "is_custom_galaxy": False,
        "local": False,
    }


def _cluster(galaxy_type: str, value: str, description: str, **meta) -> dict:
    return {
        "id": str(fake.random_int(1, 90000)),
        "uuid": str(uuid.uuid4()),
        "collection_uuid": str(uuid.uuid4()),
        "type": galaxy_type,
        "value": value,
        "tag_name": f'misp-galaxy:{galaxy_type}="{value}"',
        "description": description,
        "source": "MISP Project",
        "authors": ["MITRE"],
        "version": "20250101",
        "meta": meta,
        "local": False,
    }


def _galaxy(namespace: str, name: str, galaxy_type: str, clusters: list[dict]) -> dict:
    return {
        "id": str(fake.random_int(1, 200)),
        "uuid": str(uuid.uuid4()),
        "name": name,
        "type": galaxy_type,
        "description": f"{name} galaxy",
        "version": "20250101",
        "icon": "globe",
        "namespace": namespace,
        "enabled": True,
        "local_only": False,
        "GalaxyCluster": clusters,
    }


def _galaxies() -> list[dict]:
    return [
        _galaxy(
            "mitre-attack",
            "Intrusion Set",
            "mitre-intrusion-set",
            [
                _cluster(
                    "mitre-intrusion-set",
                    "APT29 - G0016",
                    "APT29 is a threat group attributed to Russia's SVR.",
                    synonyms=["IRON HEMLOCK", "The Dukes", "NobleBaron"],
                    external_id=["G0016"],
                )
            ],
        ),
        _galaxy(
            "mitre-attack",
            "Attack Pattern",
            "mitre-attack-pattern",
            [
                _cluster(
                    "mitre-attack-pattern",
                    "Spearphishing Attachment - T1566.001",
                    "Adversaries may send spearphishing emails with a malicious "
                    "attachment.",
                    external_id=["T1566.001"],
                    kill_chain=["mitre-attack:enterprise-attack:initial-access"],
                )
            ],
        ),
        _galaxy(
            "mitre-attack",
            "Malware",
            "mitre-malware",
            [
                _cluster(
                    "mitre-malware",
                    "Cobalt Strike - S0154",
                    "Cobalt Strike is a commercial penetration testing tool.",
                    synonyms=["Agentemis"],
                    external_id=["S0154"],
                )
            ],
        ),
        _galaxy(
            "misp",
            "Sector",
            "sector",
            [_cluster("sector", "Finance", "Financial services.")],
        ),
        _galaxy(
            "misp",
            "Country",
            "country",
            [_cluster("country", "france", "France", ISO="FR")],
        ),
        _galaxy(
            "misp",
            "Regions UN M49",
            "region",
            [_cluster("region", "155 - Western Europe", "Western Europe")],
        ),
    ]


def _attribute(
    event_id: str, category: str, kind: str, value: str, to_ids: bool = True, **extra
) -> dict:
    return {
        "id": str(fake.random_int(1000, 900000)),
        "event_id": event_id,
        "object_id": "0",
        "object_relation": None,
        "category": category,
        "type": kind,
        "value": value,
        "to_ids": to_ids,
        "uuid": str(uuid.uuid4()),
        "timestamp": str(int(time.time()) - 600),
        "distribution": "5",
        "sharing_group_id": "0",
        "comment": "",
        "deleted": False,
        "disable_correlation": False,
        "first_seen": None,
        "last_seen": None,
        **extra,
    }


def _object(
    event_id: str, name: str, meta: str, description: str, attributes: list[tuple]
) -> dict:
    object_id = str(fake.random_int(1000, 90000))
    return {
        "id": object_id,
        "name": name,
        "meta-category": meta,
        "description": description,
        "template_uuid": str(uuid.uuid4()),
        "template_version": "10",
        "event_id": event_id,
        "uuid": str(uuid.uuid4()),
        "timestamp": str(int(time.time()) - 600),
        "distribution": "5",
        "sharing_group_id": "0",
        "comment": "",
        "deleted": False,
        "first_seen": None,
        "last_seen": None,
        "Attribute": [
            _attribute(
                event_id,
                category,
                kind,
                value,
                to_ids=True,
                object_id=object_id,
                object_relation=relation,
            )
            for relation, category, kind, value in attributes
        ],
        "ObjectReference": [],
    }


def _event(index: int, moment: datetime, with_galaxies: bool) -> dict:
    """A published event of an organisation, with a mix of attributes and objects."""
    event_id = str(1200 + index)
    org = {"id": "2", "uuid": str(uuid.uuid4()), "name": "CIRCL"}
    tags = [_tag(fake.random_element(TLP)), _tag("type:OSINT")]
    galaxies = _galaxies() if with_galaxies else []
    for galaxy in galaxies:
        for cluster in galaxy["GalaxyCluster"]:
            tags.append(_tag(cluster["tag_name"], galaxy=True))
    domain = fake.domain_name()
    address = fake.ipv4_public()
    attributes = [
        _attribute(event_id, "Network activity", "domain", domain),
        _attribute(event_id, "Network activity", "ip-dst", address),
        _attribute(event_id, "Network activity", "ip-src|port", f"{address}|443"),
        _attribute(event_id, "Network activity", "hostname", f"mail.{domain}"),
        _attribute(event_id, "Network activity", "domain|ip", f"{domain}|{address}"),
        _attribute(
            event_id, "Network activity", "url", f"https://{domain}/{fake.slug()}.php"
        ),
        _attribute(event_id, "Payload delivery", "md5", fake.md5()),
        _attribute(event_id, "Payload delivery", "sha256", fake.sha256()),
        _attribute(
            event_id,
            "Payload delivery",
            "filename|sha256",
            f"{fake.word()}.docm|{fake.sha256()}",
        ),
        _attribute(event_id, "Payload delivery", "email-src", fake.email()),
        _attribute(
            event_id,
            "Payload delivery",
            "email-subject",
            f"Invoice {fake.bothify('#####')}",
        ),
        _attribute(
            event_id,
            "Persistence mechanism",
            "regkey",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\updater",
        ),
        _attribute(
            event_id,
            "External analysis",
            "link",
            f"https://blog.{fake.domain_name()}/{fake.slug()}",
            to_ids=False,
        ),
        _attribute(
            event_id, "Other", "comment", "Observed in a phishing wave", to_ids=False
        ),
        _attribute(
            event_id,
            "Network activity",
            "ip-dst",
            fake.ipv4_public(),
            Tag=[_tag('estimative-language:likelihood-probability="likely"')],
        ),
    ]
    file_object = _object(
        event_id,
        "file",
        "file",
        "File object describing a file with meta-information",
        [
            ("filename", "Payload delivery", "filename", f"{fake.word()}.exe"),
            ("md5", "Payload delivery", "md5", fake.md5()),
            ("sha256", "Payload delivery", "sha256", fake.sha256()),
        ],
    )
    network_object = _object(
        event_id,
        "domain-ip",
        "network",
        "A domain and IP address seen as a tuple in a specific time frame.",
        [
            ("domain", "Network activity", "domain", fake.domain_name()),
            ("ip", "Network activity", "ip-dst", fake.ipv4_public()),
        ],
    )
    file_object["ObjectReference"] = [
        {
            "id": str(fake.random_int(1, 9000)),
            "uuid": str(uuid.uuid4()),
            "timestamp": str(int(time.time()) - 600),
            "object_id": file_object["id"],
            "referenced_id": network_object["id"],
            "referenced_uuid": network_object["uuid"],
            "referenced_type": "1",
            "relationship_type": "communicates-with",
            "comment": "",
            "deleted": False,
            "event_id": event_id,
            "source_uuid": file_object["uuid"],
        }
    ]
    return {
        "id": event_id,
        "org_id": org["id"],
        "orgc_id": org["id"],
        "distribution": "1",
        "info": f"{fake.malware_family()} phishing campaign targeting {fake.company()}",
        "uuid": str(uuid.uuid4()),
        "date": moment.strftime("%Y-%m-%d"),
        "published": True,
        "analysis": "2",
        "attribute_count": str(len(attributes)),
        "timestamp": str(int(moment.timestamp())),
        "sharing_group_id": "0",
        "proposal_email_lock": False,
        "locked": False,
        "threat_level_id": str(fake.random_int(1, 4)),
        "publish_timestamp": str(int(moment.timestamp())),
        "sighting_timestamp": "0",
        "disable_correlation": False,
        "extends_uuid": "",
        "protected": None,
        "Org": org,
        "Orgc": org,
        "Attribute": attributes,
        "ShadowAttribute": [],
        "RelatedEvent": [],
        "Galaxy": galaxies,
        "Object": [file_object, network_object],
        "EventReport": [
            {
                "id": str(fake.random_int(1, 900)),
                "uuid": str(uuid.uuid4()),
                "event_id": event_id,
                "name": "Analysis notes",
                "content": "# Notes\n\nThe sample contacts "
                f"@[attribute]({attributes[0]['uuid']}).",
                "distribution": "5",
                "sharing_group_id": "0",
                "timestamp": str(int(moment.timestamp())),
                "deleted": False,
            }
        ],
        "Tag": tags,
    }


def events() -> list[dict]:
    """Three recent events, oldest first as MISP sorts them (ascending timestamp and
    id), the last two with galaxies."""
    now = datetime.now(UTC)
    return [
        {
            "Event": _event(
                index, now - timedelta(days=3 - index, hours=index), index > 0
            )
        }
        for index in range(3)
    ]


def _feed_event(event: dict) -> dict:
    """The event as a feed file: without database ids."""
    feed = {key: value for key, value in event.items() if key not in ("id", "org_id")}
    return {"Event": feed}


def _feed() -> dict[str, dict]:
    """The feed events, renewed every ten minutes (manifest and files agree)."""
    if not FEED or time.time() - FEED_BUILT[0] > 600:
        FEED.clear()
        FEED_BUILT[0] = time.time()
        for item in events():
            event = _feed_event(item["Event"])
            FEED[event["Event"]["uuid"]] = event
    return FEED


@router.get("/servers/getVersion")
async def get_version() -> dict:
    """The instance version and the PyMISP version it recommends."""
    return {
        "version": VERSION,
        "pymisp_recommended_version": "2.5.21",
        "perm_sync": True,
        "perm_sighting": True,
        "perm_site_admin": False,
        "request_encoding": ["gzip", "br"],
        "filter_sightings": True,
    }


@router.get("/servers/getPyMISPVersion.json")
async def get_pymisp_version() -> dict:
    return {"version": "2.5.21"}


@router.get("/users/view/{user_id}")
async def view_user() -> dict:
    """The user of the API key, with its role (PyMISP reads both when connecting)."""
    return {
        "User": {
            "id": "7",
            "org_id": "2",
            "server_id": "0",
            "email": "automation@circl.example",
            "autoalert": False,
            "authkey": None,
            "invited_by": "1",
            "gpgkey": None,
            "certif_public": "",
            "nids_sid": "4000007",
            "termsaccepted": True,
            "newsread": "0",
            "role_id": "6",
            "change_pw": "0",
            "contactalert": False,
            "disabled": False,
            "expiration": None,
            "current_login": str(int(time.time())),
            "last_login": str(int(time.time()) - 3600),
            "force_logout": False,
            "date_created": "1700000000",
            "date_modified": "1760000000",
            "sub": None,
            "external_auth_required": False,
            "external_auth_key": "",
            "last_api_access": str(int(time.time())),
            "notification_daily": False,
            "notification_weekly": False,
            "notification_monthly": False,
            "totp": None,
            "hotp_counter": None,
            "last_pw_change": "1700000000",
        },
        "Role": {
            "id": "6",
            "name": "Sync user",
            "perm_add": True,
            "perm_modify": True,
            "perm_modify_org": True,
            "perm_publish": True,
            "perm_delegate": False,
            "perm_sync": True,
            "perm_admin": False,
            "perm_audit": True,
            "perm_full": False,
            "perm_auth": True,
            "perm_site_admin": False,
            "perm_regexp_access": False,
            "perm_tagger": True,
            "perm_template": False,
            "perm_sharing_group": True,
            "perm_tag_editor": True,
            "perm_sighting": True,
            "perm_object_template": False,
            "default_role": False,
            "memory_limit": "",
            "max_execution_time": "",
            "restricted_to_site_admin": False,
            "perm_publish_zmq": False,
            "perm_publish_kafka": False,
            "perm_decaying": True,
            "enforce_rate_limit": False,
            "rate_limit_count": "0",
            "perm_galaxy_editor": False,
            "perm_warninglist": False,
            "perm_view_feed_correlations": False,
            "perm_analyst_data": True,
            "permission": "3",
            "permission_description": "Read/Write/Publish",
        },
        "Organisation": {
            "id": "2",
            "name": "CIRCL",
            "uuid": str(uuid.uuid4()),
            "local": True,
        },
        "UserSetting": [],
    }


@router.get("/attributes/describeTypes.json")
async def describe_types() -> dict:
    """A reduced attribute type catalogue."""
    kinds = ["md5", "sha1", "sha256", "domain", "ip-dst", "ip-src", "url", "text"]
    return {
        "result": {
            "sane_defaults": {
                kind: {"default_category": "Network activity", "to_ids": 1}
                for kind in kinds
            },
            "types": kinds,
            "categories": ["Network activity", "Payload delivery", "Other"],
            "category_type_mappings": {
                "Network activity": kinds,
                "Payload delivery": kinds,
                "Other": ["text"],
            },
        }
    }


@router.post("/events/restSearch")
async def rest_search(request: Request) -> dict:
    """Two pages of events: the second one is empty."""
    query = await request.json()
    if int(query.get("page") or 1) > 1:
        return {"response": []}
    limit = int(query.get("limit") or 10)
    return {"response": events()[:limit]}


@router.post("/events/add")
@router.post("/events/add/{extra:path}")
async def add_event(request: Request) -> dict:
    """The event is stored and answered with its identifiers, as MISP does."""
    body = await request.json()
    event = body.get("Event", body)
    event_id = str(len(CREATED) + 2000)
    event["id"] = event_id
    event.setdefault("uuid", str(uuid.uuid4()))
    event.setdefault("Orgc", {"id": "2", "name": "CIRCL"})
    event["org_id"] = "2"
    event["orgc_id"] = "2"
    event["timestamp"] = str(int(time.time()))
    for attribute in event.get("Attribute", []):
        attribute.setdefault("uuid", str(uuid.uuid4()))
        attribute["event_id"] = event_id
    CREATED[event["uuid"]] = event
    return {"Event": event}


@router.get("/events/view/{identifier}")
async def view_event(identifier: str) -> Response:
    """A known event, else MISP's 404 error body."""
    for event in CREATED.values():
        if identifier in (event["id"], event["uuid"]):
            return JSONResponse({"Event": event})
    return JSONResponse(
        {
            "name": "Invalid event.",
            "message": "Invalid event.",
            "url": f"/events/view/{identifier}",
        },
        status_code=404,
    )


@router.post("/events/edit/{identifier}")
async def edit_event(identifier: str, request: Request) -> Response:
    body = await request.json()
    event = body.get("Event", body)
    for known in CREATED.values():
        if identifier in (known["id"], known["uuid"]):
            known.update(event)
            known["timestamp"] = str(int(time.time()))
            return JSONResponse({"Event": known})
    return JSONResponse({"name": "Invalid event.", "message": "Invalid event."}, 404)


@router.delete("/events/delete/{identifier}")
@router.post("/events/delete/{identifier}")
async def delete_event(identifier: str) -> dict:
    for key, event in list(CREATED.items()):
        if identifier in (event["id"], event["uuid"]):
            del CREATED[key]
    return {
        "saved": True,
        "success": True,
        "name": "Event deleted.",
        "message": "Event deleted.",
        "url": f"/events/delete/{identifier}",
    }


@router.post("/objects/delete/{identifier}")
@router.post("/objects/delete/{identifier}/{hard}")
async def delete_object(identifier: str) -> dict:
    return {
        "name": "Object deleted.",
        "message": "Object deleted.",
        "url": f"/objects/delete/{identifier}",
    }


@router.post("/events/publish/{identifier}")
@router.post("/events/alert/{identifier}")
async def publish_event(identifier: str) -> dict:
    return {
        "name": "Job queued",
        "message": "Job queued",
        "url": f"/events/publish/{identifier}",
        "id": str(fake.random_int(1, 900)),
        "saved": True,
        "success": True,
    }


@router.get("/manifest.json")
async def manifest() -> dict:
    """The feed manifest: event uuid -> its metadata."""
    return {
        key: {
            "Orgc": {"name": event["Event"]["Orgc"]["name"], "uuid": uuid.uuid4().hex},
            "Tag": [
                {"name": tag["name"], "colour": tag["colour"], "exportable": True}
                for tag in event["Event"]["Tag"]
            ],
            "info": event["Event"]["info"],
            "date": event["Event"]["date"],
            "analysis": event["Event"]["analysis"],
            "threat_level_id": event["Event"]["threat_level_id"],
            "timestamp": event["Event"]["timestamp"],
        }
        for key, event in _feed().items()
    }


@router.get("/{event_uuid}.json")
async def feed_event(event_uuid: str) -> Response:
    event = _feed().get(event_uuid)
    if event is None:
        return JSONResponse({"message": "Not found"}, status_code=404)
    return JSONResponse(event)
