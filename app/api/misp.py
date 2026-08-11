"""Factories for the MISP REST API as consumed by PyMISP.

The OpenCTI ``misp-intel`` stream connector drives MISP through PyMISP, which
performs a handshake at import time - ``/servers/getVersion``,
``/servers/getPyMISPVersion.json``, ``/users/view/me`` (whose ``Role`` decides
which calls PyMISP even attempts) and ``/attributes/describeTypes.json`` - and
then manipulates events with ``/events/add``, ``/events/view/{uuid}``,
``/events/edit/{id}``, ``/events/delete/{uuid}`` and ``/events/publish/{id}``.

Events are stored so that the connector's update path, which re-reads the event
it created and edits it in place, behaves like the real thing.
"""

from dataclasses import asdict, dataclass, field

import factory

from app.api.utils import InMemoryCollection

EVENTS = InMemoryCollection()

MISP_VERSION = "2.5.24"

ROLE_PERMISSIONS = (
    "perm_add",
    "perm_modify",
    "perm_modify_org",
    "perm_publish",
    "perm_delegate",
    "perm_sync",
    "perm_admin",
    "perm_audit",
    "perm_auth",
    "perm_site_admin",
    "perm_regexp_access",
    "perm_tagger",
    "perm_template",
    "perm_sharing_group",
    "perm_tag_editor",
    "perm_sighting",
    "perm_object_template",
    "perm_publish_zmq",
    "perm_publish_kafka",
    "perm_decaying",
    "perm_galaxy_editor",
    "perm_warninglist",
    "perm_view_feed_correlations",
)


@dataclass
class Organisation:
    id: str
    name: str
    uuid: str
    local: bool = True


@dataclass
class Event:
    id: str
    uuid: str
    info: str
    date: str
    threat_level_id: str
    analysis: str
    distribution: str
    published: bool
    org_id: str
    orgc_id: str
    sharing_group_id: str
    timestamp: str
    attribute_count: str
    Org: dict
    Orgc: dict
    Attribute: list = field(default_factory=list)
    Object: list = field(default_factory=list)
    Tag: list = field(default_factory=list)
    Galaxy: list = field(default_factory=list)
    RelatedEvent: list = field(default_factory=list)
    ShadowAttribute: list = field(default_factory=list)


class OrganisationFactory(factory.Factory):
    class Meta:
        model = Organisation

    id = "1"
    name = "OFAPI"
    uuid = factory.Faker("uuid4")


class EventFactory(factory.Factory):
    class Meta:
        model = Event

    id = factory.Sequence(str)
    uuid = factory.Faker("uuid4")
    info = factory.Faker("sentence", nb_words=6)
    date = factory.Faker("date")
    threat_level_id = "2"
    analysis = "0"
    distribution = "1"
    published = False
    org_id = "1"
    orgc_id = "1"
    sharing_group_id = "0"
    timestamp = factory.Faker("unix_time")
    attribute_count = "0"
    Org = factory.LazyFunction(lambda: asdict(OrganisationFactory()))
    Orgc = factory.LazyFunction(lambda: asdict(OrganisationFactory()))


def user_me() -> dict:
    """Return the ``/users/view/me`` payload PyMISP inspects at connect time."""
    role = dict.fromkeys(ROLE_PERMISSIONS, True)
    role.update({"id": "1", "name": "admin", "permission": "3", "default_role": True})
    organisation = asdict(OrganisationFactory())
    return {
        "User": {
            "id": "1",
            "org_id": "1",
            "email": "opencti@ofapi.local",
            "authkey": "ofapi",
            "role_id": "1",
            "nids_sid": "1",
            "termsaccepted": True,
            "newsread": "0",
            "change_pw": "0",
            "contactalert": False,
            "disabled": False,
        },
        "Role": role,
        "UserSetting": [],
        "Organisation": organisation,
    }


def describe_types() -> dict:
    """Return the ``describeTypes`` payload PyMISP validates attributes against."""
    types = ["ip-src", "ip-dst", "domain", "hostname", "url", "md5", "sha256", "text"]
    categories = ["Network activity", "Payload delivery", "External analysis", "Other"]
    return {
        "result": {
            "types": types,
            "categories": categories,
            "category_type_mappings": dict.fromkeys(categories, types),
            "sane_defaults": {
                attribute_type: {
                    "default_category": "Network activity",
                    "to_ids": 1,
                }
                for attribute_type in types
            },
        }
    }


def _event_body(payload: dict) -> dict:
    """Unwrap the ``{"Event": {...}}`` envelope PyMISP sends."""
    return payload.get("Event", payload) if isinstance(payload, dict) else {}


def add_event(payload: dict) -> dict:
    """Create an event from ``/events/add`` and return it."""
    submitted = _event_body(payload)
    event = EventFactory(id=EVENTS.next_id())
    stored = asdict(event)
    stored.update(
        {
            key: value
            for key, value in submitted.items()
            if key != "id" and value is not None
        }
    )
    stored["id"] = event.id
    stored["uuid"] = submitted.get("uuid") or event.uuid
    stored["attribute_count"] = str(len(stored.get("Attribute", [])))
    EVENTS.put(stored["id"], stored)
    EVENTS.put(stored["uuid"], stored)
    return {"Event": stored}


def get_event(event_id: str) -> dict | None:
    """Return an event by id or uuid."""
    stored = EVENTS.get(event_id)
    return {"Event": stored} if stored else None


def edit_event(event_id: str, payload: dict) -> dict | None:
    """Apply ``/events/edit`` to a stored event and return it."""
    stored = EVENTS.get(event_id)
    if stored is None:
        return None
    submitted = _event_body(payload)
    stored.update(
        {
            key: value
            for key, value in submitted.items()
            if key not in ("id", "uuid") and value is not None
        }
    )
    stored["attribute_count"] = str(len(stored.get("Attribute", [])))
    return {"Event": stored}


def delete_event(event_id: str) -> dict:
    """Remove an event and return MISP's confirmation message."""
    stored = EVENTS.pop(event_id)
    if stored is not None:
        EVENTS.pop(stored["id"])
        EVENTS.pop(stored["uuid"])
        return {"message": "Event deleted.", "saved": True, "success": True}
    return {"message": "Event not found.", "saved": False, "errors": "Not found"}


def search_events(payload: dict) -> list[dict]:
    """Answer ``/events/restSearch``, optionally filtered by uuid."""
    wanted = payload.get("uuid") if isinstance(payload, dict) else None
    if wanted:
        stored = EVENTS.get(wanted)
        return [{"Event": stored}] if stored else []
    seen: list[dict] = []
    for stored in EVENTS.values():
        if stored not in seen:
            seen.append(stored)
    return [{"Event": stored} for stored in seen]
