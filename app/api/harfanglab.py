"""Factories for the HarfangLab threat intelligence API.

The OpenCTI ``harfanglab-intel`` stream connector resolves - and creates when
missing - one ``IOCSource``, ``SigmaSource`` and ``YaraSource`` at startup, then
mirrors indicators as ``IOCRule`` objects. Both source and rule lookups are
paginated Django REST Framework listings (``{"count", "next", "previous",
"results"}``), and the connector reads ``id``, ``type``, ``value``,
``description``, ``comment``, ``hl_status`` and ``enabled`` straight off the
object returned by a write, so the fake stores what it is given.
"""

from dataclasses import asdict, dataclass

import factory

from app.api.utils import InMemoryCollection

SOURCES = InMemoryCollection(id_prefix="source-")
IOC_RULES = InMemoryCollection(id_prefix="ioc-")

SOURCE_TYPES = ("IOCSource", "SigmaSource", "YaraSource")


@dataclass
class Source:
    id: str
    source_type: str
    name: str
    description: str
    enabled: bool


@dataclass
class IOCRule:
    id: str
    source_id: str
    type: str
    value: str
    description: str
    comment: str
    hl_status: str
    enabled: bool


class SourceFactory(factory.Factory):
    class Meta:
        model = Source

    id = factory.Faker("uuid4")
    source_type = "IOCSource"
    name = "from_OpenCTI"
    description = factory.Faker("sentence")
    enabled = True


class IOCRuleFactory(factory.Factory):
    class Meta:
        model = IOCRule

    id = factory.Faker("uuid4")
    source_id = factory.Faker("uuid4")
    type = "domain_name"
    value = factory.Faker("domain_name")
    description = factory.Faker("sentence")
    comment = ""
    hl_status = "stable"
    enabled = True


def paginated(results: list[dict]) -> dict:
    """Wrap ``results`` in the Django REST Framework envelope."""
    return {
        "count": len(results),
        "next": None,
        "previous": None,
        "results": results,
    }


def source_key(source_type: str, name: str) -> str:
    return f"{source_type}/{name}"


def list_sources(source_type: str, name: str | None) -> list[dict]:
    """Return the source lists of ``source_type``, optionally filtered by name."""
    if name is None:
        return SOURCES.find(source_type=source_type)
    found = SOURCES.get(source_key(source_type, name))
    return [found] if found else []


def create_source(source_type: str, name: str, description: str, enabled: bool) -> dict:
    """Create a source list and return it."""
    source = SourceFactory(
        id=SOURCES.next_id(),
        source_type=source_type,
        name=name,
        description=description,
        enabled=enabled,
    )
    return SOURCES.put(source_key(source_type, name), asdict(source))


def list_rules(
    source_id: str | None, ioc_type: str | None, value: str | None
) -> list[dict]:
    """Return the IOC rules matching the connector's lookup parameters."""
    criteria = {
        field: value
        for field, value in (
            ("source_id", source_id),
            ("type", ioc_type),
            ("value", value),
        )
        if value is not None
    }
    return IOC_RULES.find(**criteria)


def create_rule(body: dict) -> dict:
    """Create an IOC rule from the submitted body and return it."""
    rule = IOCRuleFactory(
        id=IOC_RULES.next_id(),
        source_id=body.get("source_id", ""),
        type=body.get("type", ""),
        value=body.get("value", ""),
        description=body.get("description", ""),
        comment=body.get("comment", ""),
        hl_status=body.get("hl_status", "stable"),
        enabled=body.get("enabled", True),
    )
    return IOC_RULES.put(rule.id, asdict(rule))


def update_rule(rule_id: str, body: dict) -> dict | None:
    """Apply ``body`` to an existing IOC rule and return it."""
    stored = IOC_RULES.get(rule_id)
    if stored is None:
        return None
    stored.update({key: value for key, value in body.items() if key != "id"})
    return stored


def delete_rule(rule_id: str) -> dict | None:
    """Remove an IOC rule and return it."""
    return IOC_RULES.pop(rule_id)
