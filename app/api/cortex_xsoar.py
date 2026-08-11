"""Factories for the Cortex XSOAR indicator API (``/xsoar/public/v1``).

The OpenCTI ``pan-cortex-xsoar-intel`` stream connector posts indicators to
``indicator/create`` and ``indicator/edit`` and removes them through
``indicators/batchDelete``. XSOAR answers a write with the stored indicator, so
the fake echoes back what it was given, enriched with server-side fields.
"""

from dataclasses import asdict, dataclass

import factory

from app.api.utils import InMemoryCollection

INDICATORS = InMemoryCollection(id_prefix="xsoar-")


@dataclass
class Indicator:
    id: str
    version: int
    indicator_type: str
    value: str
    score: int
    timestamp: str
    modified: str
    sourceBrand: str  # noqa: N815 - mirrors the vendor's camelCase payload
    sourceInstance: str  # noqa: N815 - mirrors the vendor's camelCase payload
    expirationStatus: str  # noqa: N815 - mirrors the vendor's camelCase payload


class IndicatorFactory(factory.Factory):
    class Meta:
        model = Indicator

    id = factory.Faker("uuid4")
    version = 1
    indicator_type = "IP"
    value = factory.Faker("ipv4")
    score = 3
    timestamp = factory.Faker("iso8601")
    modified = factory.Faker("iso8601")
    sourceBrand = "OpenCTI"
    sourceInstance = "OpenCTI"
    expirationStatus = "active"


def upsert_indicator(body: dict) -> dict:
    """Create or replace an indicator from an ``indicator/create`` payload."""
    submitted = body.get("indicator", body) or {}
    indicator = IndicatorFactory(
        id=submitted.get("id") or INDICATORS.next_id(),
        indicator_type=submitted.get("indicator_type", "IP"),
        value=submitted.get("value", ""),
        score=submitted.get("score", 0),
    )
    stored = asdict(indicator)
    # XSOAR keeps every custom field the caller sent alongside its own.
    stored.update({key: value for key, value in submitted.items() if key != "id"})
    stored["id"] = indicator.id
    return INDICATORS.put(indicator.id, stored)


def delete_indicators(body: dict) -> dict:
    """Remove the indicators listed in a ``indicators/batchDelete`` payload."""
    ids = body.get("ids") or []
    deleted = [stored for stored in (INDICATORS.pop(str(id_)) for id_ in ids) if stored]
    return {"deleted": len(deleted), "total": len(ids)}
