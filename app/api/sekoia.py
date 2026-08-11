"""Factories for the Sekoia.io intelligence collection API.

The OpenCTI ``sekoia-intel`` stream connector checks that its IOC collection
exists, pushes indicators as free text to ``/{collection}/indicators/text``, and
resolves them back through ``/{collection}/indicators?term=`` before deleting
them one by one. The fake indexes what it was given by term so the delete path
is reachable.
"""

from dataclasses import asdict, dataclass

import factory

from app.api.utils import InMemoryCollection

INDICATORS = InMemoryCollection(id_prefix="sekoia-ioc-")


@dataclass
class Indicator:
    id: str
    value: str
    type: str
    valid_from: str
    valid_until: str
    revoked: bool


class IndicatorFactory(factory.Factory):
    class Meta:
        model = Indicator

    id = factory.Faker("uuid4")
    value = factory.Faker("domain_name")
    type = "indicator"
    valid_from = factory.Faker("iso8601")
    valid_until = factory.Faker("iso8601")
    revoked = False


def import_indicators(text: str) -> dict:
    """Store every non-empty line of ``text`` as an indicator."""
    created = []
    for line in (text or "").splitlines():
        term = line.strip()
        if not term:
            continue
        indicator = IndicatorFactory(id=INDICATORS.next_id(), value=term)
        stored = asdict(indicator)
        INDICATORS.put(indicator.id, stored)
        created.append(stored)
    return {"created": len(created), "items": created}


def search_indicators(term: str | None) -> dict:
    """Return the indicators whose value matches ``term``."""
    items = INDICATORS.values() if term is None else INDICATORS.find(value=term)
    return {"items": items, "total": len(items)}


def delete_indicator(indicator_id: str) -> dict | None:
    """Remove an indicator and return it."""
    return INDICATORS.pop(indicator_id)
