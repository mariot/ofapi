"""Factories for the QRadar reference data collections API.

The OpenCTI ``qradar`` stream connector keeps a reference set per observable
type. At startup it lists the sets with ``GET /api/reference_data_collections/
sets`` (QRadar answers a bare JSON **array**) and creates the missing ones, then
mirrors the live stream into ``set_entries``. Updates and deletions are resolved
by searching ``set_entries`` with a ``filter`` of the form
``collection_id=<id> and notes="<opencti id>"``, so the entries are stored.
"""

import re
from dataclasses import asdict, dataclass

import factory

from app.api.utils import InMemoryCollection

SETS = InMemoryCollection()
SET_ENTRIES = InMemoryCollection()

_FILTER_PATTERN = re.compile(
    r'collection_id=(?P<collection_id>\d+)\s+and\s+notes="(?P<notes>[^"]*)"'
)


@dataclass
class ReferenceSet:
    id: str
    name: str
    entry_type: str
    timeout_type: str
    creation_time: int


@dataclass
class ReferenceSetEntry:
    id: str
    collection_id: str
    value: str
    source: str
    notes: str
    first_seen: int
    last_seen: int


class ReferenceSetFactory(factory.Factory):
    class Meta:
        model = ReferenceSet

    id = factory.Sequence(str)
    name = "OpenCTI - IPv4 Addresses"
    entry_type = "IP"
    timeout_type = "UNKNOWN"
    creation_time = factory.Faker("unix_time")


class ReferenceSetEntryFactory(factory.Factory):
    class Meta:
        model = ReferenceSetEntry

    id = factory.Sequence(str)
    collection_id = "1"
    value = factory.Faker("ipv4")
    source = "OpenCTI"
    notes = factory.Faker("uuid4")
    first_seen = factory.Faker("unix_time")
    last_seen = factory.Faker("unix_time")


def create_set(name: str, entry_type: str) -> dict:
    """Create a reference set and return it."""
    reference_set = ReferenceSetFactory(
        id=SETS.next_id(), name=name, entry_type=entry_type
    )
    return SETS.put(reference_set.id, asdict(reference_set))


def create_entry(collection_id: str, value: str, source: str, notes: str) -> dict:
    """Create an entry inside a reference set and return it."""
    entry = ReferenceSetEntryFactory(
        id=SET_ENTRIES.next_id(),
        collection_id=str(collection_id),
        value=value,
        source=source,
        notes=notes,
    )
    return SET_ENTRIES.put(entry.id, asdict(entry))


def search_entries(query: str | None) -> list[dict]:
    """Resolve QRadar's ``filter`` expression against the stored entries."""
    if not query:
        return SET_ENTRIES.values()
    match = _FILTER_PATTERN.search(query)
    if not match:
        return []
    return SET_ENTRIES.find(
        collection_id=match.group("collection_id"), notes=match.group("notes")
    )
