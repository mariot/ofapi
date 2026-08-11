"""Factories for the Splunk KV store REST API (``/servicesNS``).

The OpenCTI ``splunk`` stream connector creates a KV store collection at
startup and then mirrors the live stream into it, one document per entity,
using ``POST``/``PUT``/``DELETE`` on ``storage/collections/data/<collection>``.
Splunk answers a write with the ``_key`` of the affected document, so the fake
keeps the documents around to answer reads and to make ``DELETE`` on an unknown
key return ``404`` the way Splunk does.
"""

from dataclasses import dataclass

import factory

from app.api.utils import InMemoryCollection

# collection name -> {_key: document}
KV_STORE: dict[str, InMemoryCollection] = {}


def collection(name: str) -> InMemoryCollection:
    """Return the store for ``name``, creating it on first use."""
    return KV_STORE.setdefault(name, InMemoryCollection())


@dataclass
class CollectionConfig:
    name: str
    disabled: bool
    author: str


class CollectionConfigFactory(factory.Factory):
    class Meta:
        model = CollectionConfig

    name = "opencti"
    disabled = False
    author = "nobody"


def collection_config_entry(name: str) -> dict:
    """Return the Atom-ish envelope Splunk answers a collection creation with."""
    config = CollectionConfigFactory(name=name)
    return {
        "links": {"create": "/services/storage/collections/config/_new"},
        "origin": "https://splunk.example.com/services/storage/collections/config",
        "paging": {"total": 1, "perPage": 30, "offset": 0},
        "entry": [
            {
                "name": config.name,
                "id": (
                    "https://splunk.example.com/servicesNS/nobody/search/storage/"
                    f"collections/config/{config.name}"
                ),
                "author": config.author,
                "content": {"disabled": config.disabled},
            }
        ],
    }
