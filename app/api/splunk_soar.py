"""Factories for the Splunk SOAR REST API (``/rest``).

The OpenCTI ``splunk-soar-push`` stream connector checks ``/rest/version`` at
startup, then mirrors OpenCTI containers as SOAR containers - creating them with
``POST /rest/container``, updating them with ``POST /rest/container/{id}``, and
attaching artifacts and notes. Containers are looked up again by
``_filter_external_id`` before an update, so they are stored.
"""

from dataclasses import asdict, dataclass

import factory

from app.api.utils import InMemoryCollection

CONTAINERS = InMemoryCollection()
ARTIFACTS = InMemoryCollection()
NOTES = InMemoryCollection()

SOAR_VERSION = "6.2.1.305"


@dataclass
class Container:
    id: str
    name: str
    label: str
    severity: str
    status: str
    container_type: str
    external_id: str
    description: str


@dataclass
class Artifact:
    id: str
    container_id: str
    name: str
    label: str
    type: str


@dataclass
class Note:
    id: str
    container_id: str
    title: str
    content: str
    note_type: str


class ContainerFactory(factory.Factory):
    class Meta:
        model = Container

    id = factory.Sequence(str)
    name = factory.Faker("sentence", nb_words=4)
    label = "events"
    severity = "medium"
    status = "new"
    container_type = "default"
    external_id = factory.Faker("uuid4")
    description = factory.Faker("sentence")


class ArtifactFactory(factory.Factory):
    class Meta:
        model = Artifact

    id = factory.Sequence(str)
    container_id = "1"
    name = factory.Faker("sentence", nb_words=3)
    label = "artifact"
    type = "network"


class NoteFactory(factory.Factory):
    class Meta:
        model = Note

    id = factory.Sequence(str)
    container_id = "1"
    title = factory.Faker("sentence", nb_words=3)
    content = factory.Faker("paragraph")
    note_type = "general"


def _store(collection: InMemoryCollection, model, body: dict) -> dict:
    created = model(id=collection.next_id())
    stored = asdict(created)
    stored.update({key: value for key, value in body.items() if key != "id"})
    stored["id"] = created.id
    return collection.put(created.id, stored)


def create_container(body: dict) -> dict:
    """Create a container and return SOAR's creation envelope."""
    stored = _store(CONTAINERS, ContainerFactory, body)
    return {"id": stored["id"], "success": True, "message": "success", **stored}


def update_container(container_id: str, body: dict) -> dict | None:
    """Apply an update to a stored container and return it."""
    stored = CONTAINERS.get(container_id)
    if stored is None:
        return None
    stored.update({key: value for key, value in body.items() if key != "id"})
    return {"id": stored["id"], "success": True, **stored}


def search_containers(external_id: str | None) -> dict:
    """Answer ``GET /rest/container`` with SOAR's ``count``/``data`` envelope."""
    if external_id is None:
        data = CONTAINERS.values()
    else:
        data = CONTAINERS.find(external_id=external_id.strip('"'))
    return {"count": len(data), "data": data}


def create_artifact(body: dict) -> dict:
    """Create an artifact and return SOAR's creation envelope."""
    stored = _store(ARTIFACTS, ArtifactFactory, body)
    return {"id": stored["id"], "success": True, **stored}


def create_note(body: dict) -> dict:
    """Create a note and return SOAR's creation envelope."""
    stored = _store(NOTES, NoteFactory, body)
    return {"id": stored["id"], "success": True, **stored}
