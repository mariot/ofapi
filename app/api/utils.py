import itertools
import json
import threading
from typing import Any
from urllib.parse import parse_qs


class InMemoryCollection:
    """A tiny, thread-safe, process-local record store.

    Most fake APIs can answer from a factory alone, but the OpenCTI *stream*
    connectors replay a create/update/delete lifecycle: they look an object up
    by an identifier they wrote earlier and only update or delete it when the
    lookup succeeds. A stateless fake would silently skip those branches, so the
    vendors that need it keep their records here for the lifetime of the
    process.
    """

    def __init__(self, id_prefix: str = "") -> None:
        self._items: dict[str, dict[str, Any]] = {}
        self._counter = itertools.count(1)
        self._id_prefix = id_prefix
        self._lock = threading.Lock()

    def next_id(self) -> str:
        """Return a new identifier, unique for the lifetime of the process."""
        return f"{self._id_prefix}{next(self._counter)}"

    def put(self, key: str, item: dict[str, Any]) -> dict[str, Any]:
        """Store ``item`` under ``key`` and return it."""
        with self._lock:
            self._items[key] = item
        return item

    def get(self, key: str) -> dict[str, Any] | None:
        """Return the item stored under ``key``, if any."""
        return self._items.get(key)

    def pop(self, key: str) -> dict[str, Any] | None:
        """Remove the item stored under ``key`` and return it, if any."""
        with self._lock:
            return self._items.pop(key, None)

    def values(self) -> list[dict[str, Any]]:
        """Return every stored item."""
        return list(self._items.values())

    def find(self, **criteria: Any) -> list[dict[str, Any]]:
        """Return every item whose fields all equal the given values."""
        return [
            item
            for item in self.values()
            if all(item.get(field) == value for field, value in criteria.items())
        ]

    def clear(self) -> None:
        """Drop every stored item. Used by the tests to isolate cases."""
        with self._lock:
            self._items.clear()


def remove_private_attributes(data_dict: dict) -> dict:
    """
    Removes keys starting with an underscore from a dictionary,
    recursively handling nested dicts (and dicts inside lists/tuples).
    """

    def _clean(value):
        if isinstance(value, dict):
            return {
                k: _clean(v)
                for k, v in value.items()
                if not (isinstance(k, str) and k.startswith("_"))
            }
        if isinstance(value, list):
            return [_clean(item) for item in value]
        if isinstance(value, tuple):
            return tuple(_clean(item) for item in value)
        return value

    return _clean(data_dict)


async def read_form_field(request: Any, field: str) -> str | None:
    """Return a form field from a request whose content type may be wrong.

    Some clients post a URL-encoded body while announcing a JSON content type.
    The real vendor still reads it as a form, so the body is parsed both ways
    here instead of trusting the header.

    Args:
        request: The incoming request.
        field: Name of the field to read.

    Returns:
        The field value, or ``None`` when the body does not carry it.
    """
    body = (await request.body()).decode("utf-8", errors="replace")
    if not body:
        return None
    try:
        decoded = json.loads(body)
    except json.JSONDecodeError:
        pass
    else:
        if isinstance(decoded, dict):
            value = decoded.get(field)
            return None if value is None else str(value)
    parsed = parse_qs(body)
    values = parsed.get(field)
    return values[0] if values else None
