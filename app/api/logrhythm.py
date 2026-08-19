"""Fakes for the LogRhythm Search API (``lr-search-api``).

The logrhythm collector uses plain ``requests`` (see
``collectors/logrhythm/src/services/client_api.py``), no vendor SDK. It
performs a two-step flow:

1. ``POST .../lr-search-api/actions/search-task`` -> must return a truthy
   ``TaskId`` (``data.get("TaskId") or data.get("taskId")``), else the
   collector raises ``LogRhythmQueryError``.
2. ``POST .../lr-search-api/actions/search-result`` -> polled in a loop until
   ``TaskStatus`` (case-insensitively) equals ``"completed"``. The fake must
   return ``"Completed"`` on the very first poll, otherwise the collector
   would busy-poll for the full ``search_timeout`` (default 5 minutes) before
   giving up - this is the LogRhythm-specific quirk to work around, analogous
   to the CrowdStrike ``meta`` requirement.

Once completed, the collector reads ``Items`` (falling back to ``items``) as
a list of dicts and pulls every field via ``.get()``, so an empty list is a
fully valid response.
"""

from factory import Factory, Faker
from pydantic import BaseModel


class SearchTaskResponse(BaseModel):
    TaskId: str  # noqa: N815 - LogRhythm API uses PascalCase on the wire


class SearchTaskResponseFactory(Factory):
    class Meta:
        model = SearchTaskResponse

    TaskId = Faker("uuid4")


class SearchResultResponse(BaseModel):
    TaskStatus: str = "Completed"  # noqa: N815 - PascalCase on the wire
    Items: list[dict] = []  # noqa: N815
