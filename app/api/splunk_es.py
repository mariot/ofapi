import re

from pydantic import BaseModel

_EARLIEST_RE = re.compile(r"earliest=(\S+)")
_LATEST_RE = re.compile(r"latest=(\S+)")


class SearchJobResponse(BaseModel):
    """Response for ``POST /services/search/jobs``.

    The collector always calls this with ``exec_mode=oneshot``, meaning
    Splunk runs the search synchronously and returns the results directly in
    this same response (no separate job-status/poll or results endpoint is
    ever hit for this collector).
    """

    results: list[dict] = []


def _looks_like_epoch_or_relative(value: str) -> bool:
    """Return True for time bounds real Splunk actually parses.

    Real Splunk's ``earliest``/``latest`` accept epoch seconds (``1789113730``),
    relative time (``-3600s``, ``now``), or ``%m/%d/%Y:%H:%M:%S`` - but NOT
    ISO-8601 with a ``Z`` suffix/sub-second precision. Passing an unparseable
    value makes a real search FATAL and return zero results; this fake
    reproduces exactly that all-or-nothing behavior instead of a fixed reply,
    so a collector bug in the time-bound conversion is actually observable.
    """
    if value in ("now",):
        return True
    if value.lstrip("-+").isdigit():
        return True
    if re.match(r"^[+-]\d+(s|m|h|d|mon|y)$", value):
        return True
    return bool(re.match(r"^\d{1,2}/\d{1,2}/\d{4}:\d{2}:\d{2}:\d{2}$", value))


def build_search_job_response(search: str) -> SearchJobResponse:
    """Build the fake oneshot search response for a given SPL string.

    Returns one matching notable when both ``earliest``/``latest`` are in a
    format Splunk understands, or an empty result set otherwise (mirroring a
    real Splunk FATAL on unparseable time bounds, which still returns HTTP 200
    with zero results).
    """
    earliest_match = _EARLIEST_RE.search(search)
    latest_match = _LATEST_RE.search(search)
    if not earliest_match or not latest_match:
        return SearchJobResponse()
    if not _looks_like_epoch_or_relative(
        earliest_match.group(1)
    ) or not _looks_like_epoch_or_relative(latest_match.group(1)):
        return SearchJobResponse()
    return SearchJobResponse(
        results=[
            {
                "_time": "2026-09-11T08:05:00.000+00:00",
                "src_ip": "203.0.113.10",
                "dest_ip": "198.51.100.20",
                "signature": "ofapi-fake-notable",
                "rule_name": "OFAPI Fake Detection Rule",
                "event_type": "notable",
                "severity": "high",
            }
        ]
    )
