from pydantic import BaseModel


class SearchJobResponse(BaseModel):
    """Response for ``POST /services/search/jobs``.

    The collector always calls this with ``exec_mode=oneshot``, meaning
    Splunk runs the search synchronously and returns the results directly in
    this same response (no separate job-status/poll or results endpoint is
    ever hit for this collector).
    """

    results: list[dict] = []
