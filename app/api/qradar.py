from factory import Factory, Faker
from pydantic import BaseModel


class CreateSearchResponse(BaseModel):
    """Response for ``POST /api/ariel/searches``.

    The collector only reads ``search_id`` from this payload.
    """

    search_id: str
    status: str = "WAIT"


class CreateSearchResponseFactory(Factory):
    class Meta:
        model = CreateSearchResponse

    search_id = Faker("uuid4")


class SearchStatusResponse(BaseModel):
    """Response for ``GET /api/ariel/searches/{search_id}``.

    The collector polls this until ``status`` is ``COMPLETED`` (or raises on
    ``ERROR``/``CANCELED``). The fake always reports the search as already
    completed on the first poll, so no in-memory poll-count state machine is
    needed.
    """

    search_id: str
    status: str = "COMPLETED"


class SearchResultsResponse(BaseModel):
    """Response for ``GET /api/ariel/searches/{search_id}/results``.

    The real Ariel results API keys the row list by the data source name
    (e.g. ``events`` or ``flows``), so the payload is built dynamically from
    the requested ``data_source`` rather than modeled as a fixed field.
    """

    @staticmethod
    def for_data_source(data_source: str) -> dict:
        """Return an empty results payload keyed by the requested data source."""
        return {data_source: []}
