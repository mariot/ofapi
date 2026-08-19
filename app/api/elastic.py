"""Fakes for the Elastic Security ``_search`` API.

The elastic collector talks to Elasticsearch with plain ``requests`` (no
official ``elasticsearch``/``elasticsearch8`` client, see
``collectors/elastic/src/services/client_api.py``), so there is no
``X-Elastic-Product`` response-header quirk to satisfy (that check only
exists in the official client's transport layer). The collector posts a
single ``_search`` query and only reads ``hits.hits[]._source`` off the
response (via defensive ``dict.get`` lookups in
``ElasticResponse.from_raw_response``), so an empty hits list is a fully
valid, error-free response.
"""

from pydantic import BaseModel


class Hits(BaseModel):
    total: dict = {"value": 0, "relation": "eq"}
    hits: list[dict] = []


class SearchResponse(BaseModel):
    took: int = 1
    timed_out: bool = False
    # NOTE: pydantic treats a leading-underscore attribute as private (it would
    # be silently dropped from model_dump()), so "_shards" is added as a plain
    # dict key in the route handler instead of being a model field here.
    hits: Hits = Hits()
