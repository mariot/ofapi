"""Fakes for the RSA NetWitness Core SDK query API (``GET /sdk?msg=query``).

The netwitness collector uses plain ``requests`` (see
``collectors/netwitness/src/services/client_api.py``), no vendor SDK, and
issues a single ``GET {base_url}/sdk`` request with
``msg=query&query=<NWQL>&force-content-type=application/json&size=...``
query parameters. There is no separate login/token endpoint - auth is either
HTTP Basic or a static ``Authorization: Bearer <token>`` header sent on every
request (see ``config.yml.sample``'s ``username``/``password`` vs ``token``).

The response is parsed by ``NetWitnessResponse.from_raw_response``, which
only reads ``results.fields`` (a flat list of ``{"group", "type", "value"}``
dicts) via ``dict.get`` with safe fallbacks, so an empty ``fields`` list is a
fully valid, error-free response.
"""

from pydantic import BaseModel


class Results(BaseModel):
    fields: list[dict] = []


class SdkQueryResponse(BaseModel):
    results: Results = Results()
