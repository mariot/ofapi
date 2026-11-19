# OpenCTI Fake APIs

These are fake APIs designed to make development and testing easier for OpenCTI users and developers. They simulate various data sources and services that can be integrated with the OpenCTI platform.

They also back the OpenAEV injectors, so an injector that would normally call Shodan, Censys, Slack, Gmail or Microsoft Graph can be exercised end to end without credentials and without a single packet leaving the machine. See [OpenAEV injectors](#openaev-injectors).

This project is built with [FastAPI↗](https://fastapi.tiangolo.com/), a modern, fast (high-performance), web framework for building APIs with Python 3.7+ based on standard Python type hints.

## Table of Contents

*   [Prerequisites](#prerequisites)
*   [Installation](#installation)
*   [API Usage](#api-usage)
*   [OpenAEV injectors](#openaev-injectors)
*   [OpenAEV collectors](#openaev-collectors)

## Prerequisites

Before you begin, ensure you have the following installed on your system:

*   [Docker↗](https://www.docker.com/get-started)
*   [Docker Compose↗](https://docs.docker.com/compose/install/)

## Installation

Follow these steps to set up the project locally.

1.  **Clone the repository:**

    ```bash
    git clone git@github.com:mariot/ofapi.git
    cd ofapi
    ```

2.  **Build and run with Docker:** Use Docker to build and run the application.

*   Run with Docker

      ```bash
      docker build -t opencti-fake-apis .
      docker run -d -p 8000:80 --name ofapi opencti-fake-apis
      ```

  *   Run with Docker Compose

      ```bash
      docker compose up -d
      ```

## API Usage

Once the server is running, you can interact with the API using the automatically generated interactive documentation.

*   **Swagger UI (Interactive Docs):** Navigate to [http://127.0.0.1:8000/docs↗](http://127.0.0.1:8000/docs) in your browser. This interface allows you to visualize and interact with the API's resources without having any of the implementation logic in place.

*   **ReDoc (Alternative Docs):** Navigate to [http://127.0.0.1:8000/redoc↗](http://127.0.0.1:8000/redoc) for an alternative documentation view.

## Scenario control API

Every fake goes through a small control layer, driven from `/_control/*` by whoever runs
the test (never by the collector or injector under test).

| Endpoint | Purpose |
| --- | --- |
| `POST /_control/rules` | Script what matching requests answer, call after call |
| `GET /_control/rules` | Current rules, with how many calls each one served |
| `DELETE /_control/rules/{id}` / `DELETE /_control/rules` | Drop one rule / all rules |
| `GET /_control/journal?method=&path=` | Every request the fakes received: method, path, query, headers (secrets redacted), body, status, matching rule and whether the rule or the real fake answered (`served_by`); `path` is a prefix |
| `DELETE /_control/journal` | Clear the journal |
| `POST /_control/reset` | Forget every rule and the journal |

A rule matches on `path` (a prefix, or a regex when it starts with `^`) and an optional
`method`. Call *n* gets `responses[n]`; each step sets `status` (default 200), a JSON
`body` or a raw `text` with `content_type`, extra `headers` and `delay_ms`, or
`"passthrough": true` to let the real fake answer. Once the steps run out, the rule hands
over to the real fake (`"then": "passthrough"`, the default) or keeps repeating the last
step (`"then": "last"`).

```bash
# Defender alert latency: nothing on the first two polls, the real fixture from the third on
curl -X POST http://127.0.0.1:8000/_control/rules -H 'Content-Type: application/json' -d '{
  "path": "/microsoft-graph/v1.0/security/alerts_v2",
  "responses": [{"body": {"value": []}}, {"body": {"value": []}}]
}'

# rate limiting: answer 429 once, then behave normally
curl -X POST http://127.0.0.1:8000/_control/rules -H 'Content-Type: application/json' -d '{
  "path": "/crowdstrike/alerts", "responses": [{"status": 429, "headers": {"Retry-After": "1"}}]
}'

# what did the collector actually send?
curl 'http://127.0.0.1:8000/_control/journal?path=/microsoft-graph'
```

The journal keeps the last 5000 requests in memory. Header values whose name contains
`authorization`, `cookie`, `token`, `key` or `secret` are stored as `<redacted>`.

## OpenAEV injectors

Several [OpenAEV injectors↗](https://github.com/OpenAEV-Platform/injectors) talk to a
third-party SaaS. Every one of them exposes the vendor base URL as configuration, so
pointing it at ofapi is enough to run the full inject lifecycle offline - typically
alongside [Mimikyu↗](https://github.com/mariot/Mimikyu), which plays the OpenAEV
platform.

Assuming ofapi runs on `http://127.0.0.1:8000`:

| Injector                 | Environment variables                                                                                       |
|--------------------------|-------------------------------------------------------------------------------------------------------------|
| `censys`                 | `CENSYS_BASE_URL=http://127.0.0.1:8000/censys`                                                              |
| `shodan`                 | `SHODAN_BASE_URL=http://127.0.0.1:8000/shodan/`                                                             |
| `slack`                  | `SLACK_BASE_URL=http://127.0.0.1:8000/slack/api`                                                            |
| `teams`                  | `TEAMS_AUTHORITY_BASE_URL=http://127.0.0.1:8000/microsoft-identity`<br>`TEAMS_GRAPH_BASE_URL=http://127.0.0.1:8000/microsoft-graph/v1.0` |
| `email-google-workspace` | `GWS_GMAIL_BASE_URL=http://127.0.0.1:8000/gmail/v1` and `token_uri` set to `http://127.0.0.1:8000/google-oauth2/token` in the service account JSON |
| `email-m365`             | TLS authority plus a test-side MSAL patch, see [Microsoft 365](#microsoft-365)                              |
| `ai-redteam`             | inject content `target_endpoint=http://127.0.0.1:8000/openai/v1`                                            |
| `http-query`             | inject content `uri=http://127.0.0.1:8000/echo`                                                             |

Two details are easy to get wrong:

*   The Shodan base URL **must** end with a slash. The injector joins the endpoint with
    `urljoin()`, which replaces the last path segment when the base has none.
*   The Google service account needs a real RSA private key, because google-auth signs a
    JWT assertion before posting it to `token_uri`. The signature is never verified, so any
    generated key works: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`.

## OpenAEV collectors

Several [OpenAEV collectors↗](https://github.com/OpenAEV-Platform/collectors) poll a
third-party vendor API and report matched expectations back to OpenAEV. As with
injectors, most collectors expose the vendor base URL as configuration, so pointing it at
ofapi runs the collector offline - alongside [Mimikyu↗](https://github.com/mariot/Mimikyu)
acting as the OpenAEV platform, or against a real platform with
staticfire, whose recipes script the vendor
answers below for each verdict and check what the collector reports.

Assuming ofapi runs on `http://127.0.0.1:8000` (and `https://127.0.0.1:8443` where noted):

| Collector | Environment variables | Data to script |
|---|---|---|
| `crowdstrike` | `CROWDSTRIKE_API_BASE_URL=http://127.0.0.1:8000/crowdstrike` | `alerts/queries/alerts/v2` ids and `alerts/entities/alerts/v2` alerts whose `filename` is the implant; `pattern_disposition` 2048 when blocked, 0 when only detected |
| `sentinelone` | `SENTINELONE_BASE_URL=http://127.0.0.1:8000/sentinelone`, `SENTINELONE_ENABLE_ALERTS=false` (the unified alerts GraphQL API is not faked) | `web/api/v2.1/threats` (mitigation status `success` when blocked) and their `explore/events` naming the implant as `parentProcessName` |
| `tanium-threat-response` | `COLLECTOR_TANIUM_URL=http://127.0.0.1:8000/tanium` | `threat-response/api/v1/alerts` whose `details` (a JSON string) has the implant as acting process path |
| `palo-alto-cortex-xdr` | `PALO_ALTO_CORTEX_XDR_FQDN=127.0.0.1:8443/palo-alto-cortex-xdr` over TLS, see below | `alerts/get_alerts_multi_events` alerts with the implant in `events[].actor_process_image_name`, `action_pretty` Detected/Prevented |
| `palo-alto-cortex-xsoar` | `PALO_ALTO_CORTEX_XSOAR_API_URL=http://127.0.0.1:8000/palo-alto-cortex-xsoar` | `incidents/search` incidents whose XDR alert `detection_timestamp` falls inside the expectation window |
| `elastic` | `ELASTIC_BASE_URL=http://127.0.0.1:8000/elastic` | `<index>/_search` hits whose `url.path` is the implant download path `/api/injects/<inject>/<agent>/executable-payload` |
| `logrhythm` | `LOGRHYTHM_BASE_URL=http://127.0.0.1:8000/logrhythm` | `lr-search-api/actions/search-result` items with that path as `url` |
| `netwitness` | `NETWITNESS_BASE_URL=http://127.0.0.1:8000/netwitness` | `sdk` query meta with that path as `url` |
| `qradar` | `QRADAR_BASE_URL=http://127.0.0.1:8000/qradar` | `ariel/searches/<id>/results` events with that path as `URL` |
| `splunk-es` | `SPLUNKES_BASE_URL=http://127.0.0.1:8000/splunk-es` | `services/search/jobs` results whose `_raw` names the implant |
| `xtm-one` | `COLLECTOR_XTM_ONE_URL=http://127.0.0.1:8000/xtm-one` | `api/v1/audit-logs` events quoting the inject's AI marker, `blocked` when prevented |
| `lakera-guard` / `hiddenlayer` / `prisma-airs` / `prompt-security` | `COLLECTOR_BASE_URL=http://127.0.0.1:8000/<any prefix>` | no route: script the vendor scan path (`guard`, `detection/v1/interactions`, `v1/scan/sync/request`, `api/protect`) with a flagged/blocked or clean verdict |
| `cisco-ai-defense` | `COLLECTOR_BASE_URL=http://127.0.0.1:8000` (scheme and host only, a path is refused) | script `/api/v1/inspect/prompt` |
| `mitre-atlas` | `COLLECTOR_STIX_URL=http://127.0.0.1:8000/mitre-atlas/stix-atlas.json` | served: 2 tactics, 3 techniques (one sub-technique), 1 revoked |
| `nvd-nist-cve` | `NVDNISTCVE_API_BASE_URL=http://127.0.0.1:8000/nvd/rest/json` | served: 3 `CVE-2099-*` CVEs, one without CVSS v3.1 |
| `openaev` | `OPENAEV_URL_PREFIX=http://127.0.0.1:8000/openaev-payloads/` (trailing slash) | served: a native and a community payload |
| `aws-resources` | `AWS_ENDPOINT_URL_EC2=http://127.0.0.1:8000/aws-ec2` (botocore's per-service override) | served: `DescribeInstances` with a running, a terminated and an address-less instance |

The `palo-alto-cortex-xdr` collector's client hardcodes `https://{fqdn}` (no scheme
override), so ofapi must be served over TLS for it. Generate a self-signed cert and run:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 825 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
uv run uvicorn app.main:app --host 127.0.0.1 --port 8443 \
  --ssl-keyfile key.pem --ssl-certfile cert.pem
REQUESTS_CA_BUNDLE=/path/to/cert.pem  # trust the cert for the collector's requests session
```

Scripted rules and the journal live in the process: to serve HTTP and TLS with the same
state, run both servers from one process (staticfire's `ofapi_dual.py` does that).

### Known limitations

These collectors cannot be pointed at ofapi without changing their code, because their
vendor host is hardcoded:

*   `microsoft-defender` and `microsoft-defender-o365` build their MSAL authority with
    `AuthorityBuilder(AZURE_PUBLIC, tenant)`, so authentication always goes to
    `login.microsoftonline.com`. Their Graph side is configurable (`SOURCE_BASE_URL`) and
    `microsoft-graph/v1.0/security/alerts_v2` is served here.
*   `microsoft-azure`, `microsoft-intune` and `microsoft-sentinel` hardcode both the
    authority and the API host (`management.azure.com`, `graph.microsoft.com`,
    `api.loganalytics.azure.com`).
*   `microsoft-entra` uses msgraph's `GraphServiceClient`, whose Graph host cannot be
    changed from configuration.
*   `google-workspace` builds its Admin SDK client from the bundled discovery document
    (`admin.googleapis.com`), with no endpoint override passed by the collector.
*   `ovhcloud`, `mitre-attack` and `atomic-red-team` hardcode their source URLs.

### Endpoint behaviour

*   `POST /openai/v1/chat/completions` and `POST /anthropic/v1/messages` are *defended* by
    default: the fake model refuses and never echoes the `X-OAEV-Inject-Marker` canary, so an
    AI red-team inject reports `DEFENDED`. Add `?behaviour=vulnerable` to leak the marker and
    exercise the `VULNERABLE` path instead.
*   The Censys Search endpoints always return an empty `links.next`, which terminates the
    injector's cursor pagination after a single page.
*   `/echo` answers any method with a description of the request it received.

### Microsoft 365

The Graph endpoints are shared with the `teams` injector, so `sendMail` is served here
too. The `email-m365` injector reaches them under two conditions that both come from MSAL:

*   MSAL refuses non-HTTPS authorities: serve ofapi over TLS (see the XDR note above) and
    trust the certificate through `REQUESTS_CA_BUNDLE`.
*   MSAL asks the *public* `login.microsoftonline.com` instance-discovery endpoint whether
    the authority is a known cloud, unless `instance_discovery=False` is passed, which the
    injector does not expose. Until it does, turn it off when the interpreter starts, with
    a `sitecustomize.py` on the `PYTHONPATH` of the injector's process:

    ```python
    import msal

    _init = msal.ConfidentialClientApplication.__init__

    def _no_discovery(self, *args, **kwargs):
        kwargs.setdefault("instance_discovery", False)
        _init(self, *args, **kwargs)

    msal.ConfidentialClientApplication.__init__ = _no_discovery
    ```

```bash
M365_AUTHORITY_BASE_URL=https://127.0.0.1:8443/microsoft-identity
M365_GRAPH_BASE_URL=http://127.0.0.1:8000/microsoft-graph/v1.0
REQUESTS_CA_BUNDLE=/path/to/cert.pem
```
