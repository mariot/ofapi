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
| `email-m365`             | not usable yet, see [Microsoft 365](#microsoft-365)                                                         |
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
acting as the OpenAEV platform.

Assuming ofapi runs on `http://127.0.0.1:8000`:

| Collector                  | Environment variables                                                                                          |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------|
| `crowdstrike`               | `CROWDSTRIKE_BASE_URL=http://127.0.0.1:8000/crowdstrike`                                                        |
| `tanium-threat-response`    | `COLLECTOR_TANIUM_URL=http://127.0.0.1:8000/tanium`                                                             |
| `xtm-one`                   | `COLLECTOR_XTM_ONE_URL=http://127.0.0.1:8000/xtm-one`                                                           |
| `elastic`                   | `ELASTIC_BASE_URL=http://127.0.0.1:8000/elastic`                                                                |
| `logrhythm`                 | `LOGRHYTHM_BASE_URL=http://127.0.0.1:8000/logrhythm`                                                            |
| `netwitness`                | `NETWITNESS_BASE_URL=http://127.0.0.1:8000/netwitness`                                                          |
| `qradar`                    | `QRADAR_BASE_URL=http://127.0.0.1:8000/qradar`                                                                  |
| `splunk-es`                 | `SPLUNK_ES_BASE_URL=http://127.0.0.1:8000/splunk-es`                                                            |
| `palo-alto-cortex-xdr`      | `PALO_ALTO_CORTEX_XDR_FQDN=127.0.0.1:8443/palo-alto-cortex-xdr` served over TLS, see note below                 |
| `palo-alto-cortex-xsoar`    | `PALO_ALTO_CORTEX_XSOAR_API_URL=http://127.0.0.1:8000/palo-alto-cortex-xsoar`                                   |
| `sentinelone`               | `SENTINELONE_BASE_URL=http://127.0.0.1:8000/sentinelone`                                                        |
| `hiddenlayer`/`lakera-guard`/`prisma-airs`/`prompt-security` | run cleanly against Mimikyu's AI expectations endpoint alone; no vendor fake required for a clean startup |
| `microsoft-azure`/`microsoft-defender`/`microsoft-defender-o365`/`microsoft-entra`/`microsoft-intune` | not usable, see [Known limitations](#known-limitations)                          |
| `google-workspace`          | not usable, see [Known limitations](#known-limitations)                                                         |
| `aws-resources`             | starts and registers cleanly, but talks to real AWS (see [Known limitations](#known-limitations))               |

The `palo-alto-cortex-xdr` collector's client hardcodes `https://{fqdn}` (no scheme
override), so ofapi must be served over TLS for it. Generate a self-signed cert and run:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 825 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
uv run uvicorn app.main:app --host 127.0.0.1 --port 8443 \
  --ssl-keyfile key.pem --ssl-certfile cert.pem
REQUESTS_CA_BUNDLE=/path/to/cert.pem  # trust the cert for the collector's requests session
```

### Known limitations

A few collectors cannot be exercised against ofapi without changing the collector code
itself, which is out of scope for this project:

*   `microsoft-azure`, `microsoft-defender`, `microsoft-defender-o365`, `microsoft-entra`
    and `microsoft-intune` authenticate via MSAL/azure-identity's `ClientSecretCredential`,
    which posts directly to the *public* `https://login.microsoftonline.com/{tenant_id}`
    endpoint with no base-URL override exposed by the collector. Even a valid-looking fake
    tenant is rejected by the real Microsoft endpoint (`AADSTS900023`) before any request
    could reach ofapi.
*   `google-workspace` builds its Admin SDK client with `googleapiclient.discovery.build()`,
    whose bundled discovery document always targets `https://www.googleapis.com`, with no
    `discoveryServiceUrl` override passed by the collector.
*   `aws-resources` uses `boto3.Session().client(...)` with no `endpoint_url` override, so
    it always calls real AWS regional endpoints. It fails authentication gracefully
    (`AuthFailure`) rather than crashing, and still registers with the OpenAEV platform
    fine, but it cannot be driven end-to-end offline.

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
too. The `email-m365` injector cannot reach them yet, for two reasons that both live in
MSAL rather than in ofapi:

*   MSAL refuses non-HTTPS authorities. Serving ofapi behind TLS solves this - generate a
    certificate and trust it through `REQUESTS_CA_BUNDLE`:

    ```bash
    openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 825 \
      -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
    uv run uvicorn app.main:app --host 127.0.0.1 --port 8443 \
      --ssl-keyfile key.pem --ssl-certfile cert.pem
    ```

*   MSAL then asks the *public* `login.microsoftonline.com` instance-discovery endpoint
    whether the configured authority is a known cloud. No fake authority can satisfy that,
    and the injector does not expose MSAL's `instance_discovery` switch, so the flow stops
    before any request reaches ofapi.

Once the injector allows instance discovery to be disabled, these settings are enough:

```bash
M365_AUTHORITY_BASE_URL=https://127.0.0.1:8443/microsoft-identity
M365_GRAPH_BASE_URL=https://127.0.0.1:8443/microsoft-graph/v1.0
REQUESTS_CA_BUNDLE=/path/to/cert.pem
```
