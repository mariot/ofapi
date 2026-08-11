# OpenCTI Fake APIs

These are fake APIs designed to make development and testing easier for OpenCTI users and developers. They simulate various data sources and services that can be integrated with the OpenCTI platform.

They also back the OpenAEV injectors, so an injector that would normally call Shodan, Censys, Slack, Gmail or Microsoft Graph can be exercised end to end without credentials and without a single packet leaving the machine. See [OpenAEV injectors](#openaev-injectors).

This project is built with [FastAPI↗](https://fastapi.tiangolo.com/), a modern, fast (high-performance), web framework for building APIs with Python 3.7+ based on standard Python type hints.

## Table of Contents

*   [Prerequisites](#prerequisites)
*   [Installation](#installation)
*   [API Usage](#api-usage)
*   [OpenCTI connectors](#opencti-connectors)
*   [OpenAEV injectors](#openaev-injectors)

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

## OpenCTI connectors

Several [OpenCTI connectors↗](https://github.com/OpenCTI-Platform/connectors) push to, or
enrich from, a third-party SaaS. Each one takes the vendor base URL from configuration, so
pointing it at ofapi runs the whole connector lifecycle offline - typically alongside a
real OpenCTI platform, which stays the only genuine component in the loop.

Assuming ofapi runs on `http://127.0.0.1:8000`:

| Connector                  | Environment variables                                            |
|----------------------------|------------------------------------------------------------------|
| `ismalicious`              | `ISMALICIOUS_API_URL=http://127.0.0.1:8000/ismalicious`          |
| `splunk`                   | `SPLUNK_URL=http://127.0.0.1:8000/splunk`                        |
| `splunk-soar-push`         | `SPLUNK_SOAR_URL=http://127.0.0.1:8000/splunk-soar`              |
| `qradar`                   | `QRADAR_URL=http://127.0.0.1:8000/qradar`                        |
| `harfanglab-intel`         | `HARFANGLAB_INTEL_URL=http://127.0.0.1:8000/harfanglab`          |
| `sekoia-intel`             | `SEKOIA_INTEL_URL=http://127.0.0.1:8000/sekoia`                  |
| `pan-cortex-xsoar-intel`   | `XSOAR_URL=http://127.0.0.1:8000/cortex-xsoar`                   |
| `misp-intel`               | `MISP_URL=http://127.0.0.1:8000/misp`                            |
| `webhook`                  | `WEBHOOK_URL=http://127.0.0.1:8000/echo`                         |

### Stateful endpoints

Stream connectors replay a create/update/delete lifecycle: they look an object up by an
identifier they wrote earlier and only update or delete it when that lookup succeeds. A
purely generated answer would silently skip those branches, so the vendors above keep
their records in memory for the lifetime of the process - Splunk KV store documents,
QRadar reference sets and entries, HarfangLab source lists and IOC rules, Sekoia
indicators, Cortex XSOAR indicators, MISP events, and Splunk SOAR containers, artifacts
and notes. Restarting ofapi resets them.

Two details are easy to get wrong:

*   `GET /qradar/api/reference_data_collections/sets` answers with a bare JSON **array**,
    not an object, because that is what QRadar does and what the connector iterates over.
*   `GET /misp/users/view/me` must return a complete `Role` object. PyMISP reads the
    permission flags at connect time and disables features - or refuses to start - when
    they are missing.
*   The MISP endpoints answer at `/misp/...` **and** at the root, because PyMISP resolves
    every path with `urljoin()` against the configured URL. A base URL carrying a path is
    therefore discarded, and `MISP_URL=http://127.0.0.1:8000` reaches the same handlers.


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
