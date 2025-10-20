# OpenCTI Fake APIs

These are fake APIs designed to make development and testing easier for OpenCTI users and developers. They simulate various data sources and services that can be integrated with the OpenCTI platform.

This project is built with [FastAPI↗](https://fastapi.tiangolo.com/), a modern, fast (high-performance), web framework for building APIs with Python 3.7+ based on standard Python type hints.

## Table of Contents

*   [Prerequisites](#prerequisites)
*   [Installation](#installation)
*   [API Usage](#api-usage)

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
