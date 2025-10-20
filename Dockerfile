FROM python:3.14-slim

ENV UV_COMPILE_BYTECODE=1
ENV UV_NO_EDITABLE=1
ENV UV_FROZEN=1
ENV UV_WORKING_DIRECTORY=/code


# Install uv.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /code

# Install the application dependencies.
COPY ./pyproject.toml /code/pyproject.toml
COPY ./uv.lock /code/uv.lock
RUN uv sync --no-dev --no-cache

# Copy the application into the container.
COPY ./app /code/app

# Run the application.
CMD ["/code/.venv/bin/fastapi", "run", "app/main.py", "--port", "80", "--host", "0.0.0.0"]
