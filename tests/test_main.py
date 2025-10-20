import gzip
import json
from io import BytesIO

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_hunt_io_feeds_c2():
    response = client.get("/hunt-io/feeds/c2")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/gzip"
    with gzip.GzipFile(fileobj=BytesIO(response.content)) as gzipped_file:
        raw_data = gzipped_file.read().decode("utf-8")
    lines = raw_data.splitlines()
    assert len(lines) == 10
    for line in lines:
        if line.strip():
            assert json.loads(line)
