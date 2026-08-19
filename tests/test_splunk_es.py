from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_splunk_es_search_jobs_oneshot_returns_empty_results():
    response = client.post(
        "/splunk-es/services/search/jobs",
        data={
            "search": "search index=_notable earliest=-1h latest=now",
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": "0",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["results"] == []
