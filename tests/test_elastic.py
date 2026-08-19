from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_elastic_search_alerts_returns_empty_hits():
    response = client.post(
        "/elastic/.alerts-security.alerts-*/_search",
        json={
            "size": 100,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [{"range": {"@timestamp": {"gte": "now-3600s"}}}]
                }
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["hits"]["hits"] == []
    assert body["hits"]["total"] == {"value": 0, "relation": "eq"}
    assert body["timed_out"] is False
