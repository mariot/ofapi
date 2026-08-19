from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_palo_alto_cortex_xsoar_search_incidents_returns_empty_by_default():
    response = client.post(
        "/palo-alto-cortex-xsoar/xsoar/public/v1/incidents/search",
        json={
            "filter": {
                "page": 0,
                "size": 100,
                "sort": [{"field": "created", "asc": True}],
            }
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 0
    assert body["data"] == []
