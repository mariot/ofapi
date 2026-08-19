from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_qradar_create_search_returns_search_id():
    response = client.post(
        "/qradar/api/ariel/searches",
        params={"query_expression": "SELECT * FROM events LAST 60 MINUTES"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["search_id"]


def test_qradar_search_status_returns_completed():
    create_response = client.post(
        "/qradar/api/ariel/searches",
        params={"query_expression": "SELECT * FROM events LAST 60 MINUTES"},
    )
    search_id = create_response.json()["search_id"]

    response = client.get(f"/qradar/api/ariel/searches/{search_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "COMPLETED"
    assert body["search_id"] == search_id


def test_qradar_search_results_returns_empty_events():
    create_response = client.post(
        "/qradar/api/ariel/searches",
        params={"query_expression": "SELECT * FROM events LAST 60 MINUTES"},
    )
    search_id = create_response.json()["search_id"]

    response = client.get(
        f"/qradar/api/ariel/searches/{search_id}/results",
        headers={"Range": "items=0-99"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["events"] == []


def test_qradar_search_results_uses_flows_data_source():
    create_response = client.post(
        "/qradar/api/ariel/searches",
        params={"query_expression": "SELECT * FROM flows LAST 60 MINUTES"},
    )
    search_id = create_response.json()["search_id"]

    response = client.get(f"/qradar/api/ariel/searches/{search_id}/results")
    assert response.status_code == 200
    body = response.json()
    assert body["flows"] == []
