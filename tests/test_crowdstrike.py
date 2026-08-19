from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_crowdstrike_oauth2_token():
    response = client.post(
        "/crowdstrike/oauth2/token",
        data={"client_id": "client", "client_secret": "secret"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["expires_in"] == 1799


def test_crowdstrike_query_alerts_v2_returns_empty_resources():
    response = client.get(
        "/crowdstrike/alerts/queries/alerts/v2",
        params={"filter": "timestamp:>'2024-01-01T00:00:00Z'"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["resources"] == []


def test_crowdstrike_entities_alerts_v2_returns_empty_resources():
    response = client.post(
        "/crowdstrike/alerts/entities/alerts/v2",
        json={"composite_ids": ["fake-id"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["resources"] == []
