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


def test_crowdstrike_entities_alerts_v2_returns_one_alert_per_composite_id():
    response = client.post(
        "/crowdstrike/alerts/entities/alerts/v2",
        json={"composite_ids": ["cid:alert-1", "cid:alert-2"]},
    )
    assert response.status_code == 200
    resources = response.json()["resources"]
    assert [a["composite_id"] for a in resources] == ["cid:alert-1", "cid:alert-2"]
    assert [a["id"] for a in resources] == ["alert-1", "alert-2"]
    # every field the OpenAEV collector parses is present
    for alert in resources:
        assert alert["filename"].endswith(".exe")
        assert alert["parent_details"]["filename"]
        assert alert["grandparent_details"]["filename"]
        assert alert["device"]["hostname"]
        assert alert["pattern_disposition"] == 0
        assert alert["display_name"]
        assert alert["created_timestamp"]
        assert alert["updated_timestamp"]


def test_crowdstrike_entities_alerts_v2_without_ids_returns_empty_resources():
    response = client.post("/crowdstrike/alerts/entities/alerts/v2", json={})
    assert response.status_code == 200
    assert response.json()["resources"] == []
