from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_palo_alto_cortex_xdr_get_alerts_multi_events():
    response = client.post(
        "/palo-alto-cortex-xdr/public_api/v1/alerts/get_alerts_multi_events",
        params={"implant_id": "test-implant"},
        json={"request_data": {"search_from": 0, "search_to": 100}},
    )
    assert response.status_code == 200
    body = response.json()
    alerts = body["reply"]["alerts"]
    assert len(alerts) >= 1
    assert any(
        "test-implant" in (event.get("actor_process_image_name") or "")
        for alert in alerts
        for event in (alert.get("events") or [])
    )


def test_palo_alto_cortex_xdr_get_original_alerts_returns_empty_alerts():
    response = client.post(
        "/palo-alto-cortex-xdr/public_api/v1/alerts/get_original_alerts",
        json={"request_data": {"alert_id_list": ["1"]}},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["reply"]["alerts"] == []


def test_palo_alto_cortex_xdr_get_incident_extra_data():
    response = client.post(
        "/palo-alto-cortex-xdr/public_api/v1/incidents/get_incident_extra_data",
        json={"request_data": {"incident_id": "1"}},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["reply"]["incident"]["incident_id"]
    assert body["reply"]["alerts"]["data"] == []
    assert body["reply"]["file_artifacts"]["data"] == []
