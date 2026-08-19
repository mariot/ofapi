from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_tanium_threat_response_alerts_returns_empty_data():
    response = client.get("/tanium/plugin/products/threat-response/api/v1/alerts")
    assert response.status_code == 200
    assert response.json() == {"data": []}
