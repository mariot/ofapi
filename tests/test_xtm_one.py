from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_xtm_one_agents_returns_empty_items():
    response = client.get("/xtm-one/api/v1/agents")
    assert response.status_code == 200
    assert response.json() == {"items": []}


def test_xtm_one_audit_logs_returns_empty_items():
    response = client.get("/xtm-one/api/v1/audit-logs")
    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}
