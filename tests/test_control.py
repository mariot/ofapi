import pytest
from fastapi.testclient import TestClient

from app import control
from app.main import app

client = TestClient(app)

ALERTS = "/microsoft-graph/v1.0/security/alerts_v2"
ENDPOINT_FILTER = {"$filter": "serviceSource eq 'microsoftDefenderForEndpoint'"}
AUTH = {"Authorization": "Bearer fake-token"}


@pytest.fixture(autouse=True)
def reset_control():
    control.reset()
    yield
    control.reset()


def test_rule_scripts_a_timeline_then_falls_through_to_the_real_fake():
    response = client.post(
        "/_control/rules",
        json={
            "path": ALERTS,
            "method": "GET",
            "responses": [{"body": {"value": []}}, {"body": {"value": []}}],
        },
    )
    assert response.status_code == 201
    rule_id = response.json()["id"]

    polls = [
        client.get(ALERTS, params=ENDPOINT_FILTER, headers=AUTH).json()["value"]
        for _ in range(3)
    ]
    assert polls[0] == []
    assert polls[1] == []
    assert polls[2][0]["serviceSource"] == "microsoftDefenderForEndpoint"

    rules = client.get("/_control/rules").json()
    assert rules[0]["id"] == rule_id
    assert rules[0]["calls"] == 3


def test_rule_can_keep_answering_the_last_step():
    client.post(
        "/_control/rules",
        json={
            "path": "/echo",
            "responses": [{"status": 429, "headers": {"Retry-After": "1"}}],
            "then": "last",
        },
    )
    for _ in range(3):
        response = client.get("/echo")
        assert response.status_code == 429
        assert response.headers["retry-after"] == "1"


def test_passthrough_step_and_text_body():
    client.post(
        "/_control/rules",
        json={
            "path": "^/echo$",
            "responses": [
                {"passthrough": True},
                {"text": "<xml/>", "content_type": "application/xml"},
            ],
        },
    )
    first = client.post("/echo", json={"a": 1})
    assert first.status_code == 200  # served by the real /echo
    second = client.get("/echo")
    assert second.text == "<xml/>"
    assert second.headers["content-type"].startswith("application/xml")
    third = client.get("/echo")  # steps exhausted: back to the real fake
    assert third.status_code == 200

    journal = client.get("/_control/journal").json()
    assert [e["served_by"] for e in journal] == ["fake", "rule", "fake"]
    assert all(e["rule_id"] is not None for e in journal)


def test_rule_method_filter():
    client.post(
        "/_control/rules",
        json={"path": "/echo", "method": "POST", "responses": [{"status": 503}]},
    )
    assert client.get("/echo").status_code == 200
    assert client.post("/echo").status_code == 503


def test_rule_can_be_deleted():
    rule_id = client.post(
        "/_control/rules",
        json={"path": "/echo", "responses": [{"status": 503}], "then": "last"},
    ).json()["id"]
    assert client.delete(f"/_control/rules/{rule_id}").status_code == 204
    assert client.get("/echo").status_code == 200
    assert client.delete(f"/_control/rules/{rule_id}").status_code == 404


def test_rule_requires_at_least_one_response():
    response = client.post("/_control/rules", json={"path": "/echo", "responses": []})
    assert response.status_code == 422


def test_journal_records_requests_and_redacts_secrets():
    client.post(
        "/_control/rules", json={"path": "/echo", "responses": [{"status": 418}]}
    )
    client.post(
        "/echo?x=1",
        json={"hello": "world"},
        headers={"Authorization": "Bearer s3cr3t", "X-Api-Key": "k3y"},
    )
    client.get(ALERTS, params=ENDPOINT_FILTER, headers=AUTH)
    client.get("/_control/rules")  # control calls are not journaled

    journal = client.get("/_control/journal").json()
    assert [(e["method"], e["path"], e["status"]) for e in journal] == [
        ("POST", "/echo", 418),
        ("GET", ALERTS, 200),
    ]
    assert journal[0]["query"] == "x=1"
    assert journal[0]["body"] == {"hello": "world"}
    assert journal[0]["rule_id"] is not None
    assert journal[0]["headers"]["authorization"] == "<redacted>"
    assert journal[0]["headers"]["x-api-key"] == "<redacted>"
    assert "s3cr3t" not in str(journal)
    assert journal[1]["rule_id"] is None

    only_gets = client.get("/_control/journal", params={"method": "get"}).json()
    assert len(only_gets) == 1
    graph_only = client.get("/_control/journal", params={"path": "/microsoft"}).json()
    assert len(graph_only) == 1

    assert client.delete("/_control/journal").status_code == 204
    assert client.get("/_control/journal").json() == []


def test_reset_forgets_rules_and_journal():
    client.post(
        "/_control/rules", json={"path": "/echo", "responses": [{"status": 503}]}
    )
    client.get("/echo")
    assert client.post("/_control/reset").status_code == 204
    assert client.get("/_control/rules").json() == []
    assert client.get("/_control/journal").json() == []


def test_graph_alerts_v2_serves_endpoint_alert_for_defender_for_endpoint():
    response = client.get(ALERTS, params=ENDPOINT_FILTER, headers=AUTH)
    assert response.status_code == 200
    alert = response.json()["value"][0]
    assert alert["serviceSource"] == "microsoftDefenderForEndpoint"
    evidence_types = [e["@odata.type"] for e in alert["evidence"]]
    assert "#microsoft.graph.security.processEvidence" in evidence_types
    assert "#microsoft.graph.security.deviceEvidence" in evidence_types
    assert alert["createdDateTime"].endswith("Z")


def test_graph_alerts_v2_still_serves_o365_alert_by_default():
    response = client.get(ALERTS, headers=AUTH)
    alert = response.json()["value"][0]
    assert alert["serviceSource"] == "microsoftDefenderForOffice365"
