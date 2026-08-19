from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_sentinelone_get_threats_returns_empty_data():
    response = client.get(
        "/sentinelone/web/api/v2.1/threats",
        params={
            "createdAt__gte": "2024-01-01T00:00:00.000000Z",
            "createdAt__lt": "2024-01-01T01:00:00.000000Z",
            "sortOrder": "desc",
            "limit": 1000,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["data"] == []


def test_sentinelone_get_threat_events_returns_empty_data():
    response = client.get(
        "/sentinelone/web/api/v2.1/threats/fake-threat-id/explore/events",
        params={"limit": 100},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["data"] == []


def test_sentinelone_dv_init_query_returns_query_id():
    response = client.post(
        "/sentinelone/web/api/v2.1/dv/init-query",
        json={
            "query": 'tgtFileSha1 = "abc"',
            "fromDate": "2024-01-01T00:00:00.000000Z",
            "toDate": "2024-01-01T01:00:00.000000Z",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["data"]["queryId"]


def test_sentinelone_dv_query_status_is_immediately_finished():
    response = client.get(
        "/sentinelone/web/api/v2.1/dv/query-status",
        params={"queryId": "fake-query-id"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["data"]["responseState"] == "FINISHED"
    assert body["data"]["progressStatus"] == 100


def test_sentinelone_dv_events_returns_empty_data():
    response = client.get(
        "/sentinelone/web/api/v2.1/dv/events",
        params={"queryId": "fake-query-id"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["data"] == []
