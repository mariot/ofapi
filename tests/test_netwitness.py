from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_netwitness_sdk_query_returns_empty_fields():
    response = client.get(
        "/netwitness/sdk",
        params={
            "msg": "query",
            "query": "select time,ip.src,ip.dst,url,service,alert where "
            'time="2024-01-01 00:00:00"-"2024-01-01 01:00:00" && (ip.src=1.2.3.4)',
            "force-content-type": "application/json",
            "size": 100,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["results"]["fields"] == []
