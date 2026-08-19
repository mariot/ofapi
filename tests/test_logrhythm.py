from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_logrhythm_search_task_returns_task_id():
    response = client.post(
        "/logrhythm/lr-search-api/actions/search-task",
        json={
            "maxMsgsToQuery": 100,
            "queryTimeout": 300,
            "queryRawLog": True,
            "queryEventManager": True,
            "dateCriteria": {
                "useInsertedDate": False,
                "lastIntervalValue": 60,
                "lastIntervalUnit": 4,
            },
            "queryFilter": {
                "msgFilterType": 2,
                "isSavedFilter": False,
                "filterGroup": {
                    "filterItemType": 1,
                    "fieldOperator": 1,
                    "filterMode": 1,
                    "filterGroupOperator": 1,
                    "filterItems": [],
                },
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["TaskId"]


def test_logrhythm_search_result_returns_completed_with_no_items():
    response = client.post(
        "/logrhythm/lr-search-api/actions/search-result",
        json={
            "TaskId": "fake-task-id",
            "PagedCriteria": {"PageNumber": 1, "PageSize": 100},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["TaskStatus"] == "Completed"
    assert body["Items"] == []
