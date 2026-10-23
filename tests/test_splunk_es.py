from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_splunk_es_search_jobs_oneshot_matches_on_relative_time_bounds():
    """Real Splunk parses relative time bounds like '-1h'/'now' just fine,
    so this fake should return a match too (not always-empty)."""
    response = client.post(
        "/splunk-es/services/search/jobs",
        data={
            "search": "search index=_notable earliest=-1h latest=now",
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": "0",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body["results"]) == 1


def test_splunk_es_search_jobs_oneshot_rejects_iso_z_time_bounds():
    """A raw ISO-8601 'Z' earliest/latest (the collector bug this fake is
    designed to catch) must yield zero results, mirroring a real Splunk
    search FATAL on that unparseable format."""
    response = client.post(
        "/splunk-es/services/search/jobs",
        data={
            "search": (
                "search index=_notable "
                "earliest=2026-09-11T08:02:10.806778868Z "
                "latest=2026-09-11T09:02:10.806778868Z"
            ),
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": "0",
        },
    )
    assert response.status_code == 200
    assert response.json()["results"] == []


def test_splunk_es_search_jobs_oneshot_matches_on_epoch_time_bounds():
    """Epoch earliest/latest (what the collector should send) returns a
    matching fake notable."""
    response = client.post(
        "/splunk-es/services/search/jobs",
        data={
            "search": "search index=_notable earliest=1789113730 latest=1789117330",
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": "0",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body["results"]) == 1
    assert body["results"][0]["signature"] == "ofapi-fake-notable"
