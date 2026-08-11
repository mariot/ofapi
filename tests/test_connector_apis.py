"""Tests for the fake APIs backing the OpenCTI connectors."""

import pytest
from fastapi.testclient import TestClient

from app.api import harfanglab, misp, qradar, sekoia, splunk, splunk_soar
from app.api.cortex_xsoar import INDICATORS as XSOAR_INDICATORS
from app.main import app

client = TestClient(app)

SPLUNK_COLLECTION = "/splunk/servicesNS/nobody/search/storage/collections"
OPENCTI_ID = "37489d92-8f7c-43e8-aaa7-64c2758ab9aa"


@pytest.fixture(autouse=True)
def _reset_stores():
    """Keep the stateful fakes from leaking records between test cases."""
    for store in (
        qradar.SETS,
        qradar.SET_ENTRIES,
        harfanglab.SOURCES,
        harfanglab.IOC_RULES,
        sekoia.INDICATORS,
        misp.EVENTS,
        splunk_soar.CONTAINERS,
        splunk_soar.ARTIFACTS,
        splunk_soar.NOTES,
        XSOAR_INDICATORS,
    ):
        store.clear()
    splunk.KV_STORE.clear()
    yield


def test_ismalicious_check():
    response = client.get(
        "/ismalicious/check", params={"query": "1.1.1.1", "enrichment": "standard"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["query"] == "1.1.1.1"
    assert body["malicious"] is True
    assert 0 <= body["confidenceScore"] <= 100
    assert body["categories"]
    assert all(source["name"] for source in body["sources"])
    assert body["metadata"]["threatLevel"]


def test_splunk_collection_accepts_a_mislabelled_form_body():
    # The connector posts a form body under an application/json header.
    response = client.post(
        "/splunk/servicesNS/nobody/search/storage/collections/config",
        content="name=opencti",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert response.json()["entry"][0]["name"] == "opencti"


def test_splunk_kv_store_lifecycle():
    created = client.post(f"{SPLUNK_COLLECTION}/config", data={"name": "opencti"})
    assert created.status_code == 200
    assert created.json()["entry"][0]["name"] == "opencti"

    inserted = client.post(
        f"{SPLUNK_COLLECTION}/data/opencti",
        json={"_key": OPENCTI_ID, "value": "8.8.8.8"},
    )
    assert inserted.status_code == 200
    assert inserted.json()["_key"] == OPENCTI_ID

    listed = client.get(f"{SPLUNK_COLLECTION}/data/opencti")
    assert [document["value"] for document in listed.json()] == ["8.8.8.8"]

    updated = client.put(
        f"{SPLUNK_COLLECTION}/data/opencti/{OPENCTI_ID}", json={"value": "9.9.9.9"}
    )
    assert updated.status_code == 200

    deleted = client.delete(f"{SPLUNK_COLLECTION}/data/opencti/{OPENCTI_ID}")
    assert deleted.status_code == 200
    # A second deletion answers 404, the way Splunk does.
    assert (
        client.delete(f"{SPLUNK_COLLECTION}/data/opencti/{OPENCTI_ID}").status_code
        == 404
    )


def test_splunk_update_of_unknown_key_is_not_found():
    client.post(f"{SPLUNK_COLLECTION}/config", data={"name": "opencti"})
    response = client.put(f"{SPLUNK_COLLECTION}/data/opencti/unknown", json={})
    assert response.status_code == 404


def test_qradar_reference_set_lifecycle():
    # The connector expects a bare array when it lists the sets.
    assert client.get("/qradar/api/reference_data_collections/sets").json() == []

    reference_set = client.post(
        "/qradar/api/reference_data_collections/sets",
        json={"name": "OpenCTI - IPv4 Addresses", "entry_type": "IP"},
    ).json()
    assert reference_set["id"]

    listed = client.get("/qradar/api/reference_data_collections/sets").json()
    assert [item["name"] for item in listed] == ["OpenCTI - IPv4 Addresses"]

    entry = client.post(
        "/qradar/api/reference_data_collections/set_entries",
        json={
            "collection_id": reference_set["id"],
            "notes": OPENCTI_ID,
            "source": "OpenCTI",
            "value": "8.8.8.8",
        },
    ).json()

    found = client.get(
        "/qradar/api/reference_data_collections/set_entries",
        params={
            "filter": f'collection_id={reference_set["id"]} and notes="{OPENCTI_ID}"'
        },
    ).json()
    assert [item["id"] for item in found] == [entry["id"]]

    updated = client.post(
        f"/qradar/api/reference_data_collections/set_entries/{entry['id']}",
        json={"value": "9.9.9.9"},
    )
    assert updated.status_code == 200
    assert updated.json()["value"] == "9.9.9.9"

    assert (
        client.delete(
            f"/qradar/api/reference_data_collections/set_entries/{entry['id']}"
        ).status_code
        == 200
    )


def test_qradar_filter_without_match_returns_nothing():
    response = client.get(
        "/qradar/api/reference_data_collections/set_entries",
        params={"filter": 'collection_id=42 and notes="unknown"'},
    )
    assert response.json() == []


def test_harfanglab_source_lists_are_created_once():
    for source_type in harfanglab.SOURCE_TYPES:
        listing = client.get(
            f"/harfanglab/api/data/threat_intelligence/{source_type}",
            params={"name__exact": "from_OpenCTI"},
        ).json()
        assert listing["results"] == []

        created = client.post(
            f"/harfanglab/api/data/threat_intelligence/{source_type}",
            json={"name": "from_OpenCTI", "description": "", "enabled": True},
        ).json()
        assert created["id"]

        listing = client.get(
            f"/harfanglab/api/data/threat_intelligence/{source_type}",
            params={"name__exact": "from_OpenCTI"},
        ).json()
        assert [item["id"] for item in listing["results"]] == [created["id"]]


def test_harfanglab_accepts_the_trailing_slash_the_connector_sends():
    source = client.post(
        "/harfanglab/api/data/threat_intelligence/IOCSource",
        json={"name": "opencti_list"},
    ).json()
    response = client.post(
        "/harfanglab/api/data/threat_intelligence/IOCRule/",
        json={
            "source_id": source["id"],
            "type": "ip_both",
            "value": "198.51.100.42",
        },
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert response.json()["value"] == "198.51.100.42"


def test_harfanglab_ioc_rule_lifecycle():
    source = client.post(
        "/harfanglab/api/data/threat_intelligence/IOCSource",
        json={"name": "from_OpenCTI", "description": "", "enabled": True},
    ).json()

    rule = client.post(
        "/harfanglab/api/data/threat_intelligence/IOCRule",
        json={
            "source_id": source["id"],
            "type": "domain_name",
            "value": "evil.example.com",
            "description": "",
            "hl_status": "stable",
            "enabled": True,
            "comment": "",
        },
    ).json()
    # The connector reads these straight off the creation response.
    assert rule["type"] == "domain_name"
    assert rule["value"] == "evil.example.com"

    found = client.get(
        "/harfanglab/api/data/threat_intelligence/IOCRule",
        params={
            "source_id": source["id"],
            "type": "domain_name",
            "value__exact": "evil.example.com",
        },
    ).json()
    assert [item["id"] for item in found["results"]] == [rule["id"]]

    patched = client.patch(
        f"/harfanglab/api/data/threat_intelligence/IOCRule/{rule['id']}",
        json={"hl_status": "testing"},
    )
    assert patched.json()["hl_status"] == "testing"

    assert (
        client.delete(
            f"/harfanglab/api/data/threat_intelligence/IOCRule/{rule['id']}"
        ).status_code
        == 204
    )


def test_harfanglab_unknown_type_is_not_found():
    response = client.get("/harfanglab/api/data/threat_intelligence/Unknown")
    assert response.status_code == 404


def test_sekoia_indicator_lifecycle():
    collection_id = "83399ea3-37be-4f78-b65e-a6d5600e6c60"
    assert client.get(f"/sekoia/{collection_id}").status_code == 200

    imported = client.post(
        f"/sekoia/{collection_id}/indicators/text",
        json={"indicators": "evil.example.com\n9.9.9.9\n"},
    ).json()
    assert imported["created"] == 2

    found = client.get(
        f"/sekoia/{collection_id}/indicators", params={"term": "9.9.9.9"}
    ).json()
    assert len(found["items"]) == 1
    assert found["items"][0]["revoked"] is False

    indicator_id = found["items"][0]["id"]
    assert (
        client.delete(f"/sekoia/{collection_id}/indicators/{indicator_id}").status_code
        == 200
    )
    assert (
        client.delete(f"/sekoia/{collection_id}/indicators/{indicator_id}").status_code
        == 404
    )


def test_cortex_xsoar_indicator_lifecycle():
    created = client.post(
        "/cortex-xsoar/xsoar/public/v1/indicator/create",
        json={"indicator": {"indicator_type": "IP", "value": "8.8.8.8", "score": 3}},
    ).json()
    assert created["value"] == "8.8.8.8"

    deleted = client.post(
        "/cortex-xsoar/xsoar/public/v1/indicators/batchDelete",
        json={"ids": [created["id"]]},
    ).json()
    assert deleted == {"deleted": 1, "total": 1}


def test_misp_handshake():
    assert client.get("/misp/servers/getVersion").json()["version"]
    assert client.get("/misp/servers/getPyMISPVersion.json").json()["version"]

    me = client.get("/misp/users/view/me").json()
    # PyMISP refuses to run without a complete Role object.
    assert me["Role"]["perm_add"] is True
    assert me["User"]["email"]

    described = client.get("/misp/attributes/describeTypes.json").json()["result"]
    assert described["types"]
    assert described["category_type_mappings"]


def test_misp_event_lifecycle():
    created = client.post(
        "/misp/events/add", json={"Event": {"info": "py312 proof", "Attribute": []}}
    ).json()["Event"]
    # The connector reads threat_level_id off the event it re-reads.
    assert created["threat_level_id"]
    assert created["Org"]["name"]

    read = client.get(f"/misp/events/view/{created['uuid']}").json()["Event"]
    assert read["info"] == "py312 proof"

    edited = client.post(
        f"/misp/events/edit/{created['id']}", json={"Event": {"info": "updated"}}
    ).json()["Event"]
    assert edited["info"] == "updated"

    assert client.post(f"/misp/events/publish/{created['id']}").json()["saved"] is True

    # PyMISP deletes with POST and then unblocklists the event.
    deleted = client.post(f"/misp/events/delete/{created['uuid']}").json()
    assert deleted["success"] is True
    assert client.get(f"/misp/events/view/{created['uuid']}").status_code == 404

    unblocked = client.post(f"/misp/eventBlocklists/delete/{created['uuid']}").json()
    assert unblocked["saved"] is True


def test_misp_answers_at_the_root():
    # PyMISP discards any path in the configured URL, so the same handlers have
    # to answer at the root of the host.
    assert client.get("/servers/getVersion").json()["version"]
    assert client.get("/users/view/me").json()["Role"]["perm_add"] is True

    created = client.post(
        "/events/add", json={"Event": {"info": "root mounted", "Attribute": []}}
    ).json()["Event"]
    assert client.get(f"/events/view/{created['uuid']}").json()["Event"]["info"] == (
        "root mounted"
    )
    assert client.post(f"/events/delete/{created['uuid']}").json()["success"] is True


def test_splunk_soar_container_lifecycle():
    assert client.get("/splunk-soar/rest/version").json()["version"]

    container = client.post(
        "/splunk-soar/rest/container",
        json={
            "name": "py312 proof",
            "external_id": OPENCTI_ID,
            "container_type": "case",
        },
    ).json()
    assert container["success"] is True
    assert container["container_type"] == "case"

    found = client.get(
        "/splunk-soar/rest/container",
        params={"_filter_external_id": f'"{OPENCTI_ID}"'},
    ).json()
    assert found["count"] == 1

    updated = client.post(
        f"/splunk-soar/rest/container/{container['id']}", json={"severity": "high"}
    )
    assert updated.json()["severity"] == "high"

    artifact = client.post(
        "/splunk-soar/rest/artifact",
        json={"container_id": container["id"], "name": "ip"},
    ).json()
    assert artifact["success"] is True

    note = client.post(
        "/splunk-soar/rest/note",
        json={"container_id": container["id"], "content": "hello"},
    ).json()
    assert note["success"] is True


def test_splunk_soar_update_of_unknown_container_is_not_found():
    assert client.post("/splunk-soar/rest/container/999", json={}).status_code == 404
