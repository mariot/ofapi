import gzip
import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_stix_bundle_holds_a_report_on_its_objects():
    bundle = client.get("/fixtures/stix-bundle.json").json()
    objects = {o["id"]: o for o in bundle["objects"]}
    report = next(o for o in objects.values() if o["type"] == "report")
    assert set(report["object_refs"]) <= set(objects)
    assert {"intrusion-set", "malware", "indicator", "relationship"} <= {
        o["type"] for o in objects.values()
    }


def test_pdf_report_is_a_pdf():
    body = client.get("/fixtures/report.pdf").content
    assert body.startswith(b"%PDF-1.4") and body.rstrip().endswith(b"%%EOF")


def test_misp_event_galaxies_carry_their_namespace():
    galaxies = client.get("/fixtures/misp-event.json").json()["Event"]["Galaxy"]
    assert {(g["namespace"], g["name"]) for g in galaxies} == {
        ("mitre-attack", "Attack Pattern"),
        ("mitre-attack", "Intrusion Set"),
    }


def test_sink_accepts_anything_and_hunt_io_serves_its_feed():
    assert client.put("/sink/any/path", json={"a": 1}).json()["method"] == "PUT"
    feed = gzip.decompress(client.get("/hunt-io/v1/feeds/c2").content).decode()
    assert all(json.loads(line) for line in feed.splitlines())
    assert client.get("/_control/hosts").json()["api.hunt.io"] == "/hunt-io"
