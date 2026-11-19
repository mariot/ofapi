from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_mitre_atlas_bundle_has_tactics_techniques_and_a_revoked_one():
    objects = client.get("/mitre-atlas/stix-atlas.json").json()["objects"]
    types = [o["type"] for o in objects]
    assert types.count("x-mitre-tactic") == 2
    assert types.count("attack-pattern") == 4
    assert sum(1 for o in objects if o.get("revoked")) == 1
    relationship = next(o for o in objects if o["type"] == "relationship")
    assert relationship["relationship_type"] == "subtechnique-of"


def test_nvd_cves_pages_and_one_cve_lacks_cvss_v31():
    page = client.get(
        "/nvd/rest/json/cves/2.0", params={"startIndex": 0, "resultsPerPage": 2}
    ).json()
    assert page["totalResults"] == 3
    assert len(page["vulnerabilities"]) == 2
    rest = client.get("/nvd/rest/json/cves/2.0", params={"startIndex": 2}).json()
    assert "cvssMetricV31" not in rest["vulnerabilities"][0]["cve"]["metrics"]


def test_nvd_source_resolves_a_name():
    sources = client.get(
        "/nvd/rest/json/source/2.0", params={"sourceIdentifier": "nvd@nist.gov"}
    ).json()["sources"]
    assert sources[0]["name"]


def test_openaev_payloads_manifest_has_native_and_community():
    manifest = client.get("/openaev-payloads/manifest.json").json()
    assert {p["native_collection"] for p in manifest} == {True, False}
    assert all(p["payload_information"]["payload_external_id"] for p in manifest)


def test_aws_ec2_describe_instances_answers_xml():
    response = client.post(
        "/aws-ec2/", data={"Action": "DescribeInstances", "Version": "2016-11-15"}
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/xml")
    assert response.text.count("<instanceId>") == 3


def test_aws_ec2_refuses_other_actions():
    response = client.post("/aws-ec2/", data={"Action": "RunInstances"})
    assert response.status_code == 400
    assert "InvalidAction" in response.text
