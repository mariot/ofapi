from fastapi.testclient import TestClient

from api.feedly import (
    BundleFactory,
)
from main import app

client = TestClient(app)


def test_bundle_to_dict():
    """
    Tests the to_dict method of the Bundle dataclass to ensure it correctly
    formats the STIX bundle structure.
    """
    # Arrange: Create a bundle instance using the factory
    bundle = BundleFactory()

    # Act: Convert the bundle to a dictionary
    bundle_dict = bundle.to_dict()

    # Assert: Check the top-level bundle properties
    assert bundle_dict["type"] == "bundle"
    assert bundle_dict["id"] == bundle.id
    assert "spec_version" not in bundle_dict
    assert "_internal_id" not in bundle_dict
    assert "reports" not in bundle_dict
    assert "objects" in bundle_dict
    assert isinstance(bundle_dict["objects"], list)

    # Assert: Check that reports and their object_refs are correctly processed
    original_report = bundle.reports[0]
    report_in_dict = next(
        (obj for obj in bundle_dict["objects"] if obj["id"] == original_report.id), None
    )
    assert report_in_dict is not None
    assert report_in_dict["type"] == "report"
    assert "_internal_id" not in report_in_dict

    # Assert: Check that object_refs are now a list of string IDs
    assert isinstance(report_in_dict["object_refs"], list)
    assert all(isinstance(ref, str) for ref in report_in_dict["object_refs"])

    # Assert: Check that the referenced objects are also present in the main 'objects' list
    original_ref_id = original_report.object_refs[0].id
    assert original_ref_id in report_in_dict["object_refs"]
    ref_in_dict = next(
        (obj for obj in bundle_dict["objects"] if obj["id"] == original_ref_id), None
    )
    assert ref_in_dict is not None
    assert "_internal_id" not in ref_in_dict


def test_feedly_enterprise_ioc_success():
    """
    Tests the happy path for the Feedly IOC endpoint with required parameters.
    """
    # Arrange
    params = {"streamId": "enterprise/acme/category/all", "newerThan": "1672531200000"}

    # Act
    response = client.get("/feedly/v3/enterprise/ioc", params=params)
    data = response.json()

    # Assert
    assert response.status_code == 200
    assert "id" in data
    assert data["type"] == "bundle"
    assert "objects" in data
    assert isinstance(data["objects"], list)
    assert len(data["objects"]) > 0


def test_feedly_enterprise_ioc_with_optional_params():
    """
    Tests that the endpoint works correctly when optional parameters are provided.
    """
    # Arrange
    params = {
        "streamId": "enterprise/acme/category/all",
        "newerThan": "1672531200000",
        "count": 5,
        "continuation": 12345,
    }

    # Act
    response = client.get("/feedly/v3/enterprise/ioc", params=params)

    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data["type"] == "bundle"


def test_feedly_enterprise_ioc_missing_stream_id():
    """
    Tests that the endpoint returns a 422 error if the 'streamId' parameter is missing.
    """
    # Arrange
    params = {"newerThan": "1672531200000"}

    # Act
    response = client.get("/feedly/v3/enterprise/ioc", params=params)

    # Assert
    assert response.status_code == 422
    error_detail = response.json()["detail"][0]
    assert error_detail["msg"] == "Field required"
    assert error_detail["loc"] == ["query", "streamId"]


def test_feedly_enterprise_ioc_missing_newer_than():
    """
    Tests that the endpoint returns a 422 error if the 'newerThan' parameter is missing.
    """
    # Arrange
    params = {"streamId": "enterprise/acme/category/all"}

    # Act
    response = client.get("/feedly/v3/enterprise/ioc", params=params)

    # Assert
    assert response.status_code == 422
    error_detail = response.json()["detail"][0]
    assert error_detail["msg"] == "Field required"
    assert error_detail["loc"] == ["query", "newerThan"]
