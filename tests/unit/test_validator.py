
import pytest
import json
from validator import validate_finding_data, validate_snapshot_data, get_error_response_400

@pytest.mark.parametrize("field", ["product_name", "product_version", "source", "snapshot_time"])
def test_validate_snapshot_data_empty_fields(field):
    # Test with empty fields
    invalid_snapshot = {
        "product_name": "Test Product",
        "product_version": "1.0.0",
        "source": "Test Source",
        "snapshot_time": "2024-06-01T12:00:00Z",
        "findings": [
            {
                "vulnerability_id": "123",
                "component_name": "Test Component",
                "component_version": "1.0.0",
                "severity": "high",
                "affected_status": "affected"
            }
        ]
    }
    invalid_snapshot[field] = ""
    result, error = validate_snapshot_data(invalid_snapshot)
    assert result == False
    assert error is not None
    assert "Invalid snapshot data" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": field, "message": f"Missing required field in snapshot: {field}"} in error["details"]


@pytest.mark.parametrize("field", ["product_name", "product_version", "source", "snapshot_time", "findings"])
def test_validate_snapshot_data_missing_fields(field):
    # Test with missing fields
    invalid_snapshot = {
        "product_name": "Test Product",
        "product_version": "1.0.0",
        "source": "Test Source",
        "snapshot_time": "2024-06-01T12:00:00Z",
        "findings": [
            {
                "vulnerability_id": "123",
                "component_name": "Test Component",
                "component_version": "1.0.0",
                "severity": "high",
                "affected_status": "affected"
            }
        ]
    }
    invalid_snapshot.pop(field, None)
    result, error = validate_snapshot_data(invalid_snapshot)
    assert result == False
    assert error is not None
    assert "Invalid snapshot data" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": field, "message": f"Missing required field in snapshot: {field}"} in error["details"]
    print(error)


def test_validate_snapshot_data():
    # Test with valid data
    snapshot_data = {
        "product_name": "Test Product",
        "product_version": "1.0.0",
        "source": "Test Source",
        "snapshot_time": "2024-06-01T12:00:00Z",
        "findings": [
            {
                "vulnerability_id": "123",
                "component_name": "Test Component",
                "component_version": "1.0.0",
                "severity": "high",
                "affected_status": "affected"
            }
        ]
    }
    result, error = validate_snapshot_data(snapshot_data)
    assert result == True
    assert error == None

    # test with invalid snapshot_time format
    snapshot_data["snapshot_time"] = "2024/06/01 12:00:00"
    result, error = validate_snapshot_data(snapshot_data)
    assert result == False
    assert error is not None
    assert "Invalid snapshot data" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": "snapshot_time", "message": "Invalid snapshot_time format, should be in ISO 8601 format, example: 2023-01-01T00:00:00Z"} in error["details"]

    #test wth invalid snapshot_time 2026-02-31T12:00:00Z - Feb 31st is invalid date
    snapshot_data["snapshot_time"] = "2026-02-31T12:00:00Z"
    result, error = validate_snapshot_data(snapshot_data)
    assert result == False
    assert error is not None
    assert "Invalid snapshot data" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": "snapshot_time", "message": "Invalid snapshot_time format, should be in ISO 8601 format, example: 2023-01-01T00:00:00Z"} in error["details"]
    print(error)

    #empty findings test
    snapshot_data["snapshot_time"] = "2024-06-01T12:00:00Z"
    snapshot_data["findings"] = []
    result, error = validate_snapshot_data(snapshot_data)
    assert result == False
    assert error is not None
    assert "Invalid snapshot data" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": "findings", "message": "Findings must be a non-empty list"} in error["details"]
    print(error)

    # Duplicate findings test
    snapshot_data["findings"] = [
            {
                "vulnerability_id": "123",
                "component_name": "Test Component",
                "component_version": "1.0.0",
                "severity": "high",
                "affected_status": "affected"
            },
            {
                "vulnerability_id": "123",
                "component_name": "Test Component",
                "component_version": "1.0.0",
                "severity": "high",
                "affected_status": "affected"
            }
    ]
    result, error = validate_snapshot_data(snapshot_data)
    assert result == False
    assert error is not None
    assert "Invalid snapshot data" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": "findings", "message": "Duplicate finding found in request data for vulnerability_id: 123, component_name: Test Component and component_version: 1.0.0"} in error["details"]
    print(error)

    # Missed vulnerability id in findings test
    snapshot_data["findings"] = [
            {
                "component_name": "Test Component",
                "component_version": "1.0.0",
                "severity": "high",
                "affected_status": "affected"
            }
    ]
    result, error = validate_snapshot_data(snapshot_data)
    assert result == False
    assert error is not None
    assert "Invalid snapshot payload" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": "vulnerability_id", "message": "Missing required field in finding: vulnerability_id"} in error["details"]  
    print(error)
@pytest.mark.parametrize("field", ["vulnerability_id", "component_name", "component_version", "severity", "affected_status"])
def test_validate_finding_data_empty_fields(field):
    # Test with empty fields
    invalid_finding = {
            "vulnerability_id": "123",
            "component_name": "Test Component",
            "component_version": "1.0.0",
            "severity": "high",
            "affected_status": "affected"
    }
    invalid_finding[field] = ""
    result, error = validate_finding_data(invalid_finding)
    assert result == False
    assert error is not None
    assert "Invalid snapshot payload" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": field, "message": f"Missing required field in finding: {field}"} in error["details"]
    print(error)

@pytest.mark.parametrize("field", ["vulnerability_id", "component_name", "component_version", "severity", "affected_status"])
def test_validate_finding_data_missing_fields(field):
    # Test with missing fields
    invalid_finding = {
            "vulnerability_id": "123",
            "component_name": "Test Component",
            "component_version": "1.0.0",
            "severity": "high",
            "affected_status": "affected"
    }
    invalid_finding.pop(field)
    result, error = validate_finding_data(invalid_finding)
    assert result == False
    assert error is not None
    assert "Invalid snapshot payload" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": field, "message": f"Missing required field in finding: {field}"} in error["details"]
    print(error)

def test_validate_finding_data_missing_fields():
    # Test with valid data
    finding_data = {
            "vulnerability_id": "123",
            "component_name": "Test Component",
            "component_version": "1.0.0",
            "severity": "high",
            "affected_status": "affected"
    }
    result, error = validate_finding_data(finding_data)
    assert result == True
    assert error == None

    # Test with wrong severirty value
    finding_data["severity"] = "highh"
    result, error = validate_finding_data(finding_data)
    assert result == False
    assert error is not None
    assert "Invalid snapshot payload" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": "severity", "message": "Severity value should be: critical, high, medium, low, none, unknown"} in error["details"]

    finding_data["severity"] = 5
    result, error = validate_finding_data(finding_data)
    assert result == False
    assert error is not None
    print(error)

    finding_data["severity"] = "high"


    # Test with wrong cvss score value, should be in range 0.0 ~ 10.0
    finding_data["cvss_score"] = 10.8  # Range should be 0.0 ~ 10.0
    result, error = validate_finding_data(finding_data)
    assert result == False
    assert error is not None
    assert "Invalid snapshot payload" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": "cvss_score", "message": "CVSS score should be in range: 0.0 ~ 10.0"} in error["details"]

    finding_data["cvss_score"]  = "high"
    result, error = validate_finding_data(finding_data)
    assert result == False
    assert error is not None
    assert "Invalid snapshot payload" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": "cvss_score", "message": "CVSS score should be in range: 0.0 ~ 10.0"} in error["details"]

    finding_data["cvss_score"]  = -0.1
    result, error = validate_finding_data(finding_data)
    assert result == False
    assert error is not None
    assert "Invalid snapshot payload" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": "cvss_score", "message": "CVSS score should be in range: 0.0 ~ 10.0"} in error["details"]

    finding_data["cvss_score"]  = 5
    result, error = validate_finding_data(finding_data)
    assert result == True
    assert error is None
    print(error)

    #test with wrong affected_status value
    finding_data["affected_status"] = "affectd"
    result, error = validate_finding_data(finding_data)
    assert result == False
    assert error is not None
    assert "Invalid snapshot payload" in error["message"]
    assert "Vulnerability Snapshot Change Monitor" in error["details"]
    assert {"field": "affected_status", "message": "Affected status value should be in: affected, not_affected, fixed, under_investigation, accepted_risk"} in error["details"]

    finding_data["affected_status"] = "fixed"
    result, error = validate_finding_data(finding_data)
    assert result == True
    assert error is None
    print(error)
    
def test_get_error_response_400():
    # Test with only message
    error_response = get_error_response_400("Invalid input")
    assert error_response["code"] == "validation_error"
    assert error_response["message"] == "Invalid input"
    assert error_response["details"] ==  ['Bad Request']

    # Test with message and details
    error_response = get_error_response_400("Invalid input", details="Missing required fields")
    assert error_response["code"] == "validation_error"
    assert error_response["message"] == "Invalid input"
    assert error_response["details"] == ["Missing required fields"]

    # Test with message, details, and field
    error_response = get_error_response_400("Invalid input", details="Missing required fields", field="username", field_message="Username is required")
    assert error_response["code"] == "validation_error"
    assert error_response["message"] == "Invalid input"
    assert {"field": "username", "message": "Username is required"} in error_response["details"]
    print(error_response)

