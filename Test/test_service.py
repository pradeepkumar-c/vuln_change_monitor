import sys
import os
import pytest
from sqlalchemy.exc import SQLAlchemyError
from model import SnapshotChanges
from service import NotFoundError, ValidationError, get_error_response_400, get_existing_findings, get_snapshot_changes, get_snapshots, update_findings, validate_finding_data, validate_snapshot_data, DatabaseError, get_snapshot, get_existing_snapshot
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


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
    print(error)

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

class MockSnapshots:
    def __init__(self):
        self.snapshot_id = 1
        self.snapshot_time = __import__("datetime").datetime.now()
        self.source = "scanner"
        self.finding_count = 5
        self.created_at = __import__("datetime").datetime.now()

@patch("service.Snapshots")
def test_get_snapshots(mock_snapshots):
    mock_query = mock_snapshots.query.filter_by.return_value
    
    mock_query.order_by.return_value.limit.return_value.offset.return_value.all.return_value = [
        MockSnapshots()
    ]
    res = get_snapshots("Test Product", "1.0.0", 10, 0)

    response = res["items"][0]
    assert response["snapshot_id"] == 1
    assert response["snapshot_time"] is not None
    assert response["source"] == "scanner"
    assert response["finding_count"] == 5
    assert response["created_at"] is not None

    mock_query = mock_snapshots.query.filter_by.return_value
    mock_query.order_by.return_value .limit.return_value .offset.return_value .all.side_effect = SQLAlchemyError("Database error")
    with pytest.raises(DatabaseError) as excinfo:
        get_snapshots("Test Product", "1.0.0", 10, 0)
    assert str(excinfo.value) == "Database error occurred"

    mock_query = mock_snapshots.query.filter_by.return_value
    mock_query.order_by.return_value .limit.return_value .offset.return_value .all.side_effect = Exception("Some random error")
    with pytest.raises(Exception) as excinfo:
        get_snapshots("Test Product", "1.0.0", 10, 0)
    assert str(excinfo.value) == "Some random error"


class MockSnapshot:
    def __init__(self):
        self.snapshot_id = 1
        self.product_name = "Test Product"
        self.product_version = "1.0.0"
        self.snapshot_time = __import__("datetime").datetime.now()
        self.source = "scanner"
        self.finding_count = 5
        self.previous_snapshot_id = None
        self.new = 2
        self.resolved = 1
        self.severity_changed = 1
        self.status_changed = 0
        self.unchanged = 1

@patch("service.Snapshots")
def test_get_snapshot(mock_snapshots):
    #Snapshots.query.filter_by(snapshot_id=snapshot_id).first()
    mock_snapshots.query.filter_by.return_value.first.return_value = MockSnapshot()
    response = get_snapshot(1)

    assert response["snapshot_id"] == 1
    assert response["snapshot_time"] is not None
    assert response["source"] == "scanner"
    assert response["finding_count"] == 5
    assert response["previous_snapshot_id"] is None
    assert response["summary"]["new"] == 2
    assert response["summary"]["resolved"] == 1
    assert response["summary"]["severity_changed"] == 1
    assert response["summary"]["status_changed"] == 0
    assert response["summary"]["unchanged"] == 1

    mock_snapshots.query.filter_by.return_value.first.side_effect = SQLAlchemyError("Database error")
    with pytest.raises(DatabaseError) as excinfo:
        get_snapshot(1)
    assert str(excinfo.value) == "Database error occurred"

    mock_snapshots.query.filter_by.return_value.first.side_effect = Exception("Some random error")
    with pytest.raises(Exception) as excinfo:
        get_snapshot(1)
    assert str(excinfo.value) == "Some random error"

    mock_snapshots.query.filter_by.return_value.first.side_effect = None
    mock_snapshots.query.filter_by.return_value.first.return_value = None
    with pytest.raises(NotFoundError) as excinfo:
        get_snapshot(1)
    assert str(excinfo.value) == "Snapshot not found"

class MockSnapshotChangesNew:
    def __init__(self):
        self.change_type = "new"
        self.vulnerability_id = "123"
        self.component_name = "Test Component"
        self.component_version = "1.0.0"
        self.package_url = None
        self.previous_severity = None
        self.current_severity = "high"
        self.previous_cvss_score = None
        self.current_cvss_score = 7.5
        self.previous_affected_status = None
        self.current_affected_status = "affected"


class MockSnapshotChangesResolved:
    def __init__(self):
        self.change_type = "resolved"
        self.vulnerability_id = "123"
        self.component_name = "Test Component"
        self.component_version = "1.0.0"
        self.package_url = None
        self.previous_severity = "high"
        self.current_severity = None
        self.previous_cvss_score = 7.5
        self.current_cvss_score = None
        self.previous_affected_status = "affected"
        self.current_affected_status = None

@patch("service.SnapshotChanges")
def test_get_snapshot_changes(mock_snapshotchanges):

    #query = SnapshotChanges.query.filter_by(snapshot_id=snapshot_id)
    mock_query = mock_snapshotchanges.query.filter_by.return_value
    
    #      changes = query.limit(limit).offset(offset).all()
    mock_query.limit.return_value.offset.return_value.all.return_value = [
        MockSnapshotChangesNew()
    ]

    res = get_snapshot_changes(1, 10, 0, None, None, None)
    response = res["changes"][0]
    print(len(response))
    assert response["change_type"] == "new"
    assert response["vulnerability_id"] == "123"
    assert response["component_name"] == "Test Component"
    assert response["component_version"] == "1.0.0"
    assert response["package_url"] is None
    assert response["previous"] is None
    assert response["current"]["severity"] == "high"
    assert response["current"]["cvss_score"] == 7.5
    assert response["current"]["affected_status"] == "affected"

    mock_query.limit.return_value.offset.return_value.all.return_value = [
        MockSnapshotChangesResolved()
    ]
    res = get_snapshot_changes(1, 10, 0, None, None, None)
    response = res["changes"][0]
    assert response["change_type"] == "resolved"
    assert response["vulnerability_id"] == "123"
    assert response["component_name"] == "Test Component"
    assert response["component_version"] == "1.0.0"
    assert response["package_url"] is None
    assert response["current"] is None
    assert response["previous"]["severity"] == "high"
    assert response["previous"]["cvss_score"] == 7.5
    assert response["previous"]["affected_status"] == "affected"

    #query.filter_bym changetype proper 'resolved'
    mock_query.filter_by.return_value.limit.return_value.offset.return_value.all.return_value = [
        MockSnapshotChangesResolved()
    ]
    res = get_snapshot_changes(1, 10, 0, "resolved", None, None)
    response = res["changes"][0]
    assert response["change_type"] == "resolved"
    assert response["vulnerability_id"] == "123"
    assert response["component_name"] == "Test Component"
    assert response["component_version"] == "1.0.0"
    assert response["package_url"] is None
    assert response["current"] is None
    assert response["previous"]["severity"] == "high"
    assert response["previous"]["cvss_score"] == 7.5
    assert response["previous"]["affected_status"] == "affected"

    #query.filter_bym changetype not proper 'Resolved'
    mock_query.filter_by.return_value.limit.return_value.offset.return_value.all.return_value = [
        MockSnapshotChangesResolved()
    ]
    with pytest.raises(ValidationError) as excinfo:
        res = get_snapshot_changes(1, 10, 0, "Resolved", None, None)
    assert str(excinfo.value) == "Invalid change_type value. Allowed values are: ['new', 'resolved', 'severity_changed', 'status_changed']"

    #severity
    mock_query.filter_by.return_value.limit.return_value.offset.return_value.all.return_value = [
        MockSnapshotChangesResolved()
    ]
    with pytest.raises(ValidationError) as excinfo:
        res = get_snapshot_changes(1, 10, 0, None, "Critical", None)
    assert str(excinfo.value) == "Invalid severity value. Allowed values are: ['critical', 'high', 'medium', 'low', 'none', 'unknown']"

    mock_query.filter_by.return_value.limit.return_value.offset.return_value.all.return_value = [
        MockSnapshotChangesResolved()
    ]
    res = get_snapshot_changes(1, 10, 0, None, "high", None)
    response = res["changes"][0]
    assert response["previous"]["severity"] == "high"

    #component_name
    mock_query.filter_by.return_value.limit.return_value.offset.return_value.all.return_value = [
        MockSnapshotChangesResolved()
    ]
    res = get_snapshot_changes(1, 10, 0, None, None, "Test Component")
    response = res["changes"][0]
    assert response["component_name"] == "Test Component"

    #No data 404
    mock_query.filter_by.return_value.limit.return_value.offset.return_value.all.return_value = None
    with pytest.raises(NotFoundError) as excinfo:
        res = get_snapshot_changes(1, 10, 0, None, None, "Test Component")
    assert str(excinfo.value) == "Snapshot changes not found"

    # Test with SQLAlchemyError
    mock_query.limit.return_value.offset.return_value.all.side_effect = SQLAlchemyError("Database error")
    with pytest.raises(DatabaseError) as excinfo:
        get_snapshot_changes(1, 10, 0, None, None, None)
    assert str(excinfo.value) == "Database error occurred"

    # Test with generic Exception
    mock_query.limit.return_value.offset.return_value.all.side_effect = Exception("Some random error")
    with pytest.raises(Exception) as excinfo:
        get_snapshot_changes(1, 10, 0, None, None, None)
    assert str(excinfo.value) == "Some random error"

class MockFindings:
    def __init__(self):
        self.change_type = "new"
        self.vulnerability_id = "123"
        self.component_name = "Test Component"
        self.component_version = "1.0.0"
        self.package_url = None
        self.previous_severity = None
        self.current_severity = "high"
        self.previous_cvss_score = None
        self.current_cvss_score = 7.5
        self.previous_affected_status = None
        self.current_affected_status = "affected"

@patch("service.Findings")
def test_get_existing_findings(mock_findings):
    # Test with existing findings
    mock_findings.query.filter_by.return_value.first.return_value = MockFindings()

    finding_data = {
        "vulnerability_id": "123",
        "component_name": "Test Component",
        "component_version": "1.0.0",
        "severity": "high",
        "affected_status": "affected"
    }
    res = get_existing_findings(finding_data, 1)
    assert res is not None
    assert res.vulnerability_id == "123"

    # Test with no findings
    mock_findings.query.filter_by.return_value.first.return_value = None
    existing_finding = get_existing_findings(finding_data, 1)
    assert existing_finding is None

@patch("service.Snapshots")
def test_get_existing_snapshots(mock_snapshots):
    # Test with existing snapshots
    mock_snapshots.query.filter_by.return_value.order_by.return_value.first.return_value = MockSnapshot()
    snapshot_data = {
        "product_name": "Test Product",
        "product_version": "1.0.0",
        "source": "scanner"
    }
    existing_snapshot = get_existing_snapshot(snapshot_data)
    assert existing_snapshot is not None
    print(existing_snapshot)
    assert existing_snapshot.snapshot_id == 1
    assert existing_snapshot.snapshot_time is not None
    assert existing_snapshot.source == "scanner"
    assert existing_snapshot.finding_count == 5
    assert existing_snapshot.previous_snapshot_id is None

    # Test with no snapshots
    mock_snapshots.query.filter_by.return_value.order_by.return_value.first.return_value = None
    existing_snapshot = get_existing_snapshot(snapshot_data)
    assert existing_snapshot is None

def test_update_findings():
    # This function is not implemented yet, but you can add tests for it once it's implemented
    update_findings(new_findings=[], existing_findings=[])