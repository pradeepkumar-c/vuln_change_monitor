import sys
import os
import pytest
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from model import SnapshotChanges
from service import NotFoundError, ValidationError, add_snapshot_change, create_snapshot, generate_uniqueid, get_error_response_400, get_existing_findings, get_resolved_findings_count, get_snapshot_changes, get_snapshots, normalize_snapshot_input, update_findings, validate_finding_data, validate_snapshot_data, DatabaseError, get_snapshot, get_existing_snapshot, add_new_finding, update_snapshot, ConflictError
from unittest.mock import MagicMock, patch
from datetime import datetime

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


class NewMockSnapshot:
    def __init__(self):
        self.snapshot_id = 1
        self.new = 0
        self.resolved = 0
        self.severity_changed = 0
        self.status_changed = 0
        self.unchanged = 0
        self.finding_count = 0

@patch("service.add_new_finding")
@patch("service.add_snapshot_change")
def test_update_findings_no_existing_snapshot(mock_add_change, mock_add_new):
    
    new_snapshot = NewMockSnapshot()
    findings_data = [
        {"severity": "HIGH", "affected_status": "OPEN"},
        {"severity": "LOW", "affected_status": "OPEN"}
    ]

    update_findings(new_snapshot, None, findings_data)

    assert new_snapshot.new == 2
    assert new_snapshot.finding_count == 2
    
    assert mock_add_new.call_count == 2
    assert mock_add_change.call_count == 2


@patch("service.get_existing_findings")
@patch("service.add_snapshot_change")
@patch("service.add_new_finding")
@patch("service.get_resolved_findings_count")
@patch("service.db.session.flush")
def test_update_findings_severity_changed(
    mock_flush,
    mock_resolved,
    mock_add_new,
    mock_add_change,
    mock_get_existing
):
    new_snapshot = NewMockSnapshot()

    existing_snapshot = NewMockSnapshot()
    existing_snapshot.snapshot_id = 100

    existing_finding = MagicMock()
    existing_finding.severity = "LOW"
    existing_finding.affected_status = "OPEN"

    mock_get_existing.return_value = existing_finding
    mock_resolved.return_value = 0

    findings_data = [{"severity": "HIGH", "affected_status": "OPEN"}]

    update_findings(new_snapshot, existing_snapshot, findings_data)

    assert new_snapshot.severity_changed == 1
    assert new_snapshot.status_changed == 0
    assert new_snapshot.unchanged == 0

    mock_add_change.assert_called_with(
        new_snapshot, existing_finding, findings_data[0], 'severity_changed'
    )

@patch("service.get_existing_findings")
@patch("service.add_snapshot_change")
@patch("service.add_new_finding")
@patch("service.get_resolved_findings_count")
@patch("service.db.session.flush")
def test_update_findings_affected_status_changed(
    mock_flush,
    mock_resolved,
    mock_add_new,
    mock_add_change,
    mock_get_existing
):
    new_snapshot = NewMockSnapshot()

    existing_snapshot = NewMockSnapshot()
    existing_snapshot.snapshot_id = 100

    existing_finding = MagicMock()
    existing_finding.severity = "HIGH"
    existing_finding.affected_status = "OPEN"
    
    mock_get_existing.return_value = existing_finding
    mock_resolved.return_value = 0

    findings_data = [{"severity": "HIGH", "affected_status": "affected"}]

    update_findings(new_snapshot, existing_snapshot, findings_data)

    assert new_snapshot.severity_changed == 0
    assert new_snapshot.status_changed == 1
    assert new_snapshot.unchanged == 0

    mock_add_change.assert_called_with(
        new_snapshot, existing_finding, findings_data[0], 'status_changed'
    )

@patch("service.get_existing_findings")
@patch("service.get_resolved_findings_count")
@patch("service.add_new_finding")
@patch("service.db.session.flush")
def test_update_findings_unchanged(mock_flush, mock_add_new, mock_resolved, mock_get_existing):

    new_snapshot = NewMockSnapshot()
    existing_snapshot = NewMockSnapshot()

    existing_finding = MagicMock()
    existing_finding.severity = "HIGH"
    existing_finding.affected_status = "OPEN"

    mock_get_existing.return_value = existing_finding
    mock_resolved.return_value = 0

    findings_data = [{"severity": "HIGH", "affected_status": "OPEN"}]

    update_findings(new_snapshot, existing_snapshot, findings_data)

    assert new_snapshot.unchanged == 1


@patch("service.get_existing_findings")
@patch("service.get_resolved_findings_count")
@patch("service.add_snapshot_change")
@patch("service.add_new_finding")
@patch("service.db.session.flush")
def test_update_findings_new(
    mock_flush,
    mock_add_new,
    mock_add_change,
    mock_resolved,
    mock_get_existing
):
    
    new_snapshot = NewMockSnapshot()
    existing_snapshot = MockSnapshot()

    mock_get_existing.return_value = None
    mock_resolved.return_value = 0

    findings_data = [{"severity": "HIGH", "affected_status": "OPEN"}]

    update_findings(new_snapshot, existing_snapshot, findings_data)

    assert new_snapshot.new == 1

    mock_add_change.assert_called_with(
        new_snapshot, None, findings_data[0], 'new'
    )



class DummySnapshot:
    def __init__(self, snapshot_id):
        self.snapshot_id = snapshot_id


class DummyFinding:
    def __init__(self, vulnerability_id, component_name, component_version):
        self.vulnerability_id = vulnerability_id
        self.component_name = component_name
        self.component_version = component_version


@patch("service.add_snapshot_change")
@patch("service.Findings")
def test_get_resolved_findings_count_when_some_resolved(mock_findings, mock_add_change):

    existing_snapshot = DummySnapshot(snapshot_id=1)
    new_snapshot = DummySnapshot(snapshot_id=2)

    existing_findings = [
        DummyFinding("V1", "compA", "1.0"),
        DummyFinding("V2", "compB", "2.0"),
    ]

    findings_data = [
        {
            "vulnerability_id": "V1",
            "component_name": "compA",
            "component_version": "1.0",
        }
    ]

    mock_findings.query.filter_by.return_value.all.return_value = existing_findings

    result = get_resolved_findings_count(new_snapshot, existing_snapshot, findings_data)


    assert result == 1 
    assert mock_add_change.call_count == 1

    mock_add_change.assert_called_with(
        new_snapshot,
        existing_findings[1],
        None,
        "resolved"
    )


@patch("service.add_snapshot_change")
@patch("service.Findings")
def test_get_resolved_findings_count_when_none_resolved(mock_findings, mock_add_change):
    existing_snapshot = DummySnapshot(1)
    new_snapshot = DummySnapshot(2)

    existing_findings = [
        DummyFinding("V1", "compA", "1.0"),
    ]

    findings_data = [
        {
            "vulnerability_id": "V1",
            "component_name": "compA",
            "component_version": "1.0",
        }
    ]

    mock_findings.query.filter_by.return_value.all.return_value = existing_findings

    result = get_resolved_findings_count(new_snapshot, existing_snapshot, findings_data)

    assert result == 0
    mock_add_change.assert_not_called()


@patch("service.add_snapshot_change")
@patch("service.Findings")
def test_get_resolved_findings_count_when_all_resolved(mock_findings, mock_add_change):
    existing_snapshot = DummySnapshot(1)
    new_snapshot = DummySnapshot(2)

    existing_findings = [
        DummyFinding("V1", "compA", "1.0"),
        DummyFinding("V2", "compB", "2.0"),
    ]

    findings_data = []

    mock_findings.query.filter_by.return_value.all.return_value = existing_findings

    result = get_resolved_findings_count(new_snapshot, existing_snapshot, findings_data)

    assert result == 2
    assert mock_add_change.call_count == 2


class DummySnapshot1:
    def __init__(self):
        self.snapshot_id = 2
        self.previous_snapshot_id = 1


class DummyExistingFinding:
    def __init__(self):
        self.vulnerability_id = "V1"
        self.component_name = "compA"
        self.component_version = "1.0"
        self.package_url = "pkg://abc"
        self.severity = "HIGH"
        self.cvss_score = 7.5
        self.affected_status = "affected"


@patch("service.db")
@patch("service.SnapshotChanges")
def test_add_snapshot_change_with_finding_data(mock_snapshot_changes, mock_db):

    new_snapshot = DummySnapshot1()
    existing_finding = DummyExistingFinding()

    finding_data = {
        "vulnerability_id": "V1_new",
        "component_name": "compA_new",
        "component_version": "2.0",
        "package_url": "pkg://new",
        "severity": "CRITICAL",
        "cvss_score": 9.5,
        "affected_status": "not_affected"
    }

    mock_instance = MagicMock()
    mock_snapshot_changes.return_value = mock_instance

    add_snapshot_change(new_snapshot, existing_finding, finding_data, "updated")

    mock_snapshot_changes.assert_called_once_with(
        snapshot_id=2,
        previous_snapshot_id=1,
        change_type="updated",
        vulnerability_id="V1_new",
        component_name="compA_new",
        component_version="2.0",
        package_url="pkg://new",
        previous_severity="HIGH",
        current_severity="CRITICAL",
        previous_cvss_score=7.5,
        current_cvss_score=9.5,
        previous_affected_status="affected",
        current_affected_status="not_affected"
    )

    mock_db.session.add.assert_called_once_with(mock_instance)



@patch("service.db")
@patch("service.SnapshotChanges")
def test_add_snapshot_change_without_finding_data(mock_snapshot_changes, mock_db):

    new_snapshot = DummySnapshot1()
    existing_finding = DummyExistingFinding()

    mock_instance = MagicMock()
    mock_snapshot_changes.return_value = mock_instance


    add_snapshot_change(new_snapshot, existing_finding, None, "resolved")

    mock_snapshot_changes.assert_called_once_with(
        snapshot_id=2,
        previous_snapshot_id=1,
        change_type="resolved",
        vulnerability_id="V1",
        component_name="compA",
        component_version="1.0",
        package_url="pkg://abc",
        previous_severity="HIGH",
        current_severity=None,
        previous_cvss_score=7.5,
        current_cvss_score=None,
        previous_affected_status="affected",
        current_affected_status=None
    )

    mock_db.session.add.assert_called_once()



@patch("service.db")
@patch("service.SnapshotChanges")
def test_add_snapshot_change_with_no_existing_finding(mock_snapshot_changes, mock_db):

    new_snapshot = DummySnapshot1()

    finding_data = {
        "vulnerability_id": "V2",
        "component_name": "compB",
        "component_version": "1.1",
        "package_url": "pkg://xyz",
        "severity": "MEDIUM",
        "cvss_score": 5.5,
        "affected_status": "affected"
    }

    mock_instance = MagicMock()
    mock_snapshot_changes.return_value = mock_instance

    # Act
    add_snapshot_change(new_snapshot, None, finding_data, "new")

    # Assert
    mock_snapshot_changes.assert_called_once_with(
        snapshot_id=2,
        previous_snapshot_id=1,
        change_type="new",
        vulnerability_id="V2",
        component_name="compB",
        component_version="1.1",
        package_url="pkg://xyz",
        previous_severity=None,
        current_severity="MEDIUM",
        previous_cvss_score=None,
        current_cvss_score=5.5,
        previous_affected_status=None,
        current_affected_status="affected"
    )

    mock_db.session.add.assert_called_once()



@patch("service.db")
@patch("service.Findings")
@patch("service.generate_uniqueid")
def test_add_new_finding_with_all_fields(mock_generate_id, mock_findings, mock_db):

    new_snapshot = DummySnapshot(10)

    finding_data = {
        "vulnerability_id": "V1",
        "component_name": "compA",
        "component_version": "1.0",
        "package_url": "pkg://abc",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected_status": "affected"
    }

    mock_generate_id.return_value = "unique-123"
    mock_instance = MagicMock()
    mock_findings.return_value = mock_instance

    add_new_finding(new_snapshot, finding_data)

    mock_findings.assert_called_once_with(
        finding_id="unique-123",
        snapshot_id=10,
        vulnerability_id="V1",
        component_name="compA",
        component_version="1.0",
        package_url="pkg://abc",
        severity="HIGH",
        cvss_score=7.5,
        affected_status="affected"
    )

    mock_db.session.add.assert_called_once_with(mock_instance)



class DummySnapshot2:
    def __init__(self, snapshot_id, snapshot_time):
        self.snapshot_id = snapshot_id
        self.snapshot_time = snapshot_time

@patch("service.get_existing_snapshot")
def test_update_snapshot_same_time_conflict(mock_get_existing):
    data = {
        "product_name": "prodA",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z"
    }

    existing = DummySnapshot2("123", datetime(2025, 6, 1, 10, 0, 0))
    mock_get_existing.return_value = existing

    with pytest.raises(ConflictError) as exc:
        update_snapshot(data)

    assert "same product/version/source and snapshot_time exists" in str(exc.value)

@patch("service.get_existing_snapshot")
def test_update_snapshot_newer_exists_conflict(mock_get_existing):
    data = {
        "product_name": "prodA",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T09:00:00Z"
    }

    existing = DummySnapshot2("123", datetime(2025, 6, 1, 10, 0, 0))
    mock_get_existing.return_value = existing

    with pytest.raises(ConflictError) as exc:
        update_snapshot(data)

    assert "newer snapshot" in str(exc.value)

@patch("service.db")
@patch("service.Snapshots")
@patch("service.generate_uniqueid")
@patch("service.get_existing_snapshot")
def test_update_snapshot_success(mock_get_existing, mock_generate_id, mock_snapshots, mock_db):

    data = {
        "product_name": "prodA",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z"
    }

    existing = DummySnapshot2("old-123", datetime(2025, 5, 1, 10, 0, 0))
    mock_get_existing.return_value = existing

    mock_generate_id.return_value = "new-456"
    mock_instance = MagicMock()
    mock_snapshots.return_value = mock_instance

    new_snapshot, existing_snapshot = update_snapshot(data)

    mock_snapshots.assert_called_once_with(
        snapshot_id="new-456",
        product_name="prodA",
        product_version="1.0",
        source="scanner",
        snapshot_time=datetime(2025, 6, 1, 10, 0, 0),
        new=0,
        resolved=0,
        severity_changed=0,
        status_changed=0,
        unchanged=0,
        previous_snapshot_id="old-123"
    )

    mock_db.session.add.assert_called_once_with(mock_instance)
    mock_db.session.flush.assert_called_once()

    assert new_snapshot == mock_instance
    assert existing_snapshot == existing

@patch("service.db")
@patch("service.Snapshots")
@patch("service.generate_uniqueid")
@patch("service.get_existing_snapshot")
def test_update_snapshot_no_existing(mock_get_existing, mock_generate_id, mock_snapshots, mock_db):

    data = {
        "product_name": "prodA",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z"
    }

    mock_get_existing.return_value = None
    mock_generate_id.return_value = "new-001"

    mock_instance = MagicMock()
    mock_snapshots.return_value = mock_instance

    new_snapshot, existing_snapshot = update_snapshot(data)

    args = mock_snapshots.call_args[1]

    assert args["previous_snapshot_id"] is None

    assert existing_snapshot is None
    assert new_snapshot == mock_instance


@patch("service.db")
@patch("service.update_findings")
@patch("service.update_snapshot")
@patch("service.validate_snapshot_data")
def test_create_snapshot_success(
    mock_validate,
    mock_update_snapshot,
    mock_update_findings,
    mock_db
):

    data = {
        "product_name": "prodA",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": []
    }

    mock_validate.return_value = (True, None)

    new_snapshot = MagicMock()
    new_snapshot.snapshot_id = "123"
    new_snapshot.product_name = " prodA "
    new_snapshot.product_version = " 1.0 "
    new_snapshot.source = " scanner "
    new_snapshot.snapshot_time = datetime(2025, 6, 1, 10, 0, 0)
    new_snapshot.finding_count = 5
    new_snapshot.new = 1
    new_snapshot.resolved = 2
    new_snapshot.severity_changed = 1
    new_snapshot.status_changed = 0
    new_snapshot.unchanged = 1

    existing_snapshot = MagicMock()
    existing_snapshot.snapshot_id = "old-123"

    mock_update_snapshot.return_value = (new_snapshot, existing_snapshot)

    response = create_snapshot(data)

    mock_validate.assert_called_once()
    mock_update_snapshot.assert_called_once_with(data)
    mock_update_findings.assert_called_once_with(new_snapshot, existing_snapshot, [])

    mock_db.session.commit.assert_called_once()

    assert response["snapshot_id"] == "123"
    assert response["previous_snapshot_id"] == "old-123"
    assert response["summary"]["resolved"] == 2

@patch("service.db")
@patch("service.validate_snapshot_data")
def test_create_snapshot_validation_error(mock_validate, mock_db):

    mock_validate.return_value = (False, "Invalid data")

    data = {}

    with pytest.raises(ValidationError):
        create_snapshot(data)

    mock_db.session.rollback.assert_called_once()


@patch("service.db")
@patch("service.update_snapshot")
@patch("service.validate_snapshot_data")
def test_create_snapshot_conflict_error(mock_validate, mock_update_snapshot, mock_db):
    mock_validate.return_value = (True, None)
    mock_update_snapshot.side_effect = ConflictError("conflict")

    data = {
        "findings": []
    }

    with pytest.raises(ConflictError):
        create_snapshot(data)

    mock_db.session.rollback.assert_called_once()

@patch("service.db")
@patch("service.update_findings")
@patch("service.update_snapshot")
@patch("service.validate_snapshot_data")
def test_create_snapshot_integrity_error(
    mock_validate,
    mock_update_snapshot,
    mock_update_findings,
    mock_db
):
    mock_validate.return_value = (True, None)

    new_snapshot = MagicMock()
    existing_snapshot = None
    mock_update_snapshot.return_value = (new_snapshot, existing_snapshot)

    mock_update_findings.side_effect = IntegrityError("err", None, None)

    data = {"findings": []}

    with pytest.raises(ConflictError) as exc:
        create_snapshot(data)

    assert "Duplicate snapshot" in str(exc.value)

    mock_db.session.rollback.assert_called_once()

@patch("service.db")
@patch("service.update_findings")
@patch("service.update_snapshot")
@patch("service.validate_snapshot_data")
def test_create_snapshot_generic_exception(
    mock_validate,
    mock_update_snapshot,
    mock_update_findings,
    mock_db
):
    mock_validate.return_value = (True, None)

    new_snapshot = MagicMock()
    mock_update_snapshot.return_value = (new_snapshot, None)

    mock_update_findings.side_effect = Exception("Something failed")

    data = {"findings": []}

    with pytest.raises(Exception):
        create_snapshot(data)

    mock_db.session.rollback.assert_called_once()

def test_generate_uniqueid_returns_string():
    result = generate_uniqueid()
    assert isinstance(result, str)

def test_generate_uniqueid_returns_unique_values():
    id1 = generate_uniqueid()
    id2 = generate_uniqueid()

    assert id1 != id2


def test_normalize_snapshot_input_basic():
    payload = {
        "product_name": "  prodA  ",
        "product_version": " 1.0 ",
        "source": " scanner ",
        "findings": [
            {
                "vulnerability_id": "V1",
                "component_name": "compA",
                "component_version": "1.0"
            }
        ]
    }

    result = normalize_snapshot_input(payload)
    
    assert result["product_name"] == "prodA"
    assert result["product_version"] == "1.0"
    assert result["source"] == "scanner"

def test_normalize_finding_inside_snapshot():
    payload = {
        "product_name": "prodA",
        "product_version": "1.0",
        "source": "scanner",
        "findings": [
            {
                "vulnerability_id": " V1 ",
                "component_name": " compA ",
                "component_version": " 1.0 "
            }
        ]
    }

    result = normalize_snapshot_input(payload)

    finding = result["findings"][0]

    assert finding["vulnerability_id"] == "V1"
    assert finding["component_name"] == "compA"
    assert finding["component_version"] == "1.0"


def test_original_input_not_modified():
    payload = {
        "product_name": " prodA ",
        "product_version": "1.0",
        "source": "scanner",
        "findings": []
    }

    original = payload.copy()

    normalize_snapshot_input(payload)
    assert payload["product_name"] == original["product_name"]

