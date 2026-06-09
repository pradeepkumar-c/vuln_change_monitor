
import json
import pytest
from unittest.mock import patch

from app import app
from routes import ConflictError, NotFoundError, ValidationError, DatabaseError 

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@patch("routes.create_snapshot")
def test_create_snapshot_success(mock_create_snapshot, client):
    mock_response = {
        "snapshot_id": "123",
        "product_name": "prodA",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00",
        "finding_count": 5,
        "previous_snapshot_id": None,
        "summary": {
            "new": 1,
            "resolved": 2,
            "severity_changed": 1,
            "status_changed": 0,
            "unchanged": 1
        }
    }

    mock_create_snapshot.return_value = mock_response

    payload = {"dummy": "data"}

    response = client.post(
        "/snapshots",
        data=json.dumps(payload),
        content_type="application/json"
    )

    assert response.status_code == 201
    assert response.get_json()["snapshot_id"] == "123"

def test_create_snapshot_bad_json(client):
    bad_json = '{"product_name": "prodA",}'

    response = client.post(
        "/snapshots",
        data=bad_json,
        content_type="application/json"
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Malformed JSON syntax encountered"

@patch("routes.create_snapshot")
def test_create_snapshot_conflict(mock_create_snapshot, client):
    mock_create_snapshot.side_effect = ConflictError("Duplicate snapshot")

    response = client.post(
        "/snapshots",
        json={}
    )

    assert response.status_code == 409
    assert "Duplicate snapshot" in response.get_json()["error"]


@patch("routes.create_snapshot")
def test_create_snapshot_not_found(mock_create_snapshot, client):
    mock_create_snapshot.side_effect = NotFoundError("Not found")

    response = client.post("/snapshots", json={})

    assert response.status_code == 404
    assert response.get_json()["error"] == "Not found"


@patch("routes.create_snapshot")
def test_create_snapshot_generic_exception(mock_create_snapshot, client):
    mock_create_snapshot.side_effect = Exception("Something went wrong")

    response = client.post("/snapshots", json={})

    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"

@patch("routes.create_snapshot")
def test_create_snapshot_validation_exception(mock_create_snapshot, client):

    exc = ValidationError("Validation failed")
    exc.error_body = {"error": "Validation failed"}
    mock_create_snapshot.side_effect = exc

    response = client.post("/snapshots", json={})

    assert response.status_code == 400
    assert response.get_json()["error"] == "Validation failed"


@patch("routes.get_snapshots")
def test_get_snapshots_success_default_pagination(mock_get_snapshots, client):

    mock_get_snapshots.return_value = {"data": ["snap1", "snap2"]}

    response = client.get("/products/prodA/versions/1.0/snapshots")

    assert response.status_code == 200
    assert response.get_json()["data"] == ["snap1", "snap2"]

    mock_get_snapshots.assert_called_once_with("prodA", "1.0", 10, 0)


@patch("routes.get_snapshots")
def test_get_snapshots_with_limit_offset(mock_get_snapshots, client):

    mock_get_snapshots.return_value = {"data": []}

    response = client.get(
        "/products/prodA/versions/1.0/snapshots?limit=5&offset=2"
    )

    assert response.status_code == 200

    mock_get_snapshots.assert_called_once_with("prodA", "1.0", 5, 2)


@patch("routes.get_snapshots")
def test_get_snapshots_strip_inputs(mock_get_snapshots, client):

    mock_get_snapshots.return_value = {"data": []}

    response = client.get(
        "/products/%20prodA%20/versions/%201.0%20/snapshots"
    )

    assert response.status_code == 200

    mock_get_snapshots.assert_called_once_with("prodA", "1.0", 10, 0)

from routes import ValidationError


@patch("routes.get_snapshots")
def test_get_snapshots_validation_error(mock_get_snapshots, client):

    mock_get_snapshots.side_effect = ValidationError("Invalid input")

    response = client.get("/products/prodA/versions/1.0/snapshots")

    assert response.status_code == 400
    assert response.get_json()["error"] == "Invalid input"


@patch("routes.get_snapshots")
def test_get_snapshots_not_found(mock_get_snapshots, client):

    mock_get_snapshots.side_effect = NotFoundError("Not found")

    response = client.get("/products/prodA/versions/1.0/snapshots")

    assert response.status_code == 404
    assert response.get_json()["error"] == "Not found"


@patch("routes.get_snapshots")
def test_get_snapshots_db_error(mock_get_snapshots, client):

    mock_get_snapshots.side_effect = DatabaseError("DB failure")

    response = client.get("/products/prodA/versions/1.0/snapshots")

    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"


@patch("routes.get_snapshots")
def test_get_snapshots_generic_exception(mock_get_snapshots, client):

    mock_get_snapshots.side_effect = Exception("Unexpected")

    response = client.get("/products/prodA/versions/1.0/snapshots")

    assert response.status_code == 500
    assert response.get_json()["error"] == "Unexpected server error"

@patch("routes.get_snapshot")
def test_get_snapshot_success(mock_get_snapshot, client):

    mock_get_snapshot.return_value = {
        "snapshot_id": 1,
        "product_name": "prodA"
    }

    response = client.get("/snapshots/1")

    assert response.status_code == 200
    assert response.get_json()["snapshot_id"] == 1

    mock_get_snapshot.assert_called_once_with(1)

@patch("routes.get_snapshot")
def test_get_snapshot_validation_error(mock_get_snapshot, client):

    mock_get_snapshot.side_effect = ValidationError("Invalid input")

    response = client.get("/snapshots/1")

    assert response.status_code == 400
    assert response.get_json()["error"] == "Invalid input"

@patch("routes.get_snapshot")
def test_get_snapshot_not_found(mock_get_snapshot, client):

    mock_get_snapshot.side_effect = NotFoundError("Snapshot not found")

    response = client.get("/snapshots/1")

    assert response.status_code == 404
    assert response.get_json()["error"] == "Snapshot not found"

@patch("routes.get_snapshot")
def test_get_snapshot_db_error(mock_get_snapshot, client):

    mock_get_snapshot.side_effect = DatabaseError("DB error")

    response = client.get("/snapshots/1")

    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"


@patch("routes.get_snapshot")
def test_get_snapshot_generic_exception(mock_get_snapshot, client):

    mock_get_snapshot.side_effect = Exception("Something failed")

    response = client.get("/snapshots/1")

    assert response.status_code == 500
    assert response.get_json()["error"] == "Unexpected server error"


@patch("routes.get_snapshot_changes")
def test_get_changes_default(mock_get_changes, client):

    mock_get_changes.return_value = {"data": []}

    response = client.get("/snapshots/10/changes")

    assert response.status_code == 200
    assert response.get_json()["data"] == []

    mock_get_changes.assert_called_once_with(
        10, 10, 0, None, None, None
    )

@patch("routes.get_snapshot_changes")
def test_get_changes_with_filters(mock_get_changes, client):

    mock_get_changes.return_value = {"data": []}

    response = client.get(
        "/snapshots/10/changes?limit=5&offset=2&change_type=resolved&severity=HIGH&component_name=compA"
    )

    assert response.status_code == 200

    mock_get_changes.assert_called_once_with(
        10, 5, 2, "resolved", "HIGH", "compA"
    )

@patch("routes.get_snapshot_changes")
def test_get_changes_empty_filters(mock_get_changes, client):

    mock_get_changes.return_value = {"data": []}

    response = client.get(
        "/snapshots/10/changes?change_type=&severity=&component_name="
    )

    assert response.status_code == 200

    mock_get_changes.assert_called_once_with(
        10, 10, 0, None, None, None
    )

@patch("routes.get_snapshot_changes")
def test_get_changes_validation_error(mock_get_changes, client):

    mock_get_changes.side_effect = ValidationError("Invalid filter")

    response = client.get("/snapshots/10/changes")

    assert response.status_code == 400
    assert response.get_json()["error"] == "Invalid filter"

@patch("routes.get_snapshot_changes")
def test_get_changes_not_found(mock_get_changes, client):

    mock_get_changes.side_effect = NotFoundError("Not found")

    response = client.get("/snapshots/10/changes")

    assert response.status_code == 404
    assert response.get_json()["error"] == "Not found"

@patch("routes.get_snapshot_changes")
def test_get_changes_db_error(mock_get_changes, client):

    mock_get_changes.side_effect = DatabaseError("DB issue")

    response = client.get("/snapshots/10/changes")

    assert response.status_code == 500
    assert response.get_json()["error"] == "Internal server error"

@patch("routes.get_snapshot_changes")
def test_get_changes_generic_error(mock_get_changes, client):

    mock_get_changes.side_effect = Exception("Unexpected")

    response = client.get("/snapshots/10/changes")

    assert response.status_code == 500
    assert response.get_json()["error"] == "Unexpected server error"


@patch("routes.db")
def test_health_success(mock_db, client):

    # Mock DB execution as success
    mock_db.session.execute.return_value = None

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "ok",
        "database": "ok"
    }

    mock_db.session.execute.assert_called_once()

@patch("routes.db")
def test_health_db_failure(mock_db, client):

    # Simulate DB failure
    mock_db.session.execute.side_effect = Exception("DB down")

    response = client.get("/health")

    assert response.status_code == 500
    assert response.get_json() == {
        "status": "down",
        "database": "down"
    }

@patch("routes.db")
@patch("routes.text")
def test_health_executes_select1(mock_text, mock_db, client):

    mock_text.return_value = "SELECT 1"

    response = client.get("/health")

    mock_text.assert_called_once_with("SELECT 1")
    mock_db.session.execute.assert_called_once_with("SELECT 1")

    assert response.status_code == 200
