
from app import db, app
import pytest


def test_create_snapshot_integration(client):

    payload = {
        "product_name": "prodA",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {
                "vulnerability_id": "V1",
                "component_name": "compA",
                "component_version": "1.0",
                "severity": "high",
                "affected_status": "affected"
            }
        ]
    }

    response = client.post("/snapshots", json=payload)

    assert response.status_code == 201
    data = response.get_json()

    assert data["product_name"] == "prodA"
    assert data["summary"]["new"] == 1

def test_get_snapshot_integration(client):

    payload = {
        "product_name": "prodC",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {
                "vulnerability_id": "V1",
                "component_name": "compA",
                "component_version": "1.0",
                "severity": "high",
                "affected_status": "affected"
            }
        ]
    }
    

    post_res = client.post("/snapshots", json=payload)
    snapshot_id = post_res.get_json()["snapshot_id"]

    print(f"Created snapshot with ID: {snapshot_id}")
    response = client.get(f"/snapshots/{snapshot_id}")
    print(f"GET snapshot response: {response.get_json()}")

    assert response.status_code == 200
    assert response.get_json()["snapshot_id"] == snapshot_id

def test_get_changes_integration(client):

    # create snapshot
    payload = {
        "product_name": "prodE",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {
                "vulnerability_id": "V1",
                "component_name": "compA",
                "component_version": "1.0",
                "severity": "high",
                "affected_status": "affected"
            }
        ]
    }

    res = client.post("/snapshots", json=payload)
    snapshot_id = res.get_json()["snapshot_id"]

    response = client.get(f"/snapshots/{snapshot_id}/changes")

    assert response.status_code == 200

def test_health_integration(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_first_snapshot_all_new(client):
    payload = {
        "product_name": "prod1",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {
                "vulnerability_id": "V1",
                "component_name": "compA",
                "component_version": "1.0",
                "severity": "high",
                "affected_status": "affected"
            }
        ]
    }

    res = client.post("/snapshots", json=payload)
    data = res.get_json()

    assert res.status_code == 201
    assert data["summary"]["new"] == 1

def test_mixed_diff(client):
    payload1 = {
        "product_name": "prod2",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"}
        ]
    }

    payload2 = {
        **payload1,
        "snapshot_time": "2025-06-02T10:00:00Z",
        "findings": [
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"},  # unchanged
            {"vulnerability_id": "V2", "component_name": "compB", "component_version": "1.0", "severity": "low", "affected_status": "affected"}   # new
        ]
    }

    client.post("/snapshots", json=payload1)
    res = client.post("/snapshots", json=payload2)

    summary = res.get_json()["summary"]

    assert summary["new"] == 1
    assert summary["unchanged"] == 1


def test_severity_and_status_change(client):
    payload1 = {
        "product_name": "prod3",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "low", "affected_status": "affected"}
        ]
    }

    payload2 = {
        **payload1,
        "snapshot_time": "2025-06-02T10:00:00Z",
        "findings": [
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "fixed"}
        ]
    }

    client.post("/snapshots", json=payload1)
    res = client.post("/snapshots", json=payload2)

    summary = res.get_json()["summary"]

    assert summary["severity_changed"] == 1
    assert summary["status_changed"] == 1

    snapshot_id = res.get_json()["snapshot_id"]
    response = client.get(f"/snapshots/{snapshot_id}/changes?limit=2&offset=0")
    assert response.status_code == 200
    data = response.get_json()
    changes = data["changes"]
    assert len(changes) == 2

def test_validation_error_missing_fields(client):
    payload = {
        "product_name": "prod4",
    }

    res = client.post("/snapshots", json=payload)

    assert res.status_code == 400


def test_duplicate_finding_in_payload(client):
    payload = {
        "product_name": "prod5",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"},
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"}
        ]
    }

    res = client.post("/snapshots", json=payload)

    assert res.status_code == 400


def test_duplicate_snapshot_rejection(client):
    payload = {
        "product_name": "prod6",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"},
            {"vulnerability_id": "V2", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"}
        ]
    }

    client.post("/snapshots", json=payload)
    res = client.post("/snapshots", json=payload)

    assert res.status_code == 409

def test_duplicate_snapshot_rejection_older_snapshot(client):
    payload = {
        "product_name": "prod6",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"},
            {"vulnerability_id": "V2", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"}
        ]
    }

    payload1 = {
        **payload,
        "snapshot_time": "2025-06-01T10:00:00Z",
    }
    client.post("/snapshots", json=payload)
    res = client.post("/snapshots", json=payload1)

    assert res.status_code == 409

def test_full_api_flow(client):
    payload = {
        "product_name": "prod7",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"},
            {"vulnerability_id": "V2", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"}
        ]
    }

    post_res = client.post("/snapshots", json=payload)
    snapshot_id = post_res.get_json()["snapshot_id"]

    get_res = client.get(f"/snapshots/{snapshot_id}")
    changes_res = client.get(f"/snapshots/{snapshot_id}/changes")

    assert post_res.status_code == 201
    assert get_res.status_code == 200
    assert changes_res.status_code == 200


def test_matching_key_behavior(client):
    payload1 = {
        "product_name": "prod8",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"},
            {"vulnerability_id": "V2", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"}
        ]
    }

    payload2 = {
        **payload1,
        "snapshot_time": "2025-06-02T10:00:00Z",
        "findings": [
            {"vulnerability_id": "V1", "component_name": "compA", "component_version": "1.0", "severity": "high", "affected_status": "affected"}
        ]

    }

    client.post("/snapshots", json=payload1)
    res = client.post("/snapshots", json=payload2)

    summary = res.get_json()["summary"]

    assert summary["new"] == 0
    assert summary["unchanged"] == 1
    assert summary["resolved"] == 1

def test_pagination_and_filtering(client):
    payload = {
        "product_name": "prod9",
        "product_version": "1.0",
        "source": "scanner",
        "snapshot_time": "2025-06-01T10:00:00Z",
        "findings": [
            {"vulnerability_id": f"V{i}", "component_name": "comp", "component_version": "1.0", "severity": "low", "affected_status": "affected"}
            for i in range(5)
        ]
    }

    res = client.post("/snapshots", json=payload)
    snapshot_id = res.get_json()["snapshot_id"]

    response = client.get(f"/snapshots/{snapshot_id}/changes?limit=2&offset=0")

    assert response.status_code == 200
    assert len(response.get_json()) <= 2


