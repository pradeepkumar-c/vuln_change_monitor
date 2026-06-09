
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

    # Then fetch
    response = client.get(f"/snapshots/{snapshot_id}")

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
