# Vulnerability Snapshot Monitor

This repository implements a Flask-based service that ingests vulnerability snapshot payloads, computes diffs against the previous snapshot for the same product/version/source, persists findings and change rows, and exposes query endpoints.

## Project files (short explanation)
- `app.py`: Flask app bootstrap and application entry point. Initializes DB and registers routes.
- `routes.py`: HTTP route handlers and mapping of domain exceptions to HTTP status codes.
- `service.py`: Business logic for validation, diff computation, persistence helpers, and read/query helpers.
- `model.py`: SQLAlchemy models for `Snapshots`, `Findings`, and `SnapshotChanges`.
- `validator.py`: Validates the json data received.
- `Dockerfile` / `Docker-compose.yml`: Container image and compose configuration for app + Postgres.
- `tests/unit`: Unit tests (pytest)
- `tests/integration`: Integration tests here.
- `Testdata/`: Example snapshot JSON payloads used for tests.

## Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/snapshots` | Ingest a snapshot payload. Returns stored snapshot summary and `snapshot_id`. Responses: `201` success, `400` validation error, `409` duplicate/out-of-order, `500` server error. |
| GET | `/snapshots` | List snapshots filtered by `product_name` and `product_version` with `limit` and `offset` pagination. |
| GET | `/snapshots/{snapshot_id}` | Get snapshot summary and counts. Returns `404` if not found. |
| GET | `/snapshots/{snapshot_id}/changes` | List change rows for a snapshot. Supports `change_type`, `severity`, `component_name`, plus `limit`/`offset`. |
| GET | `/health` | Health check. Returns an object with at least `status` (recommendation: `{"status":"ok"}`). |

Note: This implementation treats `source` as part of snapshot identity and ordering. Accepted snapshots are chosen per `product_name`, `product_version`, and `source` (this is an explicit project assumption to keep scans from different ingestion sources isolated).

## Build and run with Docker / docker-compose

Build the docker image locally:

```
docker build -t vuln-monitor:local .
```

Run with docker-compose (starts app + postgres):

```
docker-compose up --build
```

Environment variables (see `docker-compose.yml` for defaults):
- `DATABASE_URL` - SQLAlchemy DB URL
- `FLASK_ENV` - `development` or `production`

## Run tests

Install dependencies and run tests locally:

```
python -m venv .venv
.venv\Scripts\activate    # Windows
pip install -r requirements.txt
pytest -q
```

Run tests in Docker (if image includes test deps):

```
docker-compose run --rm app pytest -q
```
## Example Usage
1. Snapsshot creation
```
curl -i -X POST http://localhost:8080/snapshots -H "Content-Type: application/json" -d @Testdata/snapshot-day-4.json

HTTP/1.1 201 CREATED
Server: Werkzeug/3.1.8 Python/3.11.15
Date: Thu, 18 Jun 2026 04:10:34 GMT
Content-Type: application/json
Content-Length: 388
Connection: close

{
  "snapshot_id": "6aeaa0d1-2f12-40c2-a01d-88c0bac5254d",
  "product_name": "ExampleDevice7",
  "product_version": "1.2.3.5",
  "source": "daily-vulnerability-scan",
  "snapshot_time": "2026-01-01T12:00:10",
  "finding_count": 3,
  "previous_snapshot_id": null,
  "summary": {
    "new": 3,
    "resolved": 0,
    "severity_changed": 0,
    "status_changed": 0,
    "unchanged": 0
  }
}
```
2.Getting snapshot status
```
curl -i -X GET http://localhost:8080/snapshots/6aeaa0d1-2f12-40c2-a01d-88c0bac5254d/changes

HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.11.15
Date: Thu, 18 Jun 2026 04:14:54 GMT
Content-Type: application/json
Content-Length: 1096
Connection: close

{
  "changes": [
    {
      "change_type": "new",
      "vulnerability_id": "CVE-2024-12345678",
      "component_name": "openssl",
      "component_version": "1.1.1k",
      "package_url": "pkg:generic/openssl@1.1.1k",
      "previous": null,
      "current": {
        "severity": "medium",
        "cvss_score": 7.1,
        "affected_status": "not_affected"
      }
    },
    {
      "change_type": "new",
      "vulnerability_id": "CVE-2024-12345679",
      "component_name": "openssl",
      "component_version": "1.1.1k",
      "package_url": "pkg:generic/openssl@1.1.1k",
      "previous": null,
      "current": {
        "severity": "low",
        "cvss_score": 8.1,
        "affected_status": "not_affected"
      }
    },
    {
      "change_type": "new",
      "vulnerability_id": "CVE-2024-123456791",
      "component_name": "openssl",
      "component_version": "1.1.1k",
      "package_url": "pkg:generic/openssl@1.1.1k",
      "previous": null,
      "current": {
        "severity": "low",
        "cvss_score": 8.1,
        "affected_status": "affected"
      }
    }
  ]
}
```
3. Getting specfic changes of snapshot
```
curl -i -X GET http://localhost:8080/products/ExampleDevice7/versions/1.2.3.5/snapshots

HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.11.15
Date: Thu, 18 Jun 2026 04:17:51 GMT
Content-Type: application/json
Content-Length: 289
Connection: close

{
  "items": [
    {
      "snapshot_id": "6aeaa0d1-2f12-40c2-a01d-88c0bac5254d",
      "snapshot_time": "2026-01-01T12:00:10",
      "source": "daily-vulnerability-scan",
      "finding_count": 3,
      "created_at": "2026-06-18T04:10:33.989765"
    }
  ],
  "offset": 0,
  "limit": 10
}
```
4. Health check
```
curl.exe -i -X GET http://localhost:8080/health

HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.11.15
Date: Thu, 18 Jun 2026 04:19:12 GMT
Content-Type: application/json
Content-Length: 41
Connection: close

{
  "status": "ok",
  "database": "ok"
}
```
## Concurrency guidance

- We avoid threading/multiprocessing because it complicates database transactions. Concurrency is handled by the server (e.g., Gunicorn workers), which is simpler and safer.


## Database Optimization

Indexes were added based on query patterns to optimize snapshot lookup,
diff computation, and change filtering operations.
