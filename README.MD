# Vulnerability Snapshot Monitor

This repository implements a Flask-based service that ingests vulnerability snapshot payloads, computes diffs against the previous snapshot for the same product/version/source, persists findings and change rows, and exposes query endpoints.

## Project files (short explanation)
- `app.py`: Flask app bootstrap and application entry point. Initializes DB and registers routes.
- `routes.py`: HTTP route handlers and mapping of domain exceptions to HTTP status codes.
- `service.py`: Business logic for validation, diff computation, persistence helpers, and read/query helpers.
- `model.py`: SQLAlchemy models for `Snapshots`, `Findings`, and `SnapshotChanges`.
- `Dockerfile` / `Docker-compose.yml`: Container image and compose configuration for app + Postgres.
- `Test/`: Unit tests (pytest). Add integration tests here.
- `Testdata/`: Example snapshot JSON payloads used for tests.

## Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/snapshots` | Ingest a snapshot payload. Returns stored snapshot summary and `snapshot_id`. Responses: `201` success, `400` validation error, `409` duplicate/out-of-order, `500` server error. |
| GET | `/snapshots` | List snapshots filtered by `product_name` and `product_version` with `limit` and `offset` pagination. |
| GET | `/snapshots/{snapshot_id}` | Get snapshot summary and counts. Returns `404` if not found. |
| GET | `/snapshots/{snapshot_id}/changes` | List change rows for a snapshot. Supports `change_type`, `severity`, `component_name`, plus `limit`/`offset`. |
| GET | `/health` | Health check. Returns an object with at least `status` (recommendation: `{"status":"ok"}`). |

Note: This implementation treats `source` as part of snapshot identity and ordering. Accepted snapshots are chosen per `product_name`, `product_version`, and `source` (this is an explicit project assumption to keep scans from different ingestion sources isolated). Document or change this behavior if you prefer ordering across sources.

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
- `CONCURRENCY` - # of worker processes to run (recommend using process manager/gunicorn)

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

## Concurrency guidance (short)

- Recommended: process-level concurrency (one process per worker). Use a production WSGI server (e.g. `gunicorn -w <workers> -b 0.0.0.0:8080 app:app`) or run multiple container replicas.
- Avoid spawning subprocesses or multiprocessing inside the request path for snapshot ingestion because:
  - DB sessions and transactions do not safely span child processes.
  - Complexity around connection pools and transactional integrity increases.
- Threading: Flask can serve multiple threads, but for CPU-heavy work or to avoid GIL contention, prefer process workers.

## What to add next
- Add integration tests (SQLite in-memory or test Postgres) for the core scenarios described in `Requirement.MD`.
- Add DB migration scripts (Alembic) to manage schema changes in production environments.

