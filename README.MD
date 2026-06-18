# Vulnerability Snapshot Monitor

A Flask-based REST API service that ingests vulnerability snapshot payloads, computes deterministic diffs against previous snapshots, persists findings and change history, and exposes query endpoints.

## Overview

The Vulnerability Snapshot Monitor is a backend service designed to:
- Ingest vulnerability snapshot payloads containing findings (vulnerabilities)
- Compare each snapshot with the previous one for the same product/version/source combination
- Detect and record changes: new vulnerabilities, resolved vulnerabilities, severity changes, and status changes
- Persist all snapshots, findings, and change history to a PostgreSQL database
- Expose REST API endpoints to query snapshots and change history with filtering and pagination

**Stack**: Python 3.11+, Flask, SQLAlchemy, PostgreSQL, Docker, pytest

---

## How to Build and Run Locally

### Prerequisites
- Python 3.11 or higher
- PostgreSQL 12+ database running locally or accessible
- pip (Python package manager)

### Steps

1. **Clone the repository** (if applicable):
   ```bash
   cd /path/to/Vulnerabilities
   ```

2. **Create a Python virtual environment**:
   ```bash
   python -m venv .venv
   ```

3. **Activate the virtual environment**:

     ```bash
     .venv\Scripts\activate
     ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # For development/testing
   ```

5. **Start the application**:
   ```bash
   python app.py
   ```

   The app will start on `http://localhost:8080`

6. **Verify the service is running**:
   ```bash
   curl http://localhost:8080/health
   # Response: {"status": "ok"}
   ```

---

## How to Run with Docker and Docker-Compose

### Prerequisites
- Docker and Docker-Compose installed

### Steps

1. **Build the Docker image locally**:
   ```bash
   docker build -t vuln-monitor:local .
   ```

2. **Start the full stack (app + PostgreSQL)** using Docker-Compose:
   ```bash
   docker-compose up --build
   ```

   This will:
   - Build/start the Flask app on port `8080`
   - Start PostgreSQL on port `5432`
   - Wait for PostgreSQL to be healthy before starting the app
   - Initialize the database schema automatically

3. **Verify the service**:
   ```bash
   curl http://localhost:8080/health
   ```

4. **Stop the stack**:
   ```bash
   docker-compose down
   ```

5. **Stop and remove all containers and volumes** (clean slate):
   ```bash
   docker-compose down -v
   ```

### Additional Docker Commands

- **Run a single command in the container** (e.g., run tests):
  ```bash
  docker-compose run --rm app pytest -v
  ```


- **Shell into the running app container**:
  ```bash
  docker exec -it <app-container-id> /bin/bash
  ```

---

## Required Environment Variables and Defaults

All environment variables are read at startup from the system environment.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_HOST` | Yes | `localhost` | PostgreSQL host address |
| `DB_PORT` | Yes | `5432` | PostgreSQL port number |
| `DB_NAME` | Yes | `mydb` | PostgreSQL database name |
| `DB_USER` | Yes | `myuser` | PostgreSQL user name |
| `DB_PASSWORD` | Yes | `mypassword` | PostgreSQL user password |
| `PORT` | Yes | `8080` | Port on which the Flask app listens |
| `CONCURRENCY` | No | `4` | Number of WSGI worker processes (used at deployment level, not internally) |
| `FLASK_ENV` | No | `development` | Set to `production` for production deployments |

### Local Development Example
```bash
# .env or manual export
DB_HOST=localhost
DB_PORT=5432
DB_NAME=mydb
DB_USER=myuser
DB_PASSWORD=mypassword
PORT=8080
FLASK_ENV=development
```

### Docker-Compose Defaults
See `Docker-compose.yml` for the defaults used by `docker-compose up`:
- PostgreSQL: `mydb` / `myuser` / `mypassword`
- App port: `8080`

---

## Database Setup

### Automatic Schema Creation

When the app starts, it **automatically creates the database schema** if it doesn't exist:
1. The Flask app initializes SQLAlchemy on startup (`db_init()` in `app.py`)
2. `db.create_all()` is called, which creates tables based on SQLAlchemy models
3. Tables created:
   - `snapshots` — Stores snapshot metadata and diff summary counts
   - `findings` — Stores individual vulnerability findings per snapshot
   - `snapshot_changes` — Stores detailed change records (new, resolved, severity_changed, status_changed)

### Database Constraints

The schema enforces:
- **Unique Constraint** on `snapshots`: `(product_name, product_version, source, snapshot_time)` — Prevents exact duplicates
- **Unique Constraint** on `findings`: `(snapshot_id, vulnerability_id, component_name, component_version)` — Prevents finding duplicates within a snapshot
- **Check Constraint** on `findings.cvss_score`: Must be between 0.0 and 10.0
- **Indix** Indexes were added based on query patterns to optimize snapshot lookup, diff computation, and change filtering operations.

### Resetting the Database

**Warning: This deletes all data.**

```bash
# Local PostgreSQL
psql -U myuser -d mydb -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# Docker-Compose
docker-compose down -v  # -v removes named volumes
docker-compose up --build  # Recreates fresh DB

## How to Run Tests

### Unit Tests (Locally)

1. **Activate the virtual environment** (if not already):
   ```bash
   .venv\Scripts\activate
   ```

2. **Install test dependencies**:
   ```bash
   pip install -r requirements-dev.txt
   ```

3. **Run all tests**:
   ```bash
   pytest
   ```

4. **Run tests with verbose output**:
   ```bash
   pytest -v
   ```

5. **Run specific test file**:
   ```bash
   pytest tests/unit/test_app.py
   ```

6. **Run tests with coverage report**:
   ```bash
   pytest --cov=. --cov-report=html
   open htmlcov/index.html  # View HTML coverage report
   ```

### Integration Tests (Requires Database)

Integration tests start a containerized PostgreSQL instance via `testcontainers`:

```bash
pytest tests/integration/ -v
```

**Note**: Integration tests may take longer due to container startup.

### Tests in Docker

```bash
# Run all tests in Docker
docker-compose run --rm app pytest -v

# Run specific test
docker-compose run --rm app pytest tests/unit/test_app.py::test_db_init_success -v

# Run with coverage
docker-compose run --rm app pytest --cov=. --cov-report=term-missing
```

### Test Directory Structure
- `tests/unit/` — Unit tests for individual components (mocked DB, validators)
- `tests/unit/test_app.py` — Tests for Flask app initialization
- `tests/unit/test_routes.py` — Tests for route handlers and error mapping
- `tests/unit/test_service.py` — Tests for business logic and validators
- `tests/unit/test_validator.py` — Tests for input validation functions
- `tests/integration/` — Integration tests with real DB via testcontainers
- `tests/integration/test_snapshot_api.py` — End-to-end API tests

---

## Matching-Key Explanation

### Matching Key Concept

The service identifies vulnerabilities across snapshots using a **matching key** — a composite identifier that uniquely identifies a finding within a product/version scope:

**Matching Key = `(vulnerability_id, component_name, component_version)`**

When comparing two snapshots, the service:
1. Extracts the matching key from each finding
2. Looks for findings with the same matching key in the previous snapshot
3. If found, compares attributes (severity, affected_status)
4. If not found, the finding is new

### Example

**Snapshot 1 (Day 1)**:
```json
{
  "vulnerability_id": "CVE-2024-12345",
  "component_name": "openssl",
  "component_version": "1.1.1k",
  "severity": "high",
  "affected_status": "affected"
}
```

**Snapshot 2 (Day 2)** contains the same component but:
- **Same CVE, same component/version, different severity** → `severity_changed` (e.g., high → critical)
- **Same CVE, same component/version, different status** → `status_changed` (e.g., affected → fixed)
- **CVE is missing** → `resolved`
- **New CVE** → `new`

### Normalization

The service normalizes matching keys by **trimming whitespace** from:
- `vulnerability_id`
- `component_name`
- `component_version`

Example: `"CVE-2024-12345 "` (with trailing space) is treated as `"CVE-2024-12345"`.

### Database Representation

- **`Findings` table**: Stores all findings with `vulnerability_id`, `component_name`, `component_version` indexed for fast lookups
- **Unique constraint**: `(snapshot_id, vulnerability_id, component_name, component_version)` prevents duplicate findings in the same snapshot

---

## Snapshot Ordering, Duplicate Submission, and Idempotency

### Snapshot Ordering

**Definition**: Snapshots are ordered by `snapshot_time` within a `(product_name, product_version, source)` group.

**Ordering Rules**:
1. Two snapshots with the **same product/version/source** must have **different `snapshot_time` values**
2. The service accepts snapshots in **any order** (e.g., Day 1, Day 3, Day 2 is allowed)
3. When computing diffs, the service uses the **most recent prior snapshot** by `snapshot_time`

**Example**:
- Product: `ExampleDevice`, Version: `1.2.3`, Source: `daily-scan`
- Ingestion order: Day 1 → Day 3 → Day 2
- Diff computation:
  - Day 1: First snapshot (all findings are "new")
  - Day 3: Compared against Day 1 (most recent before Day 3)
  - Day 2: Compared against Day 1 (most recent before Day 2, not Day 3 because Day 2 < Day 3)

### Duplicate Submission Handling

**Duplicate Detection**: A duplicate is detected when:
- **Exact duplicate**: Same `(product_name, product_version, source, snapshot_time)` is submitted

**Response**:
- **HTTP 409 Conflict** with message: `"A snapshot with same product/version/source and snapshot_time exists"`

**Out-of-Order Rejection**: If a newer or equal `snapshot_time` already exists:
- **HTTP 409 Conflict** with message: `"A newer snapshot with same product/version/source with latest snapshot_time exists"`

**Database Constraint**:
- `UNIQUE (product_name, product_version, source, snapshot_time)` enforces no duplicates

### Idempotency

The service is **conditionally idempotent**:
- **Idempotent**: Submitting the exact same snapshot twice (same `snapshot_time`) → Second submission rejected with 409 Conflict (idempotent behavior: no state change)
- **Not idempotent**: Submitting a snapshot with a different timestamp affects diff calculations

**Implications**:
- Clients can safely retry failed POST requests (same timestamp → 409, no duplicate data created)
- Clients must avoid submitting multiple snapshots with the same timestamp
- Timestamp should be server-provided or synchronized to prevent collisions

---

## Assumptions and Shortcuts

### Key Assumptions

1. **Source as Identity Component**: The service treats `source` as part of snapshot identity. Different ingestion sources (e.g., `daily-scan` vs `on-demand-scan`) for the same product/version are tracked independently.

2. **No Cross-Source Diffing**: Snapshots from different sources are never compared. Each source maintains its own snapshot sequence.

3. **Synchronous Processing**: Snapshot ingestion is synchronous. No queuing, no background processing. The POST request blocks until persistence is complete.

4. **Single-Threaded Snapshot Logic**: Per-snapshot diff computation is single-threaded for correctness. Concurrency (`CONCURRENCY` env var) applies only to request-level parallelism (WSGI workers), not within a single snapshot transaction.

5. **PostgreSQL as Primary DB**: The service is optimized for PostgreSQL. Other databases may not be fully compatible due to PostgreSQL-specific features (UUID type, Enums, etc.).

6. **Auto-Initialization**: Database schema is auto-created on first run. No manual migration step required for development.

7. **No Authentication**: The service has no authentication or authorization. It assumes network-level access control.

8. **Vulnerability Matching by Composite Key**: Vulnerabilities are matched using `(vulnerability_id, component_name, component_version)`. No fuzzy matching or alias resolution.

9. **Severity and Status as Fixed Enums**: Severity (critical, high, medium, low, none, unknown) and affected_status (affected, not_affected, fixed, under_investigation, accepted_risk) are fixed enums. No custom values allowed.

10. **CVSS Score Validation**: CVSS scores must be 0.0–10.0 if provided. Scores outside this range are rejected with HTTP 400.

### Shortcuts and Limitations

1. **No Alembic Migrations**: Database schema updates are manual. No version-controlled migration history.

2. **No Query Result Size Limits**: `limit` and `offset` parameters have no server-enforced maximums. Large result sets could cause performance issues.

3. **Concurrency guidance**: We avoid threading/multiprocessing because it complicates database transactions. Concurrency is handled by the server (e.g., Gunicorn workers), which is simpler and safer.

4. **No Connection Pooling Configuration**: Database connections are managed by SQLAlchemy's default pool. High concurrency may exhaust connections.

5. **No Request Logging to DB**: API requests/responses are logged only to stdout, not persisted.

6. **No Audit Trail**: Who/what changed data is not tracked. Only `created_at` timestamp is recorded.

7. **No Rate Limiting**: No request rate limiting or throttling. Clients can flood the API.

8. **No Snapshot Expiration**: Old snapshots are never deleted. Storage grows indefinitely.

9. **Minimal Error Details**: Error responses include generic messages, not detailed stack traces (by design for security).



## API Endpoints

### Core Endpoints

| Method | Path | Description | Status Codes |
|--------|------|-------------|--------------|
| POST | `/snapshots` | Ingest a vulnerability snapshot payload. | `201`, `400`, `409`, `500` |
| GET | `/snapshots` | List snapshots filtered by `product_name`, `product_version` with pagination. | `200`, `400`, `500` |
| GET | `/snapshots/{snapshot_id}` | Get a specific snapshot summary and diff counts. | `200`, `404`, `500` |
| GET | `/snapshots/{snapshot_id}/changes` | List change rows for a snapshot with filtering and pagination. | `200`, `400`, `404`, `500` |
| GET | `/health` | Health check endpoint. | `200`, `500` |

### Endpoint Details

#### POST `/snapshots`
**Ingest a vulnerability snapshot**

**Request**:
```json
{
  "product_name": "ExampleDevice",
  "product_version": "1.2.3",
  "source": "daily-vulnerability-scan",
  "snapshot_time": "2026-01-01T10:00:00Z",
  "findings": [
    {
      "vulnerability_id": "CVE-2024-12345",
      "component_name": "openssl",
      "component_version": "1.1.1k",
      "package_url": "pkg:generic/openssl@1.1.1k",
      "severity": "high",
      "cvss_score": 8.1,
      "affected_status": "affected"
    }
  ]
}
```

**Response (201 Created)**:
```json
{
  "snapshot_id": "6aeaa0d1-2f12-40c2-a01d-88c0bac5254d",
  "product_name": "ExampleDevice",
  "product_version": "1.2.3",
  "source": "daily-vulnerability-scan",
  "snapshot_time": "2026-01-01T10:00:00Z",
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

**Error Responses**:
- `400 Bad Request`: Validation error (missing field, invalid enum, out-of-range CVSS)
- `409 Conflict`: Duplicate or out-of-order submission
- `500 Internal Server Error`: Server error

#### GET `/snapshots`
**List snapshots with filtering and pagination**

**Query Parameters**:
- `product_name` (optional): Filter by product name
- `product_version` (optional): Filter by product version
- `limit` (optional, default: 10): Number of results per page
- `offset` (optional, default: 0): Number of results to skip

**Example**:
```bash
GET /snapshots?product_name=ExampleDevice&product_version=1.2.3&limit=20&offset=0
```

**Response (200 OK)**:
```json
{
  "snapshots": [
    {
      "snapshot_id": "6aeaa0d1-2f12-40c2-a01d-88c0bac5254d",
      "product_name": "ExampleDevice",
      "product_version": "1.2.3",
      "source": "daily-vulnerability-scan",
      "snapshot_time": "2026-01-01T10:00:00Z",
      "finding_count": 3,
      "created_at": "2026-01-01T10:05:00Z",
      "summary": {
        "new": 3,
        "resolved": 0,
        "severity_changed": 0,
        "status_changed": 0,
        "unchanged": 0
      }
    }
  ],
  "total_count": 1,
  "limit": 20,
  "offset": 0
}
```

#### GET `/snapshots/{snapshot_id}`
**Get a specific snapshot**

**Example**:
```bash
GET /snapshots/6aeaa0d1-2f12-40c2-a01d-88c0bac5254d
```

**Response (200 OK)**:
```json
{
  "snapshot_id": "6aeaa0d1-2f12-40c2-a01d-88c0bac5254d",
  "product_name": "ExampleDevice",
  "product_version": "1.2.3",
  "source": "daily-vulnerability-scan",
  "snapshot_time": "2026-01-01T10:00:00Z",
  "finding_count": 3,
  "created_at": "2026-01-01T10:05:00Z",
  "summary": {
    "new": 3,
    "resolved": 0,
    "severity_changed": 0,
    "status_changed": 0,
    "unchanged": 0
  }
}
```

**Error Response (404 Not Found)**:
```json
{
  "error": "Snapshot not found"
}
```

#### GET `/snapshots/{snapshot_id}/changes`
**List change rows for a snapshot with filtering**

**Query Parameters**:
- `change_type` (optional): Filter by `new`, `resolved`, `severity_changed`, or `status_changed`
- `severity` (optional): Filter by severity (`critical`, `high`, `medium`, `low`, `none`, `unknown`)
- `component_name` (optional): Filter by component name
- `limit` (optional, default: 10): Number of results per page
- `offset` (optional, default: 0): Number of results to skip

**Example**:
```bash
GET /snapshots/6aeaa0d1-2f12-40c2-a01d-88c0bac5254d/changes?change_type=new&limit=20
```

**Response (200 OK)**:
```json
{
  "changes": [
    {
      "change_id": 1,
      "snapshot_id": "6aeaa0d1-2f12-40c2-a01d-88c0bac5254d",
      "change_type": "new",
      "vulnerability_id": "CVE-2024-12345",
      "component_name": "openssl",
      "component_version": "1.1.1k",
      "package_url": "pkg:generic/openssl@1.1.1k",
      "previous_severity": null,
      "current_severity": "high",
      "previous_cvss_score": null,
      "current_cvss_score": 8.1,
      "previous_affected_status": null,
      "current_affected_status": "affected",
      "created_at": "2026-01-01T10:05:00Z"
    }
  ],
  "total_count": 1,
  "limit": 20,
  "offset": 0
}
```

#### GET `/health`
**Health check endpoint**

**Example**:
```bash
GET /health
```

**Response (200 OK)**:
```json
{
  "status": "ok"
}
```

**Error Response (500 Internal Server Error)**:
```json
{
  "error": "Database connection failed"
}
```

---

## Project Files

| File | Purpose |
|------|---------|
| `app.py` | Flask app initialization, database setup, and route registration |
| `routes.py` | HTTP route handlers and HTTP status code mapping for domain exceptions |
| `service.py` | Business logic: snapshot diff computation, persistence, and query helpers |
| `model.py` | SQLAlchemy models for `Snapshots`, `Findings`, and `SnapshotChanges` tables |
| `validator.py` | Input validation for snapshot and finding payloads |
| `Dockerfile` | Docker image definition (Python 3.11, dependencies, app) |
| `Docker-compose.yml` | Multi-container orchestration (Flask app + PostgreSQL) |
| `requirements.txt` | Python dependencies (Flask, SQLAlchemy, psycopg2) |
| `requirements-dev.txt` | Development dependencies (pytest, pytest-cov, testcontainers) |
| `tests/unit/` | Unit tests with mocked dependencies |
| `tests/integration/` | Integration tests with real PostgreSQL container |
| `testdata/` | Example snapshot JSON payloads for manual testing |
| `docs/` | Additional documentation (architecture, requirements, service structure) |

