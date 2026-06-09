# Architecture and Diagrams

## Overview
This document shows the high-level architecture and important flows for the Vulnerability Snapshot Monitor.

### Overall Architecture

```mermaid
graph LR
  Client[Client - API Consumer] -->|HTTP POST or GET| API[Flask API - routes.py]
  API --> Service[Service Layer - service.py]
  Service --> DB[(Postgres / SQLAlchemy)]
  Service -->|Reads/Writes| Findings[Findings table]
  Service -->|Reads/Writes| Snapshots[Snapshots table]
  Service -->|Reads/Writes| Changes[SnapshotChanges table]
  subgraph Observability
    API --> Logs[Logging]
    API --> Metrics[Metrics]
  end
```

Explanation:
- Client: external system or user that submits snapshots or queries change history.
- Flask API (`routes.py`): thin HTTP layer that handles request parsing, response formatting and maps domain exceptions (validation/conflict/not found) to HTTP status codes.
- Service layer (`service.py`): core business logic — validation, diff computation, persistence helpers, and query functions.
- Database: Postgres via SQLAlchemy stores `Snapshots`, `Findings`, and `SnapshotChanges` tables. Observability components capture logs and metrics.

### Component Design (simplified)

```mermaid
flowchart TB
  Routes[Routes (routes.py)] --> ServiceComp[Service (service.py)]
  ServiceComp --> Models[Models (model.py) - Snapshots/Findings/Changes]
  Models --> DBComp[SQLAlchemy / Postgres]
  Routes -->|error mapping| Errors[Error mapping (HTTP codes)]
  ServiceComp -->|validation & diff| Validators[Validators & Helpers]
```

Explanation:
- `routes.py` keeps request/response concerns and delegates domain work to `service.py`.
- `service.py` should contain deterministic algorithms for diffing snapshots and all DB interactions; it raises domain exceptions that routes map to HTTP responses.
- `model.py` contains SQLAlchemy models and DB constraints (unique keys, check constraints).

### Sequence: POST /snapshots (ingest)

```mermaid
sequenceDiagram
  participant C as Client
  participant R as Routes
  participant S as Service
  participant DB as Database

  C->>R: POST /snapshots (snapshot JSON payload)
  R->>S: call create_snapshot(data)
  S->>S: validate_snapshot_data() - validate top-level and per-finding fields
  S->>DB: get_existing_snapshot() - fetch latest accepted snapshot for product/version/source
  DB-->>S: returns previous snapshot row or null
  S->>S: update_findings() - compute diff: new, resolved, severity_changed, status_changed, unchanged
  S->>DB: insert Snapshots row (new snapshot metadata)
  S->>DB: insert Findings rows for new snapshot
  S->>DB: insert SnapshotChanges rows for detected changes
  S->>DB: commit transaction
  S-->>R: return snapshot summary object
  R-->>C: HTTP 201 Created + summary JSON
```

Step-by-step sequence explanation:
1. Client submits a well-formed snapshot JSON to `POST /snapshots`.
2. `routes.py` forwards the payload to `create_snapshot()` in `service.py` (a thin wrapper ensures HTTP-layer concerns remain separate).
3. `service.py` runs `validate_snapshot_data()` to check required top-level fields (`product_name`, `product_version`, `source`, `snapshot_time`, `findings`) and per-finding fields (`vulnerability_id`, `component_name`, `component_version`, `severity`, `affected_status`, `cvss_score`). Validation returns deterministic 400 errors for invalid inputs.
4. `service.py` queries the DB for the previous accepted snapshot for the same `product_name`, `product_version`, and `source` (current assumption in this repo). If none exists, the current snapshot is treated as the first snapshot.
5. The diff computation (`update_findings` / `get_resolved_findings_count`) compares matching-key tuples (`vulnerability_id`, `component_name`, `component_version`) to determine `new`, `resolved`, `severity_changed`, and `status_changed`. If both severity and affected_status change for the same finding, two change rows are created.
6. The service inserts the new `Snapshots` row, associated `Findings` rows, and `SnapshotChanges` rows within a DB transaction. After successful writes, the transaction is committed.
7. The service returns a structured summary (snapshot_id, product/version/source, snapshot_time, previous_snapshot_id, and summary counts). `routes.py` formats this into an HTTP 201 response.

Notes:
- The service currently treats `source` as part of snapshot identity to keep data from different scanners or sources isolated; change this behavior if you want cross-source ordering.
- Keep business logic deterministic and covered by unit/integration tests. The next step is to add integration tests that post snapshots and validate resulting DB state and change rows.
