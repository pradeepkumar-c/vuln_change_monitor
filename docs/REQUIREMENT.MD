# Cybellum - Backend Interview Exercise  
## Vulnerability Snapshot Change Monitor

Backend service exercise for vulnerability assessment and SBOM workflows.

---

## Overview

| Field | Details |
|------|--------|
| Audience | Backend developers joining a product security services / vulnerability assessment team |
| Expected timebox | 2 hours for core implementation |
| Primary stack | Python, Flask, SQLAlchemy, Docker, relational DB |
| Main signal | Deterministic diff logic, clean API design, validation, persistence, testing |

---

## Goal

Build an HTTP service (Dockerized) that:
- Ingests vulnerability snapshots
- Compares each snapshot with the previous one
- Stores computed differences
- Exposes change history via API

---

## Core Requirements

### Detect Changes

- **New vulnerabilities**
- **Resolved vulnerabilities**
- **Severity changes**
- **Affected status changes**
- **Unchanged count (no individual record required)**

---

## Out of Scope

- Authentication / Authorization  
- UI  
- Distributed systems (queues/workers)  
- SBOM parsing / enrichment  
- Complex out-of-order processing  

---

## Configuration (Env Variables)

| Variable | Required | Notes |
|----------|--------|------|
| DB_HOST | ✅ | Database host |
| DB_PORT | ✅ | Database port |
| DB_NAME | ✅ | Database name |
| DB_USER | ✅ | Database user |
| DB_PASSWORD | ✅ | Database password |
| PORT | ✅ | Default: 8080 |
| CONCURRENCY | ❌ | Optional |

---

## Input Model

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

---

## Allowed Values

### Severity
- critical, high, medium, low, none, unknown

### Affected Status
- affected, not_affected, fixed, under_investigation, accepted_risk

### CVSS Score
- Range: 0.0 to 10.0

---

## Finding Matching Key

```
vulnerability_id + component_name + component_version
```

### Rules

- Must be unique within a snapshot
- Reject duplicates → **400 Bad Request**
- Trim whitespace before comparison

---

## Snapshot Ordering Rules

- Must be strictly increasing by `snapshot_time`
- Reject older or same timestamp → **409 Conflict**
- Reject exact duplicates
- Previous snapshot = latest earlier snapshot

---

## Change Detection

| Type | Condition | Summary |
|------|----------|--------|
| new | Exists in current only | new++ |
| resolved | Exists in previous only | resolved++ |
| severity_changed | Severity differs | severity_changed++ |
| status_changed | Status differs | status_changed++ |
| unchanged | No changes | unchanged++ |

**Special Rule:**  
If both severity & status change → create **2 records**

---

## Database Design

### snapshots

- snapshot_id (UUID)
- product_name, product_version, source
- snapshot_time, created_at
- previous_snapshot_id
- finding_count
- summary counts

---

### snapshot_findings

- finding_id
- snapshot_id
- vulnerability_id
- component_name
- component_version
- package_url
- severity
- cvss_score
- affected_status

---

### snapshot_changes

- change_id
- snapshot_id
- previous_snapshot_id
- change_type
- vulnerability_id
- component fields
- previous_* and current_* values
- created_at

---

## API Endpoints

### POST /snapshots

Submit new snapshot.

**Response:**
```json
{
  "snapshot_id": "uuid",
  "product_name": "ExampleDevice",
  "product_version": "1.2.3",
  "previous_snapshot_id": "uuid-or-null",
  "summary": {
    "new": 1,
    "resolved": 0,
    "severity_changed": 0,
    "status_changed": 0,
    "unchanged": 0
  }
}
```

**Errors:**
- 400 → Validation
- 409 → Duplicate / ordering issue
- 500 → Server error

---

### GET /products/{product}/versions/{version}/snapshots

List snapshots (latest first)

---

### GET /snapshots/{snapshot_id}

Get snapshot metadata + summary

---

### GET /snapshots/{snapshot_id}/changes

Supports:
- Filters: `change_type`, `severity`, `component_name`
- Pagination: `limit`, `offset`

---

### GET /health

```json
{
  "status": "ok"
}
```

---

## Validation Rules

Handle:

- Missing fields
- Invalid enums
- Duplicate findings
- Invalid CVSS
- Invalid timestamps
- Unknown snapshot_id

---

## Required Tests

1. First snapshot → all new  
2. Mixed changes scenario  
3. Severity + status both change  
4. Validation failures  
5. Duplicate key rejection  
6. Duplicate snapshot rejection  
7. End-to-end flow  
8. Matching key correctness  
9. Filtering + pagination  

---

## README Must Include

- Build & run steps
- Docker instructions
- Env variables
- DB setup
- Test execution
- Matching key explanation
- Ordering & idempotency behavior
- Assumptions
- Future improvements

---

## Bonus Features (Optional)

- Idempotency key
- Docker Compose
- DB integration tests
- Logging
- Async processing
- Swagger/OpenAPI
- Transaction guarantees

---

## Example Usage

```bash
curl -X POST http://localhost:8080/snapshots   -H "Content-Type: application/json"   -d @snapshot-day-1.json

curl http://localhost:8080/snapshots/{snapshot_id}/changes
```
