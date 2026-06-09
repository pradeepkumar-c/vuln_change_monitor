from flask_sqlalchemy import SQLAlchemy
from model import db, Snapshots, Findings, SnapshotChanges
import time
import uuid
from datetime import datetime
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

allowed_severity = ['critical', 'high', 'medium', 'low', 'none', 'unknown']
allowed_affected_status = ['affected', 'not_affected', 'fixed', 'under_investigation', 'accepted_risk']
allowed_change_types = ['new', 'resolved', 'severity_changed', 'status_changed']
allowed_cvss_score_range = (0.0, 10.0)

def create_snapshot(data):
    try:
        print(f"Received snapshot data: {data}")
        valid, error = validate_snapshot_data(data)
        print(f"Snapshot data validation result: {valid}, {error}")
        if not valid:
            raise ValidationError(error)
        
        print(f"Snapshot data validated successfully, proceeding to update snapshot and findings")

        new_snapshot, existing_snapshot = update_snapshot(data)
        print(f"Snapshot update result: {new_snapshot}, {existing_snapshot}")

        print(f"Snapshot updated successfully, proceeding to update findings")
        update_findings(new_snapshot, existing_snapshot, data['findings'])
        
        db.session.commit()

        print(f"Findings updated successfully for snapshot_id: {new_snapshot.snapshot_id}")
        response = {
            'snapshot_id': new_snapshot.snapshot_id,
            'product_name': new_snapshot.product_name,
            'product_version': new_snapshot.product_version,
            'source': new_snapshot.source,
            'snapshot_time': new_snapshot.snapshot_time.isoformat(),
            'finding_count': new_snapshot.finding_count,
            "previous_snapshot_id": existing_snapshot.snapshot_id if existing_snapshot else None,
            "summary": {
                "new": new_snapshot.new,
                "resolved": new_snapshot.resolved,
                "severity_changed": new_snapshot.severity_changed,
                "status_changed": new_snapshot.status_changed,
                "unchanged": new_snapshot.unchanged
            }
        }   

        print(f"Snapshot and findings updated successfully, returning response: {response}")
        return response

    except ValidationError:
        db.session.rollback()
        raise

    except ConflictError:
        db.session.rollback()
        raise

    except IntegrityError:
        db.session.rollback()
        raise ConflictError("Duplicate snapshot or constraint violation")

    except Exception:
        db.session.rollback()
        raise


def validate_snapshot_data(data):
    print(f"Validating snapshot data")
    required_fields = ['product_name', 'product_version', 'source', 'snapshot_time', 'findings']
    for field in required_fields:
        if field not in data or data[field] is None or data[field] == "":
            print(f"Validation error: Missing required field: {field}")
            return False, get_error_response_400("Invalid snapshot data", 
                                                        "Vulnerability Snapshot Change Monitor",
                                                        field=field,
                                                        field_message=f"Missing required field in snapshot: {field}")

    if not isinstance(data['findings'], list) or len(data['findings']) == 0:
        print("Validation error: Findings must be a non-empty list")
        return False, get_error_response_400("Invalid snapshot data", 
                                                    "Vulnerability Snapshot Change Monitor",
                                                    field="findings",
                                                    field_message="Findings must be a non-empty list")

    validate_snapshot_time_result = validate_snapshot_time(data['snapshot_time'])
    if not validate_snapshot_time_result:
        print(f"Validation error: Invalid snapshot_time format: {data['snapshot_time']}")
        return False, get_error_response_400("Invalid snapshot data", 
                                                    "Vulnerability Snapshot Change Monitor",
                                                    field="snapshot_time",
                                                    field_message="Invalid snapshot_time format, should be in ISO 8601 format, example: 2023-01-01T00:00:00Z")
    
    for finding in data['findings']:
        valid, error = validate_finding_data(finding)
        if not valid:
            print(f"Validation error in finding data: {error}")
            return False, error

    # check for duplicates inside findings data, if same vulnerability_id, component_name and component_version exists more than once then reject with 400 Bad Request
    seen_findings = set()
    for finding in data['findings']:
        finding_key = (finding['vulnerability_id'].strip(), finding['component_name'].strip(), finding['component_version'].strip())
        if finding_key in seen_findings:
            return False, get_error_response_400(
                "Invalid snapshot data",
                "Vulnerability Snapshot Change Monitor",
                field="findings",
                field_message=f"Duplicate finding found in request data for vulnerability_id: {finding['vulnerability_id'].strip()}, component_name: {finding['component_name'].strip()} and component_version: {finding['component_version'].strip()}"
            )
        seen_findings.add(finding_key)

    return True, None

def update_snapshot(data):   
    existing_snapshot = get_existing_snapshot(data)
    print(f"Existing snapshot found: {existing_snapshot.snapshot_id if existing_snapshot else 'None'} for product: {data['product_name']}, version: {data['product_version']} and source: {data['source']}")
    
    # If an existing snapshot is found, compare the snapshot_time, If duplicate reject with 409 Conflict
    snapshot_time = datetime.strptime(data['snapshot_time'], '%Y-%m-%dT%H:%M:%SZ')
    if existing_snapshot and existing_snapshot.snapshot_time >= snapshot_time:
        print(f"Duplicate snapshot found with snapshot_id: {existing_snapshot.snapshot_id} having snapshot_time: {existing_snapshot.snapshot_time} which is newer or equal to the incoming snapshot_time: {data['snapshot_time']}")
        if existing_snapshot.snapshot_time == snapshot_time:
            raise ConflictError(
                "A snapshot with same product/version/source and snapshot_time exists"
            )
        else:
            raise ConflictError(
                "A newer snapshot with same product/version/source with latest snapshot_time exists"
        )

    print(f"Creating new snapshot for product: {data['product_name']}, version: {data['product_version']} and source: {data['source']} with snapshot_time: {data['snapshot_time']}")
    
    # Create new snapshot and findings
    snapshot_id = generate_uniqueid()
    product_name = data['product_name'].strip()
    product_version = data['product_version'].strip()
    source = data['source'].strip()
    print(f"Parsed snapshot_time: {data['snapshot_time']} into datetime object")
    print(f"Generated snapshot_id: {snapshot_id} for new snapshot")
    
    # Add new snapshot to the database, But update counts after processing findings
    new_snapshot = Snapshots(
        snapshot_id=snapshot_id,
        product_name=product_name,
        product_version=product_version,
        source=source,
        snapshot_time=snapshot_time,
        new=0,
        resolved=0,
        severity_changed=0,
        status_changed=0,
        unchanged=0,
        previous_snapshot_id=existing_snapshot.snapshot_id if existing_snapshot else None
    )
    print(f"Adding new snapshot to the database with snapshot_id: {snapshot_id}")
    db.session.add(new_snapshot)
    db.session.flush()
    
    return new_snapshot, existing_snapshot

def add_new_finding(new_snapshot, finding_data):
    print(f"Adding new finding for snapshot_id: {new_snapshot.snapshot_id} with vulnerability_id: {finding_data['vulnerability_id'].strip()}, component_name: {finding_data['component_name'].strip()} and component_version: {finding_data['component_version'].strip()}")
    new_finding = Findings(
        finding_id=generate_uniqueid(),
        snapshot_id=new_snapshot.snapshot_id,
        vulnerability_id=finding_data['vulnerability_id'].strip(),
        component_name=finding_data['component_name'].strip(),
        component_version=finding_data['component_version'].strip(),
        package_url=finding_data['package_url'] if 'package_url' in finding_data else None,
        severity=finding_data['severity'] if 'severity' in finding_data else None,
        cvss_score=finding_data['cvss_score'] if 'cvss_score' in finding_data else None,
        affected_status=finding_data['affected_status'] if 'affected_status' in finding_data else None
    )
    print(f"Adding new finding to the database for snapshot_id: {new_snapshot.snapshot_id} with vulnerability_id: {finding_data['vulnerability_id'].strip()}, component_name: {finding_data['component_name'].strip()} and component_version: {finding_data['component_version'].strip()}")
    db.session.add(new_finding)
    db.session.flush()

def add_snapshot_change(new_snapshot, existing_finding, finding_data, change_type):
    snapshot_change = SnapshotChanges(
        snapshot_id=new_snapshot.snapshot_id if new_snapshot else None,
        previous_snapshot_id=new_snapshot.previous_snapshot_id if new_snapshot else None,
        change_type=change_type,
        vulnerability_id=finding_data['vulnerability_id'].strip() if finding_data and 'vulnerability_id' in finding_data else existing_finding.vulnerability_id.strip() if existing_finding else None,
        component_name=finding_data['component_name'].strip() if finding_data and 'component_name' in finding_data else existing_finding.component_name.strip() if existing_finding else None,
        component_version=finding_data['component_version'].strip() if finding_data and 'component_version' in finding_data else existing_finding.component_version.strip() if existing_finding else None,
        package_url=finding_data['package_url'].strip() if finding_data and 'package_url' in finding_data else existing_finding.package_url.strip() if existing_finding else None,
        previous_severity=existing_finding.severity if existing_finding else None,
        current_severity=finding_data.get('severity') if finding_data else None,
        previous_cvss_score=existing_finding.cvss_score if existing_finding else None,
        current_cvss_score=finding_data.get('cvss_score') if finding_data else None,
        previous_affected_status=existing_finding.affected_status if existing_finding else None,
        current_affected_status=finding_data.get('affected_status') if finding_data else None
    )
    db.session.add(snapshot_change)
    db.session.flush()

def get_resolved_findings_count(new_snapshot, existing_snapshot, findings_data):
    existing_findings = Findings.query.filter_by(snapshot_id=existing_snapshot.snapshot_id).all()
    resolved_count = 0
    for existing_finding in existing_findings:
        match_found = False
        # check each existing in finding_data, if not exists resolved count to be increased, if exists check if severity or status changed, if not changed then unchanged count to be increased
        for finding_data in findings_data:
            if existing_finding.vulnerability_id == finding_data['vulnerability_id'].strip() and existing_finding.component_name == finding_data['component_name'].strip() and existing_finding.component_version == finding_data['component_version'].strip():
                match_found = True
                break
    
        if not match_found:
            resolved_count += 1
            add_snapshot_change(new_snapshot, existing_finding, None, 'resolved')
    return resolved_count

# Update findings table and findings counts in snapshots table based on comparison with existing snapshot
def update_findings(new_snapshot, existing_snapshot, findings_data):
    if existing_snapshot:
        print(f"Comparing findings with existing snapshot_id: {existing_snapshot.snapshot_id} for new snapshot_id: {new_snapshot.snapshot_id}")
        for finding_data in findings_data:
            existing_finding = get_existing_findings(finding_data, existing_snapshot.snapshot_id)
            if existing_finding:
                if existing_finding.severity != finding_data.get('severity'):
                    new_snapshot.severity_changed += 1
                    add_snapshot_change(new_snapshot, existing_finding, finding_data, 'severity_changed')
                if existing_finding.affected_status != finding_data.get('affected_status'):
                    new_snapshot.status_changed += 1
                    add_snapshot_change(new_snapshot, existing_finding, finding_data, 'status_changed')
                if existing_finding.severity == finding_data.get('severity') and existing_finding.affected_status == finding_data.get('affected_status'):
                    new_snapshot.unchanged += 1

            else:
                new_snapshot.new += 1
                add_snapshot_change(new_snapshot, existing_finding, finding_data, 'new')
            new_snapshot.finding_count += 1
            add_new_finding(new_snapshot, finding_data)
        
        new_snapshot.resolved = get_resolved_findings_count(new_snapshot, existing_snapshot, findings_data)
    else:
        print(f"No existing snapshot found, adding all findings as new for snapshot_id: {new_snapshot.snapshot_id}")
        for finding_data in findings_data:
            add_new_finding(new_snapshot, finding_data)
            new_snapshot.new += 1
            new_snapshot.finding_count += 1
            add_snapshot_change(new_snapshot, None, finding_data, 'new')
    print(f"Updating snapshot counts for snapshot_id: {new_snapshot.snapshot_id} with new: {new_snapshot.new}, resolved: {new_snapshot.resolved}, severity_changed: {new_snapshot.severity_changed}, status_changed: {new_snapshot.status_changed} and unchanged: {new_snapshot.unchanged}")
    db.session.flush()

def generate_uniqueid():
    return int(time.time() * 1000) + uuid.uuid4().int % 1000

def get_existing_snapshot(data):
    existing_snapshot = Snapshots.query.filter_by(
        product_name=data['product_name'].strip(),
        product_version=data['product_version'].strip(),
        source=data['source'].strip()).order_by(Snapshots.snapshot_time.desc()).first()
    return existing_snapshot

def get_existing_findings(findings_data, snapshot_id):
    existing_findings = Findings.query.filter_by(
        snapshot_id = snapshot_id,
        vulnerability_id = findings_data['vulnerability_id'].strip(),
        component_name = findings_data['component_name'].strip(),
        component_version = findings_data['component_version'].strip()).first()
    return existing_findings


def get_snapshot_changes(snapshot_id, limit, offset, changetype=None, severity=None, component_name=None):
    try:
        query = SnapshotChanges.query.filter_by(snapshot_id=snapshot_id)
        
        if changetype and changetype not in allowed_change_types:
            raise ValidationError(f"Invalid change_type value. Allowed values are: {allowed_change_types}")
        elif changetype is not None:
            query = query.filter_by(change_type=changetype)

        if severity and severity not in allowed_severity:
            raise ValidationError(f"Invalid severity value. Allowed values are: {allowed_severity}")
        elif severity is not None:
            query = query.filter_by(current_severity=severity)

        if component_name is not None and component_name != "":
            query = query.filter_by(component_name=component_name)

        changes = query.limit(limit).offset(offset).all()
        if not changes:
            raise NotFoundError("Snapshot changes not found")
        response = []
        for change in changes:
            response.append({
                'change_type': change.change_type,
                'vulnerability_id': change.vulnerability_id,
                'component_name': change.component_name,
                'component_version': change.component_version,
                'package_url': change.package_url,
                'previous':
                {
                    'severity': change.previous_severity,
                    'cvss_score': change.previous_cvss_score,
                    'affected_status': change.previous_affected_status
                } if change.change_type not in {'new'} else None,
                'current':
                {
                    'severity': change.current_severity,
                    'cvss_score': change.current_cvss_score,
                    'affected_status': change.current_affected_status
                } if change.change_type not in {'resolved'} else None,
                })
        return  {'changes': response}
        
    except SQLAlchemyError:
        raise DatabaseError("Database error occurred")

    except Exception:
        raise

def get_snapshot(snapshot_id):
    try:
        snapshot = Snapshots.query.filter_by(snapshot_id=snapshot_id).first()
        if not snapshot:
            raise NotFoundError("Snapshot not found")
        response = {
            'snapshot_id': snapshot.snapshot_id,
            'product_name': snapshot.product_name,
            'product_version': snapshot.product_version,
            'source': snapshot.source,
            'snapshot_time': snapshot.snapshot_time.isoformat(),
            'finding_count': snapshot.finding_count,
            "previous_snapshot_id": snapshot.previous_snapshot_id,
            "summary": {
                "new": snapshot.new,
                "resolved": snapshot.resolved,
                "severity_changed": snapshot.severity_changed,
                "status_changed": snapshot.status_changed,
                "unchanged": snapshot.unchanged
            },
        }
        return response

    except SQLAlchemyError:
        raise DatabaseError("Database error occurred")

    except Exception:
        raise


def get_snapshots(product_name, product_version, limit, offset):
    try:
        snapshots = Snapshots.query.filter_by(product_name=product_name, product_version=product_version).order_by(Snapshots.snapshot_time.desc()).limit(limit).offset(offset).all()
        response = []
        for snapshot in snapshots:
            response.append({
                'snapshot_id': snapshot.snapshot_id,
                'snapshot_time': snapshot.snapshot_time.isoformat(),
                'source': snapshot.source,
                'finding_count': snapshot.finding_count,
                'created_at': snapshot.created_at.isoformat() if snapshot.created_at else None
            })
        
        return {"items":response, 'offset':offset, 'limit':limit}

    except SQLAlchemyError:
        raise DatabaseError("Database error occurred")

    except Exception:
        raise


def validate_finding_data(finding):
    required_fields = ['vulnerability_id', 'component_name', 'component_version', 'severity', 'affected_status']

    # Check Mandatory fields
    for field in required_fields:
        if field not in finding or finding[field] is None or finding[field] == "":
            print(f"Validation error: Missing required field in finding: {field}")
            return False, get_error_response_400("Invalid snapshot payload", 
                                                        "Vulnerability Snapshot Change Monitor",
                                                        field=field,
                                                        field_message=f"Missing required field in finding: {field}")
    # Check values in fields 
    for field in finding:
        # Severity check
        if field == "severity" and finding[field] not in allowed_severity:
            print(f"Validation error: Invalid severity value in finding: {finding[field]}")
            return False, get_error_response_400("Invalid snapshot payload", 
                                                        "Vulnerability Snapshot Change Monitor",
                                                        field=field,
                                                        field_message=f"Severity value should be: {', '.join(allowed_severity)}")
        
        # CVSS score check
        if field == "cvss_score" and not validate_finding_cvss_score(finding[field]):
            print(f"Validation error: Invalid CVSS score in finding: {finding[field]}")
            return False, get_error_response_400("Invalid snapshot payload", 
                                                "Vulnerability Snapshot Change Monitor",
                                                field=field,
                                                field_message=f"CVSS score should be in range: {allowed_cvss_score_range[0]} ~ {allowed_cvss_score_range[1]}")
        
        # Affected status check
        if field == "affected_status" and finding[field] not in allowed_affected_status:
            print(f"Validation error: Invalid affected status in finding: {finding[field]}")
            return False, get_error_response_400("Invalid snapshot payload", 
                                                "Vulnerability Snapshot Change Monitor",
                                                field=field,
                                                field_message=f"Affected status value should be in: {', '.join(allowed_affected_status)}")
    return True, None

def validate_finding_cvss_score(cvss_score):
    try:
        score = float(cvss_score)
        return allowed_cvss_score_range[0] <= score <= allowed_cvss_score_range[1]
    except (ValueError, TypeError) as e:
        print(f"CVSS score validation error: {e}")
        return False


def validate_snapshot_time(snapshot_time):
    try:
        datetime.strptime(snapshot_time, '%Y-%m-%dT%H:%M:%SZ')
        return True
    except ValueError as e:
        print(f"Snapshot time validation error: {e}")
        return False
    
# Form only string as above structure for error response, if field is not applicable then return only code, message and details without field
def get_error_response_400(message, details="Bad Request", field=None, field_message=None):
    
    error_details = details if isinstance(details, list) else [details]

    if field and field_message:
        error_details.append({
            "field": field, 
            "message": field_message
        })

    error_response = {
        "code": "validation_error",
        "message": message,
        "details": error_details
    }
    return error_response

class ValidationError(Exception):
    def __init__(self, error_body):
        self.error_body = error_body

class ConflictError(Exception):
    pass

class NotFoundError(Exception):
    pass


class DatabaseError(Exception):
    pass

