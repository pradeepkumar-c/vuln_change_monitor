from flask_sqlalchemy import SQLAlchemy
from model import db, Snapshots, Findings, SnapshotChanges
import time
import uuid
from datetime import datetime
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from validator import validate_snapshot_data 
from validator import allowed_severity, allowed_affected_status, allowed_cvss_score_range, allowed_change_types

def create_snapshot(data):
    try:
        print(f"Received snapshot data: {data}")
        valid, error = validate_snapshot_data(data)
        print(f"Snapshot data validation result: {valid}, {error}")
        if not valid:
            raise ValidationError(error)
        
        print(f"Snapshot data validated successfully, proceeding to update snapshot and findings")
        data = normalize_snapshot_input(data)
        print(f"Snapshot data normalized successfully: {data}")
        
        new_snapshot, existing_snapshot = update_snapshot(data)
        print(f"Snapshot update result: {new_snapshot}, {existing_snapshot}")

        print(f"Snapshot updated successfully, proceeding to update findings")
        update_findings(new_snapshot, existing_snapshot, data['findings'])
        
        db.session.commit()
        db.session.flush()

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

def normalize_snapshot_input(data):
    normalized_data = data.copy()
    if 'product_name' in normalized_data and isinstance(normalized_data['product_name'], str):
        normalized_data['product_name'] = normalized_data['product_name'].strip()
    if 'product_version' in normalized_data and isinstance(normalized_data['product_version'], str):
        normalized_data['product_version'] = normalized_data['product_version'].strip()
    if 'source' in normalized_data and isinstance(normalized_data['source'], str):
        normalized_data['source'] = normalized_data['source'].strip()

    normalized_data['findings'] = [
        normalize_finding_input(finding)
        for finding in normalized_data.get('findings', [])
    ]

    return normalized_data

def normalize_finding_input(finding):
    normalized_finding = finding.copy()
    if 'vulnerability_id' in normalized_finding and isinstance(normalized_finding['vulnerability_id'], str):
        normalized_finding['vulnerability_id'] = normalized_finding['vulnerability_id'].strip()
    if 'component_name' in normalized_finding and isinstance(normalized_finding['component_name'], str):
        normalized_finding['component_name'] = normalized_finding['component_name'].strip()
    if 'component_version' in normalized_finding and isinstance(normalized_finding['component_version'], str):
        normalized_finding['component_version'] = normalized_finding['component_version'].strip()
    return normalized_finding

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
    product_name = data['product_name']
    product_version = data['product_version']
    source = data['source']
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
    print(f"Adding new finding for snapshot_id: {new_snapshot.snapshot_id} with vulnerability_id: {finding_data['vulnerability_id']}, component_name: {finding_data['component_name']} and component_version: {finding_data['component_version']}")
    new_finding = Findings(
        finding_id=generate_uniqueid(),
        snapshot_id=new_snapshot.snapshot_id,
        vulnerability_id=finding_data['vulnerability_id'],
        component_name=finding_data['component_name'],
        component_version=finding_data['component_version'],
        package_url=finding_data['package_url'] if 'package_url' in finding_data else None,
        severity=finding_data['severity'] if 'severity' in finding_data else None,
        cvss_score=finding_data['cvss_score'] if 'cvss_score' in finding_data else None,
        affected_status=finding_data['affected_status'] if 'affected_status' in finding_data else None
    )
    print(f"Adding new finding to the database for snapshot_id: {new_snapshot.snapshot_id} with vulnerability_id: {finding_data['vulnerability_id']}, component_name: {finding_data['component_name']} and component_version: {finding_data['component_version']}")
    db.session.add(new_finding)

def add_snapshot_change(new_snapshot, previous, current, change_type):
    def _get(src, name):
        if src is None:
            return None
        if isinstance(src, dict):
            return src.get(name)
        return getattr(src, name, None)

    snapshot_change = SnapshotChanges(
        snapshot_id=new_snapshot.snapshot_id if new_snapshot else None,
        previous_snapshot_id=new_snapshot.previous_snapshot_id if new_snapshot else None,
        change_type=change_type,
        vulnerability_id=_get(current, 'vulnerability_id') or _get(previous, 'vulnerability_id'),
        component_name=_get(current, 'component_name') or _get(previous, 'component_name'),
        component_version=_get(current, 'component_version') or _get(previous, 'component_version'),
        package_url=_get(current, 'package_url') or _get(previous, 'package_url'),
        previous_severity=_get(previous, 'severity'),
        current_severity=_get(current, 'severity'),
        previous_cvss_score=_get(previous, 'cvss_score'),
        current_cvss_score=_get(current, 'cvss_score'),
        previous_affected_status=_get(previous, 'affected_status'),
        current_affected_status=_get(current, 'affected_status')
    )
    db.session.add(snapshot_change)


def get_existing_findings_by_snapshot(snapshot_id):
    return Findings.query.filter_by(snapshot_id=snapshot_id).all()

def update_findings(new_snapshot, existing_snapshot, findings_data):
    new_map = {
        (f['vulnerability_id'], f['component_name'], f['component_version']): f
        for f in findings_data
    }
    print(f"New findings map created with {len(new_map)} entries for snapshot_id: {new_snapshot.snapshot_id}")

    if existing_snapshot:
        print(f"Comparing with existing snapshot {existing_snapshot.snapshot_id}")

        existing_findings = get_existing_findings_by_snapshot(existing_snapshot.snapshot_id)

        old_map = {
            (f.vulnerability_id, f.component_name, f.component_version): f
            for f in existing_findings
        }
        print(f"Existing findings map created with {len(old_map)} entries for snapshot_id: {existing_snapshot.snapshot_id}")
        # Process NEW + CHANGED + UNCHANGED
        for key, new_fiding in new_map.items():
            old_finding = old_map.get(key)
            print(f"Processing finding with vulnerability_id: {new_fiding['vulnerability_id']}, component_name: {new_fiding['component_name']} and component_version: {new_fiding['component_version']}. Old finding exists: {'Yes' if old_finding else 'No'}")
            if not old_finding:
                # NEW
                new_snapshot.new += 1
                add_snapshot_change(new_snapshot, None, new_fiding, 'new')

            else:
                # Exists → compare fields
                severity_changed = old_finding.severity != new_fiding.get('severity')
                status_changed = old_finding.affected_status != new_fiding.get('affected_status')

                if severity_changed:
                    new_snapshot.severity_changed += 1
                    add_snapshot_change(new_snapshot, old_finding, new_fiding, 'severity_changed')

                if status_changed:
                    new_snapshot.status_changed += 1
                    add_snapshot_change(new_snapshot, old_finding, new_fiding, 'status_changed')

                if not severity_changed and not status_changed:
                    new_snapshot.unchanged += 1

            new_snapshot.finding_count += 1
            add_new_finding(new_snapshot, new_fiding)

        #  Process RESOLVED
        for key, old_finding in old_map.items():
            if key not in new_map:
                new_snapshot.resolved += 1
                add_snapshot_change(new_snapshot, old_finding, None, 'resolved')

    else:
        print(f"No existing snapshot, all findings are NEW")

        for new_fiding in new_map.values():
            new_snapshot.new += 1
            new_snapshot.finding_count += 1

            add_new_finding(new_snapshot, new_fiding)
            add_snapshot_change(new_snapshot, None, new_fiding, 'new')

    print(f"Summary: new={new_snapshot.new}, resolved={new_snapshot.resolved}, "
        f"severity_changed={new_snapshot.severity_changed}, "
        f"status_changed={new_snapshot.status_changed}, unchanged={new_snapshot.unchanged}")

def generate_uniqueid():
    return str(uuid.uuid4())

def get_existing_snapshot(data):
    existing_snapshot = Snapshots.query.filter_by(
        product_name=data['product_name'],
        product_version=data['product_version'],
        source=data['source']).order_by(Snapshots.snapshot_time.desc()).first()
    return existing_snapshot

def get_existing_findings(findings_data, snapshot_id):
    existing_findings = Findings.query.filter_by(
        snapshot_id = snapshot_id,
        vulnerability_id = findings_data['vulnerability_id'],
        component_name = findings_data['component_name'],
        component_version = findings_data['component_version']).first()
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
        print("*************Test Pradeep****************", snapshot_id)
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

class ValidationError(Exception):
    def __init__(self, error_body):
        self.error_body = error_body

class ConflictError(Exception):
    pass

class NotFoundError(Exception):
    pass

class DatabaseError(Exception):
    pass

