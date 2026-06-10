from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
import uuid

db = SQLAlchemy(session_options={"expire_on_commit": True})
class Snapshots(db.Model):
    __tablename__ = 'snapshots'
    snapshot_id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    product_name = db.Column(db.String(80), nullable=False)
    product_version = db.Column(db.String(80), nullable=False)
    source = db.Column(db.String(80), nullable=False)
    snapshot_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    previous_snapshot_id = db.Column(UUID(as_uuid=True), nullable=True)
    finding_count = db.Column(db.Integer, nullable=False, default=0)
    new = db.Column(db.Integer, nullable=False, default=0)
    resolved = db.Column(db.Integer, nullable=False, default=0)
    severity_changed = db.Column(db.Integer, nullable=False, default=0)
    status_changed = db.Column(db.Integer, nullable=False, default=0)
    unchanged = db.Column(db.Integer, nullable=False, default=0)
    __table_args__ = (
        db.UniqueConstraint(
            'product_name', 'product_version',  'source', 'snapshot_time', name='unique_snapshot'
        ),
    )


class Findings(db.Model):
    __tablename__ = 'findings'
    finding_id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    snapshot_id = db.Column(UUID(as_uuid=True), db.ForeignKey('snapshots.snapshot_id'), nullable=False)
    vulnerability_id = db.Column(db.String(80), nullable=False)
    component_name = db.Column(db.String(80), nullable=False)
    component_version = db.Column(db.String(80), nullable=False)
    package_url = db.Column(db.String(200), nullable=True)
    severity = db.Column(db.Enum('critical', 'high', 'medium', 'low', 'none', 'unknown', name='severity_enum'), nullable=False)
    cvss_score = db.Column(db.Float, nullable=True)
    affected_status = db.Column(db.Enum('affected', 'not_affected', 'fixed', 'under_investigation', 'accepted_risk', name='affected_status_enum'), nullable=False)
    __table_args__ = (
        db.CheckConstraint('cvss_score >= 0.0 AND cvss_score <= 10.0', name='cvss_score_range'),
        db.UniqueConstraint('snapshot_id', 'vulnerability_id', 'component_name', 'component_version', name='unique_finding'),
    )

class SnapshotChanges(db.Model):
    __tablename__ = 'snapshot_changes'
    change_id = db.Column(db.BigInteger, primary_key=True)
    snapshot_id = db.Column(UUID(as_uuid=True), db.ForeignKey('snapshots.snapshot_id'), nullable=False)
    previous_snapshot_id = db.Column(UUID(as_uuid=True), nullable=True)
    change_type = db.Column(db.Enum('new', 'resolved', 'severity_changed', 'status_changed', name='change_type_enum'), nullable=False)
    vulnerability_id = db.Column(db.String(80), nullable=True)
    component_name = db.Column(db.String(80), nullable=True)
    component_version = db.Column(db.String(80), nullable=True)
    package_url = db.Column(db.String(200), nullable=True)
    previous_severity = db.Column(db.Enum('critical', 'high', 'medium', 'low', 'none', 'unknown', name='severity_enum'), nullable=True)
    current_severity = db.Column(db.Enum('critical', 'high', 'medium', 'low', 'none', 'unknown', name='severity_enum'), nullable=True)
    previous_cvss_score = db.Column(db.Float, nullable=True)
    current_cvss_score = db.Column(db.Float, nullable=True)
    previous_affected_status = db.Column(db.Enum('affected', 'not_affected', 'fixed', 'under_investigation', 'accepted_risk', name='affected_status_enum'), nullable=True)
    current_affected_status = db.Column(db.Enum('affected', 'not_affected', 'fixed', 'under_investigation', 'accepted_risk', name='affected_status_enum'), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
