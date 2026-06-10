from datetime import datetime

allowed_severity = ['critical', 'high', 'medium', 'low', 'none', 'unknown']
allowed_affected_status = ['affected', 'not_affected', 'fixed', 'under_investigation', 'accepted_risk']
allowed_change_types = ['new', 'resolved', 'severity_changed', 'status_changed']
allowed_cvss_score_range = (0.0, 10.0)

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
        finding_key = (finding['vulnerability_id'], finding['component_name'], finding['component_version'])
        if finding_key in seen_findings:
            return False, get_error_response_400(
                "Invalid snapshot data",
                "Vulnerability Snapshot Change Monitor",
                field="findings",
                field_message=f"Duplicate finding found in request data for vulnerability_id: {finding['vulnerability_id']}, component_name: {finding['component_name']} and component_version: {finding['component_version']}"
            )
        seen_findings.add(finding_key)

    return True, None
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
