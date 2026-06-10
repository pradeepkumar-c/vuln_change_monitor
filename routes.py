from sqlalchemy import text

from flask import app, request, jsonify, json, Blueprint
from werkzeug.exceptions import BadRequest
from service import create_snapshot, get_snapshots, get_snapshot, get_snapshot_changes, ConflictError, NotFoundError, ValidationError, DatabaseError
from model import db


bp = Blueprint("snapshots", __name__)

@bp.route('/snapshots', methods=['POST'])
def create_snapshot_endpoint():
    try:
        data = request.get_json()
        
        print(f"Received snapshot data: {json.dumps(data)}")
        response  = create_snapshot(data)
        return jsonify(response), 201
    
    except BadRequest as e:
        print(f"Bad request error: {str(e)}")
        return jsonify({'error': 'Malformed JSON syntax encountered'}), 400
    
    except ValidationError as e:
        return jsonify(e.error_body), 400

    except ConflictError as e:
        return jsonify({"error": str(e)}), 409

    except NotFoundError as e:
        return jsonify({"error": str(e)}), 404

    except Exception:
        return jsonify({"error": "Internal server error"}), 500

    
# GET /products/{product_name}/versions/{product_version}/snapshots
@bp.route('/products/<product_name>/versions/<product_version>/snapshots', methods=['GET'])
def get_snapshots_endpoint(product_name, product_version):

    try:  
        #Need to apply pagination here, limit and offset can be passed as query parameters, default limit to 10 and offset to 0
        limit = request.args.get('limit', 10, type=int)
        offset = request.args.get('offset', 0, type=int)
        response = get_snapshots(product_name.strip(), product_version.strip(), limit, offset)
        return jsonify(response), 200
    
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    except NotFoundError as e:
        return jsonify({"error": str(e)}), 404

    except DatabaseError:
        return jsonify({"error": "Internal server error"}), 500

    except Exception:
        return jsonify({"error": "Unexpected server error"}), 500

# GET /snapshots/{snapshot_id}
@bp.route('/snapshots/<string:snapshot_id>', methods=['GET'])
def get_snapshot_endpoint(snapshot_id):
    print(f"Received request for snapshot_id: {snapshot_id}")
    try:
        response = get_snapshot(snapshot_id)
        return jsonify(response), 200

    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    except NotFoundError as e:
        return jsonify({"error": str(e)}), 404

    except DatabaseError:
        return jsonify({"error": "Internal server error"}), 500

    except Exception:
        return jsonify({"error": "Unexpected server error"}), 500

# GET /snapshots/{snapshot_id}/changes
@bp.route('/snapshots/<string:snapshot_id>/changes', methods=['GET'])
def get_snapshot_changes_endpoint(snapshot_id):
    try:
        limit = request.args.get('limit', 10, type=int)
        offset = request.args.get('offset', 0, type=int)
        changetype = request.args.get('change_type', None, type=str)
        if changetype == "":
            changetype = None

        severity = request.args.get('severity', None, type=str)
        if severity == "":
            severity = None

        component_name = request.args.get('component_name', None, type=str)
        if component_name == "":
            component_name = None
        
        response = get_snapshot_changes(snapshot_id, limit, offset, changetype, severity, component_name)
        return jsonify(response), 200
    
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    except NotFoundError as e:
        return jsonify({"error": str(e)}), 404

    except DatabaseError:
        return jsonify({"error": "Internal server error"}), 500

    except Exception:
        return jsonify({"error": "Unexpected server error"}), 500



@bp.route("/health", methods=["GET"])
def health_endpoint():
    try:
        db.session.execute(text("SELECT 1"))
        return {"status": "ok", "database": "ok"}, 200
    except Exception:
        return {"status": "down", "database": "down"}, 500

