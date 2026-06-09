# Need to update

curl -i -X POST http://localhost:8080/snapshots -H "Content-Type: application/json" -d @snapshot-day-1.json

curl -i -X GET http://localhost:8080/products/ExampleDevice4/versions/1.2.3/snapshots?limit=3&offset=1

curl -i -X GET http://localhost:8080/snapshots/1780036118074/changes

curl -X GET "http://localhost:8080/snapshots/123/changes?change_type=UPDATED&severity=CRITICAL&component_name=engine"

python3 -m pytest -s
python3 app.py 
psql -h localhost -U myuser -d mydb //mypassword

PYTHONPATH=. pytest --cov=. --cov-report=html

PYTHONPATH=. pytest Test/test_service.py::test_validate_snapshot_data