import os
from flask import Flask
from model import db
from routes import bp

app = Flask(__name__)
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', 5432)
DB_NAME = os.getenv('DB_NAME', 'mydb')
DB_USER = os.getenv('DB_USER', 'myuser')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'mypassword')
PORT = os.getenv('PORT', 8080)

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?sslmode=disable'
app.json.sort_keys = False
app.register_blueprint(bp)

def db_init():
    try:
        with app.app_context():
            db.init_app(app)
            db.create_all()
    except Exception as e:
        print(f"Error initializing database: {e}")


@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == '__main__':
    db_init()
    app.run(host='0.0.0.0', port=PORT, debug=True, threaded=True)