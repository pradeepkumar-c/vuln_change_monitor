import pytest
from testcontainers.postgres import PostgresContainer
from app import app, db


@pytest.fixture(scope="session")
def postgres_container():
    with PostgresContainer("postgres:15") as postgres:
        yield postgres


@pytest.fixture(scope="session")
def test_app(postgres_container):
    # Configure app to use container DB
    app.config["SQLALCHEMY_DATABASE_URI"] = postgres_container.get_connection_url()
    app.config["TESTING"] = True

    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(test_app):
    return test_app.test_client()

@pytest.fixture(scope="session")
def test_app(postgres_container):

    app.config["SQLALCHEMY_DATABASE_URI"] = postgres_container.get_connection_url()
    app.config["TESTING"] = True

    with app.app_context():
        db.init_app(app)
        db.create_all()

        yield app

        db.session.remove()
        db.drop_all()