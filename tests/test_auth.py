import unittest.mock
import pytest
from talentos import create_app, db
from talentos.models import User


@pytest.fixture(autouse=True)
def no_email():
    import talentos.otp as otp_mod
    with unittest.mock.patch.object(otp_mod.mail, "send"):
        yield


@pytest.fixture
def app():
    application = create_app()
    application.config["TESTING"] = True
    application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    application.config["SERVER_NAME"] = "localhost"
    with application.app_context():
        db.drop_all()
        db.create_all()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


def test_register(app, client):
    with app.app_context():
        resp = client.post("/auth/register", json={
            "email": "test@test.com",
            "password": "secret123",
            "name": "Test User",
        })
        assert resp.status_code in (201, 200)


def test_login_unverified(app, client):
    with app.app_context():
        client.post("/auth/register", json={
            "email": "test@test.com",
            "password": "secret123",
            "name": "Test User",
        })
        resp = client.post("/auth/login", json={
            "email": "test@test.com",
            "password": "secret123",
        })
        assert resp.status_code in (403, 401)


def test_profile_requires_auth(client):
    resp = client.get("/profile")
    assert resp.status_code in (302, 401)
