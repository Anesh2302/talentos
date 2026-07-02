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
    application.config["WTF_CSRF_ENABLED"] = False
    with application.app_context():
        db.drop_all()
        db.create_all()
        user = User(
            email="admin@test.com",
            name="Admin",
            role="admin",
            is_verified=True,
        )
        user.set_password("admin123")
        db.session.add(user)
        db.session.commit()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def login_admin(client):
    client.post("/auth/login", json={
        "email": "admin@test.com",
        "password": "admin123",
    })


def test_create_todo(client):
    login_admin(client)
    resp = client.post("/admin/todos", json={
        "title": "Fix security bug",
        "priority": "high",
        "description": "SQL injection in login",
    })
    assert resp.status_code == 201


def test_list_todos(client):
    login_admin(client)
    client.post("/admin/todos", json={"title": "Task 1"})
    client.post("/admin/todos", json={"title": "Task 2"})
    resp = client.get("/admin/todos")
    assert resp.status_code == 200


def test_update_todo(client):
    login_admin(client)
    resp = client.post("/admin/todos", json={"title": "Task 1"})
    todo_id = resp.get_json()["id"]
    resp = client.put(f"/admin/todos/{todo_id}", json={
        "status": "completed",
        "priority": "low",
    })
    assert resp.status_code == 200


def test_delete_todo(client):
    login_admin(client)
    resp = client.post("/admin/todos", json={"title": "Task 1"})
    todo_id = resp.get_json()["id"]
    resp = client.delete(f"/admin/todos/{todo_id}")
    assert resp.status_code == 200


def test_non_admin_cannot_access(client):
    resp = client.post("/admin/todos", json={"title": "Hack"})
    assert resp.status_code in (302, 401, 403)
