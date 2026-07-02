from functools import wraps
from datetime import date
from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from ..models import User, Candidate, Job, Todo
from .. import db

bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if current_user.role != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


@bp.route("/dashboard")
@admin_required
def dashboard():
    todos_today = Todo.query.filter(
        Todo.due_date == date.today()
    ).order_by(Todo.scheduled_time).all()
    todos_pending = Todo.query.filter(
        Todo.status == "pending"
    ).order_by(Todo.priority.desc()).all()
    stats = {
        "total": Todo.query.count(),
        "pending": Todo.query.filter_by(status="pending").count(),
        "today": len(todos_today),
        "blocked_ips": 0,
    }
    return render_template("dashboard.html", todos=todos_today, pending=todos_pending, stats=stats)


@bp.route("/users")
@login_required
def list_users():
    users = User.query.all()
    return jsonify([{
        "id": u.id, "name": u.name,
        "email": u.email, "role": u.role,
        "verified": u.is_verified,
    } for u in users])


@bp.route("/candidates")
@login_required
def list_candidates():
    candidates = Candidate.query.all()
    return jsonify([{
        "id": c.id, "name": c.name,
        "email": c.email, "status": c.status,
    } for c in candidates])


@bp.route("/jobs")
@login_required
def list_jobs():
    jobs = Job.query.all()
    return jsonify([{
        "id": j.id, "title": j.title,
        "department": j.department,
        "status": j.status,
    } for j in jobs])


def _todo_json(t):
    return {
        "id": t.id,
        "title": t.title,
        "description": t.description,
        "status": t.status,
        "priority": t.priority,
        "scheduled_time": t.scheduled_time,
        "due_date": t.due_date.isoformat() if t.due_date else None,
        "reminder_sent": t.reminder_sent,
        "assigned_to": t.assigned_to,
        "assignee_name": t.assignee.name if t.assignee else None,
        "created_by": t.created_by,
        "creator_name": t.creator.name if t.creator else None,
        "created_at": t.created_at.isoformat(),
        "updated_at": t.updated_at.isoformat(),
    }


@bp.route("/todos", methods=["GET"])
@admin_required
def list_todos():
    todos = Todo.query.order_by(Todo.created_at.desc()).all()
    return jsonify([_todo_json(t) for t in todos])


@bp.route("/todos/today", methods=["GET"])
@admin_required
def todos_today():
    todos = Todo.query.filter(
        Todo.due_date == date.today()
    ).order_by(Todo.scheduled_time).all()
    return jsonify([_todo_json(t) for t in todos])


@bp.route("/todos", methods=["POST"])
@admin_required
def create_todo():
    data = request.get_json()
    if not data or not data.get("title"):
        return jsonify({"error": "Title is required"}), 400

    due = None
    if data.get("due_date"):
        try:
            due = date.fromisoformat(data["due_date"])
        except (ValueError, TypeError):
            pass

    todo = Todo(
        title=data["title"],
        description=data.get("description", ""),
        status=data.get("status", "pending"),
        priority=data.get("priority", "medium"),
        scheduled_time=data.get("scheduled_time", ""),
        due_date=due,
        assigned_to=data.get("assigned_to"),
        created_by=current_user.id,
    )
    db.session.add(todo)
    db.session.commit()
    return jsonify({"message": "Todo created", "id": todo.id}), 201


@bp.route("/todos/<int:todo_id>", methods=["PUT"])
@admin_required
def update_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    data = request.get_json()

    for field in ("title", "description", "status", "priority",
                   "scheduled_time", "assigned_to", "reminder_sent"):
        if field in data:
            setattr(todo, field, data[field])

    if "due_date" in data:
        try:
            todo.due_date = date.fromisoformat(data["due_date"]) if data["due_date"] else None
        except (ValueError, TypeError):
            pass

    db.session.commit()
    return jsonify({"message": "Todo updated"})


@bp.route("/todos/<int:todo_id>", methods=["DELETE"])
@admin_required
def delete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    db.session.delete(todo)
    db.session.commit()
    return jsonify({"message": "Todo deleted"})
