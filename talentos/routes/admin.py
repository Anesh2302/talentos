import os
import json as json_mod
from functools import wraps
from datetime import datetime
from flask import Blueprint, jsonify, request, render_template, redirect, url_for
from flask_login import login_required, current_user
from ..models import User, Candidate, Job, Todo, LoginHistory
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
    return redirect(url_for("main.dashboard"))


@bp.route("/security")
@admin_required
def security_dashboard():
    recent_failures = LoginHistory.query.filter_by(success=False)\
        .order_by(LoginHistory.timestamp.desc()).limit(100).all()
    recent_logins = LoginHistory.query.filter_by(success=True)\
        .order_by(LoginHistory.timestamp.desc()).limit(50).all()
    blocked_ips_path = os.path.expanduser("~/.projectpop/blocked_ips.json")
    blocked_ips = []
    if os.path.exists(blocked_ips_path):
        try:
            with open(blocked_ips_path) as f:
                blocked_ips = json_mod.load(f)
        except Exception:
            pass
    return render_template("security.html",
                           failures=recent_failures,
                           logins=recent_logins,
                           blocked_ips=blocked_ips)


@bp.route("/users")
@admin_required
def users_page():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users, active="admin_users")


@bp.route("/users/json")
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
    q = Todo.query

    search = request.args.get("search", "")
    if search:
        q = q.filter(Todo.title.ilike(f"%{search}%"))

    status = request.args.get("status", "")
    if status:
        q = q.filter(Todo.status == status)

    priority = request.args.get("priority", "")
    if priority:
        q = q.filter(Todo.priority == priority)

    assigned = request.args.get("assigned_to", "")
    if assigned:
        q = q.filter(Todo.assigned_to == int(assigned))

    due_from = request.args.get("due_from", "")
    if due_from:
        try:
            q = q.filter(Todo.due_date >= date.fromisoformat(due_from))
        except (ValueError, TypeError):
            pass

    due_to = request.args.get("due_to", "")
    if due_to:
        try:
            q = q.filter(Todo.due_date <= date.fromisoformat(due_to))
        except (ValueError, TypeError):
            pass

    todos = q.order_by(Todo.created_at.desc()).all()
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
    data = request.get_json(force=True, silent=True)
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
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

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


@bp.route("/todos/export")
@admin_required
def export_todos():
    todos = Todo.query.order_by(Todo.created_at.desc()).all()
    si = StringIO()
    w = csv.writer(si)
    w.writerow(["ID", "Title", "Description", "Status", "Priority",
                 "Scheduled Time", "Due Date", "Reminder Sent",
                 "Assigned To", "Created By", "Created At", "Updated At"])
    for t in todos:
        w.writerow([t.id, t.title, t.description, t.status, t.priority,
                     t.scheduled_time, t.due_date, t.reminder_sent,
                     t.assignee.name if t.assignee else "",
                     t.creator.name if t.creator else "",
                     t.created_at, t.updated_at])
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=todos.csv"})


@bp.route("/candidates/export")
@login_required
def export_candidates():
    candidates = Candidate.query.all()
    si = StringIO()
    w = csv.writer(si)
    w.writerow(["ID", "Name", "Email", "Phone", "Status", "Skills", "Notes", "Created"])
    for c in candidates:
        w.writerow([c.id, c.name, c.email, c.phone, c.status, c.skills, c.notes, c.created_at])
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=candidates.csv"})


@bp.route("/jobs/export")
@login_required
def export_jobs():
    jobs = Job.query.all()
    si = StringIO()
    w = csv.writer(si)
    w.writerow(["ID", "Title", "Description", "Department", "Location", "Status", "Created"])
    for j in jobs:
        w.writerow([j.id, j.title, j.description, j.department, j.location, j.status, j.created_at])
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=jobs.csv"})


@bp.route("/users/<int:user_id>/role", methods=["POST"])
@admin_required
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    role = request.form.get("role", "")
    if role in ("admin", "recruiter", "candidate"):
        user.role = role
        db.session.commit()
        flash(f"{user.name} role updated to {role}", "success")
    return redirect(url_for("admin.users_page"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Cannot delete yourself.", "error")
        return redirect(url_for("admin.users_page"))
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.name} deleted.", "success")
    return redirect(url_for("admin.users_page"))


@bp.route("/login-history")
@admin_required
def all_login_history():
    entries = LoginHistory.query.order_by(LoginHistory.timestamp.desc()).limit(200).all()
    return jsonify([{
        "id": e.id,
        "email": e.email,
        "ip": e.ip_address,
        "user_agent": e.user_agent,
        "success": e.success,
        "timestamp": e.timestamp.isoformat(),
    } for e in entries])
