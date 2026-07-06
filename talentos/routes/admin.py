from functools import wraps
from datetime import datetime, date
import re as _re
from flask import Blueprint, jsonify, request, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from sqlalchemy.exc import IntegrityError
from ..models import (
    User, Candidate, Job, Todo, LoginHistory, AuditLog, JobPosting, Application, db,
    Post, PostLike, Comment, Follow, SavedJob, Notification, CompanyReview,
    ActivityLog, FaceVerification, PasswordResetToken, BackupCode,
    ConversationParticipant, Message, UserSkill, Interview, Company
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if current_user.role != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


@bp.route("")
@admin_required
def admin_home():
    return redirect(url_for("admin.dashboard"))


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
    from sqlalchemy import func
    blocked = db.session.query(LoginHistory.ip_address, func.count(LoginHistory.id).label('attempts'))\
        .filter(LoginHistory.success == False, LoginHistory.ip_address.isnot(None))\
        .group_by(LoginHistory.ip_address)\
        .order_by(func.count(LoginHistory.id).desc())\
        .limit(50).all()
    blocked_ips = [{"ip": ip, "attempts": n} for ip, n in blocked]

    def parse_ua(ua):
        ua = ua or ""
        parts = {"os": "Unknown", "browser": "Unknown", "device": "Unknown"}
        if "Windows" in ua:
            parts["os"] = "Windows 10/11" if "Windows NT 10.0" in ua else "Windows"
        elif "Mac OS X" in ua:
            parts["os"] = "macOS"
        elif "Linux" in ua and "Android" not in ua:
            parts["os"] = "Linux"
        elif "Android" in ua:
            parts["os"] = "Android"
        elif "iPhone" in ua or "iPad" in ua:
            parts["os"] = "iOS"
        if "Mobile" in ua or "iPhone" in ua or "iPad" in ua or "Android" in ua:
            parts["device"] = "Mobile"
        else:
            parts["device"] = "Desktop"
        if "Chrome/" in ua and "Edg/" not in ua:
            parts["browser"] = "Chrome"
        elif "Firefox/" in ua:
            parts["browser"] = "Firefox"
        elif "Safari/" in ua and "Chrome" not in ua:
            parts["browser"] = "Safari"
        elif "Edg/" in ua:
            parts["browser"] = "Edge"
        return parts

    parsed_failures = []
    for e in recent_failures:
        p = parse_ua(e.user_agent)
        parsed_failures.append({"time": e.timestamp, "email": e.email, "ip": e.ip_address, "device": p["device"], "os": p["os"], "browser": p["browser"]})
    parsed_logins = []
    for e in recent_logins:
        p = parse_ua(e.user_agent)
        parsed_logins.append({"time": e.timestamp, "email": e.email, "ip": e.ip_address, "device": p["device"], "os": p["os"], "browser": p["browser"]})

    return render_template("security.html",
                           failures=parsed_failures,
                           logins=parsed_logins,
                           blocked_ips=blocked_ips,
                           active="admin_security")


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
    uid = user.id
    try:
        BackupCode.query.filter_by(user_id=uid).delete()
        PasswordResetToken.query.filter_by(user_id=uid).delete()
        LoginHistory.query.filter_by(user_id=uid).delete()
        ConversationParticipant.query.filter_by(user_id=uid).delete()
        Message.query.filter_by(sender_id=uid).delete()
        PostLike.query.filter_by(user_id=uid).delete()
        Comment.query.filter_by(user_id=uid).delete()
        Follow.query.filter_by(follower_id=uid).delete()
        Follow.query.filter_by(followed_id=uid).delete()
        SavedJob.query.filter_by(user_id=uid).delete()
        Notification.query.filter_by(user_id=uid).delete()
        CompanyReview.query.filter_by(user_id=uid).delete()
        ActivityLog.query.filter_by(user_id=uid).delete()
        AuditLog.query.filter_by(user_id=uid).delete()
        FaceVerification.query.filter_by(user_id=uid).delete()
        UserSkill.query.filter_by(user_id=uid).delete()
        Interview.query.filter_by(created_by=uid).delete()
        Candidate.query.filter_by(user_id=uid).delete()
        Application.query.filter_by(user_id=uid).delete()
        Post.query.filter_by(user_id=uid).delete()
        JobPosting.query.filter_by(created_by=uid).delete()
        Todo.query.filter_by(created_by=uid).delete()
        Company.query.filter_by(created_by=uid).delete()
        Job.query.filter_by(created_by=uid).update({"created_by": None})
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.name} deleted.", "success")
    except IntegrityError:
        db.session.rollback()
        flash(f"Cannot delete {user.name}: user has related records that cannot be removed.", "error")
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


@bp.route("/charts")
@admin_required
def charts():
    from sqlalchemy import func
    app_over_time = db.session.query(
        func.date(Application.created_at).label('date'),
        func.count(Application.id).label('count')
    ).group_by(func.date(Application.created_at)).order_by('date').all()
    status_counts = db.session.query(
        Application.status, func.count(Application.id)
    ).group_by(Application.status).all()
    jobs_over_time = db.session.query(
        func.date(JobPosting.created_at).label('date'),
        func.count(JobPosting.id).label('count')
    ).group_by(func.date(JobPosting.created_at)).order_by('date').all()
    return render_template("admin/charts.html",
        app_over_time=[{"date": str(r.date), "count": r.count} for r in app_over_time],
        status_counts=[{"status": s, "count": c} for s, c in status_counts],
        jobs_over_time=[{"date": str(r.date), "count": r.count} for r in jobs_over_time],
        active="admin_charts",
    )


@bp.route("/audit")
@admin_required
def audit_log():
    entries = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return render_template("admin/audit.html", entries=entries, active="admin_audit")


def _send_report_email(subject, html_body):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from flask import current_app
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = current_app.config.get("MAIL_USERNAME", "noreply@talentos.app")
        msg["To"] = "simonpetercys@gmail.com"
        msg.attach(MIMEText("View this email in HTML format", "plain"))
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP(
            current_app.config.get("MAIL_SERVER", "smtp.gmail.com"),
            current_app.config.get("MAIL_PORT", 587),
        ) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(
                current_app.config.get("MAIL_USERNAME", ""),
                current_app.config.get("MAIL_PASSWORD", ""),
            )
            server.sendmail(msg["From"], [msg["To"]], msg.as_string())
        return True
    except Exception as e:
        current_app.logger.error(f"Report email failed: {e}")
        return False


@bp.route("/security-report", methods=["POST"])
def security_report():
    api_key = request.headers.get("X-API-Key") or request.form.get("api_key") or request.args.get("api_key")
    expected_key = current_app.config.get("SECURITY_REPORT_KEY", "")
    if not expected_key or api_key != expected_key:
        from flask_login import current_user
        if not current_user.is_authenticated or current_user.role != "admin":
            return jsonify({"error": "Unauthorized"}), 403
    from sqlalchemy import func as _func
    from datetime import date as _date
    today = _date.today()
    yesterday = datetime(today.year, today.month, today.day) - __import__("datetime").timedelta(days=1)
    today_start = datetime(today.year, today.month, today.day)
    total_users = User.query.count()
    new_today = User.query.filter(User.created_at >= today_start).count()
    total_logins_today = LoginHistory.query.filter(LoginHistory.timestamp >= today_start).count()
    failed_today = LoginHistory.query.filter(LoginHistory.timestamp >= today_start, LoginHistory.success == False).count()
    success_today = total_logins_today - failed_today
    total_posts = Post.query.count()
    total_jobs = JobPosting.query.count()
    total_applications = Application.query.count()
    total_companies = Company.query.count()
    flagged = db.session.query(LoginHistory.ip_address, _func.count(LoginHistory.id).label("attempts"))\
        .filter(LoginHistory.success == False, LoginHistory.timestamp >= today_start, LoginHistory.ip_address.isnot(None))\
        .group_by(LoginHistory.ip_address)\
        .having(_func.count(LoginHistory.id) >= 3)\
        .order_by(_func.count(LoginHistory.id).desc()).limit(20).all()
    otp_count = User.query.filter(User.otp_enabled == True).count()
    admin_count = User.query.filter(User.role == "admin").count()
    candidate_count = User.query.filter(User.role == "candidate").count()
    recent_logins = LoginHistory.query.filter(LoginHistory.timestamp >= today_start, LoginHistory.success == True)\
        .order_by(LoginHistory.timestamp.desc()).limit(10).all()
    recent_fails = LoginHistory.query.filter(LoginHistory.timestamp >= today_start, LoginHistory.success == False)\
        .order_by(LoginHistory.timestamp.desc()).limit(10).all()
    flagged_html = ""
    for ip, n in flagged:
        flagged_html += f"<tr><td style='padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:13px'>{ip}</td><td style='padding:8px 12px;border-bottom:1px solid #e5e7eb;text-align:center;color:#ef4444;font-weight:600;font-size:13px'>{n}</td></tr>"
    login_rows = ""
    for l in recent_logins:
        login_rows += f"<tr><td style='padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:13px'>{l.email}</td><td style='padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:12px'>{l.ip_address or '-'}</td><td style='padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#6b7280'>{l.timestamp.strftime('%H:%M') if l.timestamp else '-'}</td></tr>"
    fail_rows = ""
    for l in recent_fails:
        fail_rows += f"<tr><td style='padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:13px'>{l.email}</td><td style='padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:12px'>{l.ip_address or '-'}</td><td style='padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#6b7280'>{l.timestamp.strftime('%H:%M') if l.timestamp else '-'}</td></tr>"
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background:#f4f7fb">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);overflow:hidden">
<tr><td style="background:linear-gradient(135deg,#2563eb,#7c3aed);padding:20px 24px;text-align:center">
<h1 style="margin:0;color:#fff;font-size:18px">TalentOS Security Report</h1>
<p style="margin:4px 0 0;color:#c4b5fd;font-size:12px">{now_str}</p>
</td></tr>
<tr><td style="padding:24px">
<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:24px">
<div style="background:#f0f5ff;border-radius:8px;padding:16px;text-align:center"><p style="margin:0;font-size:24px;font-weight:700;color:#2563eb">{total_logins_today}</p><p style="margin:4px 0 0;font-size:12px;color:#6b7280">Total Logins Today</p></div>
<div style="background:#fef2f2;border-radius:8px;padding:16px;text-align:center"><p style="margin:0;font-size:24px;font-weight:700;color:#ef4444">{failed_today}</p><p style="margin:4px 0 0;font-size:12px;color:#6b7280">Failed Attempts</p></div>
<div style="background:#f0fdf4;border-radius:8px;padding:16px;text-align:center"><p style="margin:0;font-size:24px;font-weight:700;color:#22c55e">{new_today}</p><p style="margin:4px 0 0;font-size:12px;color:#6b7280">New Users Today</p></div>
</div>
<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px">
<tr><td style="padding:12px;background:#f9fafb;border-radius:8px 8px 0 0;font-size:13px;font-weight:600;color:#374151">Platform Overview</td></tr>
<tr><td style="padding:0 12px">
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#6b7280">Total Users</td><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;text-align:right;font-size:13px;font-weight:600;color:#374151">{total_users}</td></tr>
<tr><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#6b7280">Admins / Candidates</td><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;text-align:right;font-size:13px;font-weight:600;color:#374151">{admin_count} / {candidate_count}</td></tr>
<tr><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#6b7280">OTP Protected</td><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;text-align:right;font-size:13px;font-weight:600;color:#374151">{otp_count}</td></tr>
<tr><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#6b7280">Companies</td><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;text-align:right;font-size:13px;font-weight:600;color:#374151">{total_companies}</td></tr>
<tr><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#6b7280">Job Postings</td><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;text-align:right;font-size:13px;font-weight:600;color:#374151">{total_jobs}</td></tr>
<tr><td style="padding:10px 0;font-size:13px;color:#6b7280">Applications</td><td style="padding:10px 0;text-align:right;font-size:13px;font-weight:600;color:#374151">{total_applications}</td></tr>
</table>
</td></tr></table>
{"<table width='100%' cellpadding='0' cellspacing='0' style='margin-bottom:16px'><tr><td style='padding:12px;background:#fef2f2;border-radius:8px 8px 0 0;font-size:13px;font-weight:600;color:#dc2626'><span style='color:#ef4444;margin-right:6px'>&#9888;</span> Flagged IPs (3+ failed attempts today)</td></tr><tr><td style='padding:0'><table width='100%' cellpadding='0' cellspacing='0'><tr><th style='padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb'>IP Address</th><th style='padding:8px 12px;text-align:center;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb'>Attempts</th></tr>"+flagged_html+"</table></td></tr></table>" if flagged else ""}
<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px">
<tr><td style="padding:12px;background:#f0fdf4;border-radius:8px 8px 0 0;font-size:13px;font-weight:600;color:#16a34a">Recent Successful Logins</td></tr>
<tr><td style="padding:0"><table width="100%" cellpadding="0" cellspacing="0"><tr><th style='padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb'>User</th><th style='padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb'>IP</th><th style='padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb'>Time</th></tr>{login_rows}</table></td></tr></table>
<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px">
<tr><td style="padding:12px;background:#fef2f2;border-radius:8px 8px 0 0;font-size:13px;font-weight:600;color:#dc2626">Recent Failed Attempts</td></tr>
<tr><td style="padding:0"><table width="100%" cellpadding="0" cellspacing="0"><tr><th style='padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb'>User</th><th style='padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb'>IP</th><th style='padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb'>Time</th></tr>{fail_rows}</table></td></tr></table>
<p style="margin:16px 0 0;font-size:11px;color:#9ca3af;text-align:center">This is an automated security report from TalentOS. Generated at {now_str}.</p>
</td></tr></table>
</td></tr></table>
</body></html>"""
    ok = _send_report_email(f"TalentOS Security Report - {today.isoformat()}", html)
    return jsonify({"success": ok, "message": "Report sent" if ok else "Failed to send"})


@bp.route("/bulk/status", methods=["POST"])
@admin_required
def bulk_status():
    ids = request.form.get("ids", "")
    status = request.form.get("status", "")
    if status not in ("applied", "screening", "interview", "offer", "rejected", "hired"):
        flash("Invalid status", "error")
        return redirect(url_for("applications.list_applications"))
    id_list = [int(x) for x in ids.split(",") if x.strip().isdigit()]
    for aid in id_list:
        app = Application.query.get(aid)
        if app:
            app.status = status
            app.updated_at = datetime.utcnow()
    db.session.commit()
    flash(f"Updated {len(id_list)} applications to {status}", "success")
    return redirect(url_for("applications.list_applications"))
