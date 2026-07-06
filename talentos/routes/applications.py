import base64
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for, send_file
from flask_login import login_required, current_user
from ..models import Application, JobPosting, User, Interview, db
from ..routes.notifications import add_notification
from datetime import datetime
import io

bp = Blueprint("applications", __name__, url_prefix="/applications")


@bp.route("")
@login_required
def list_applications():
    if current_user.role in ("admin", "recruiter"):
        apps = Application.query.order_by(Application.created_at.desc()).all()
    else:
        apps = Application.query.filter_by(user_id=current_user.id).order_by(Application.created_at.desc()).all()
    return render_template("applications/list.html", applications=apps, active="applications")


@bp.route("/<int:id>")
@login_required
def view_application(id):
    app = Application.query.get_or_404(id)
    if current_user.id != app.user_id and current_user.role not in ("admin", "recruiter"):
        flash("Access denied", "error")
        return redirect(url_for("applications.list_applications"))
    return render_template("applications/view.html", application=app, active="applications")


@bp.route("/<int:id>/status", methods=["POST"])
@login_required
def update_status(id):
    if current_user.role not in ("admin", "recruiter"):
        return jsonify({"error": "Access denied"}), 403
    app = Application.query.get_or_404(id)
    status = request.form.get("status", "")
    if status in ("applied", "screening", "interview", "offer", "rejected", "hired"):
        app.status = status
        app.updated_at = datetime.utcnow()
        db.session.commit()
        flash(f"Application moved to {status}", "success")
    return redirect(url_for("applications.view_application", id=id))


@bp.route("/<int:id>/score", methods=["POST"])
@login_required
def update_score(id):
    if current_user.role not in ("admin", "recruiter"):
        return jsonify({"error": "Access denied"}), 403
    app = Application.query.get_or_404(id)
    try:
        score = float(request.form.get("score", 0))
        app.score = max(0, min(100, score))
        app.updated_at = datetime.utcnow()
        db.session.commit()
        flash(f"Score updated to {app.score}", "success")
    except ValueError:
        flash("Invalid score", "error")
    return redirect(url_for("applications.view_application", id=id))


@bp.route("/<int:id>/resume", methods=["POST"])
@login_required
def upload_resume(id):
    app = Application.query.get_or_404(id)
    if current_user.id != app.user_id and current_user.role not in ("admin", "recruiter"):
        flash("Access denied", "error")
        return redirect(url_for("applications.list_applications"))
    if "resume" not in request.files:
        flash("No file selected", "error")
        return redirect(url_for("applications.view_application", id=id))
    f = request.files["resume"]
    if not f.filename:
        flash("No file selected", "error")
        return redirect(url_for("applications.view_application", id=id))
    MAX_FILE = 10 * 1024 * 1024
    f.seek(0, 2)
    if f.tell() > MAX_FILE:
        flash("Resume must be under 10MB", "error")
        return redirect(url_for("applications.view_application", id=id))
    f.seek(0)
    try:
        app.resume_data = base64.b64encode(f.read()).decode()
        app.resume_filename = f.filename
        app.resume_mime = f.content_type or "application/octet-stream"
        db.session.commit()
        flash("Resume uploaded", "success")
    except Exception:
        flash("Failed to upload resume. Try a different file.", "error")
    return redirect(url_for("applications.view_application", id=id))


@bp.route("/<int:id>/resume/download")
@login_required
def download_resume(id):
    app = Application.query.get_or_404(id)
    if current_user.id != app.user_id and current_user.role not in ("admin", "recruiter"):
        flash("Access denied", "error")
        return redirect(url_for("applications.list_applications"))
    if not app.resume_data:
        flash("No resume uploaded", "error")
        return redirect(url_for("applications.view_application", id=id))
    data = base64.b64decode(app.resume_data)
    return send_file(
        io.BytesIO(data),
        mimetype=app.resume_mime or "application/octet-stream",
        as_attachment=True,
        download_name=app.resume_filename or "resume.pdf",
    )


@bp.route("/<int:id>/interview", methods=["GET", "POST"])
@login_required
def interview(id):
    if current_user.role not in ("admin", "recruiter"):
        flash("Access denied", "error")
        return redirect(url_for("applications.list_applications"))
    app = Application.query.get_or_404(id)
    existing = Interview.query.filter_by(application_id=id).order_by(Interview.created_at.desc()).first()
    if request.method == "POST":
        from datetime import datetime as dt
        scheduled_str = request.form.get("scheduled_at", "")
        try:
            scheduled = dt.strptime(scheduled_str, "%Y-%m-%dT%H:%M")
        except (ValueError, TypeError):
            flash("Invalid date/time", "error")
            return redirect(url_for("applications.interview", id=id))
        notes = request.form.get("notes", "")
        location = request.form.get("location", "")
        interview = Interview(
            application_id=id, scheduled_at=scheduled,
            notes=notes, location=location, created_by=current_user.id,
        )
        db.session.add(interview)
        app.status = "interview"
        db.session.commit()
        add_notification(app.user_id, "interview", f"Interview scheduled for {app.job.title} on {scheduled.strftime('%b %d at %I:%M %p')}", f"/applications/{id}")
        flash("Interview scheduled", "success")
        return redirect(url_for("applications.view_application", id=id))
    return render_template("applications/interview.html", application=app, interview=existing, active="applications")
