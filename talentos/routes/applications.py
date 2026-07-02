from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from ..models import Application, JobPosting, User, db
from datetime import datetime

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
