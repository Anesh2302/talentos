from flask import Blueprint, jsonify, render_template, redirect, url_for
from flask_login import login_required, current_user
from ..models import JobPosting, Application, Company, User, db
from datetime import datetime, date

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return redirect(url_for("main.dashboard"))


@bp.route("/dashboard")
@login_required
def dashboard():
    total_jobs = JobPosting.query.count()
    open_jobs = JobPosting.query.filter_by(status="open").count()
    total_apps = Application.query.count()
    total_companies = Company.query.count()
    total_users = User.query.count()

    if current_user.role in ("admin", "recruiter"):
        recent_apps = Application.query.order_by(Application.created_at.desc()).limit(10).all()
        my_jobs = JobPosting.query.filter_by(created_by=current_user.id).all()
    else:
        recent_apps = Application.query.filter_by(user_id=current_user.id).order_by(Application.created_at.desc()).all()
        my_jobs = []

    stats = {
        "jobs": total_jobs,
        "open_jobs": open_jobs,
        "applications": total_apps,
        "companies": total_companies,
        "users": total_users,
    }
    return render_template("dashboard.html", stats=stats, recent_apps=recent_apps, my_jobs=my_jobs, active="dashboard")
