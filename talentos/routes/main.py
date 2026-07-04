from flask import Blueprint, jsonify, render_template, redirect, url_for, session
from flask_login import login_required, current_user
from ..models import JobPosting, Application, Company, User, db
from datetime import datetime, date

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    stats = {
        "jobs": f"{JobPosting.query.count():,}",
        "users": f"{User.query.count():,}",
        "companies": f"{Company.query.count():,}",
        "applications": f"{Application.query.count():,}",
    }
    people = User.query.order_by(User.created_at.desc()).limit(6).all()
    return render_template("landing.html", stats=stats, people=people)


@bp.route("/dashboard")
@login_required
def dashboard():
    session.pop("_flashes", None)
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
    hr = datetime.utcnow().hour
    if hr < 12:
        greeting = "Good Morning"
    elif hr < 17:
        greeting = "Good Afternoon"
    else:
        greeting = "Good Evening"
    now = datetime.utcnow()
    return render_template("dashboard.html", stats=stats, recent_apps=recent_apps, my_jobs=my_jobs, active="dashboard", greeting=greeting, day=now.strftime("%A"), date_str=now.strftime("%B %d, %Y"), time_str=now.strftime("%I:%M %p"))
