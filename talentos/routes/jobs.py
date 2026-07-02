from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from ..models import JobPosting, Company, Application, User, db
from datetime import datetime

bp = Blueprint("jobs", __name__, url_prefix="/jobs")


@bp.route("/")
def list_jobs():
    search = request.args.get("search", "").strip()
    job_type = request.args.get("job_type", "").strip()
    experience_level = request.args.get("experience_level", "").strip()
    location = request.args.get("location", "").strip()

    query = JobPosting.query

    if search:
        query = query.join(Company).filter(
            JobPosting.title.ilike(f"%{search}%")
            | Company.name.ilike(f"%{search}%")
        )
    if job_type:
        query = query.filter(JobPosting.job_type == job_type)
    if experience_level:
        query = query.filter(JobPosting.experience_level == experience_level)
    if location:
        query = query.filter(JobPosting.location.ilike(f"%{location}%"))

    jobs = query.order_by(JobPosting.created_at.desc()).all()
    return render_template(
        "jobs/list.html",
        jobs=jobs,
        search=search,
        job_type=job_type,
        experience_level=experience_level,
        location=location,
        active="jobs",
    )


@bp.route("/<int:id>")
def job_detail(id):
    job = JobPosting.query.get_or_404(id)
    applied = False
    if current_user.is_authenticated:
        applied = Application.query.filter_by(
            job_id=job.id, user_id=current_user.id
        ).first() is not None
    return render_template(
        "jobs/view.html", job=job, applied=applied, active="jobs"
    )


@bp.route("/create", methods=["GET", "POST"])
@login_required
def create_job():
    if current_user.role not in ('admin', 'recruiter'):
        flash("Only recruiters and admins can create job postings.", "danger")
        return redirect(url_for("jobs.list_jobs"))

    companies = Company.query.all()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        requirements = request.form.get("requirements", "").strip()
        location = request.form.get("location", "").strip()
        salary_min = request.form.get("salary_min", type=int)
        salary_max = request.form.get("salary_max", type=int)
        job_type = request.form.get("job_type", "").strip()
        experience_level = request.form.get("experience_level", "").strip()
        skills_required = request.form.get("skills_required", "").strip()
        company_id = request.form.get("company_id", type=int)

        if not title or not description or not company_id:
            flash("Title, description, and company are required.", "danger")
            return render_template(
                "jobs/create.html",
                companies=companies,
                active="jobs",
            )

        job = JobPosting(
            title=title,
            description=description,
            requirements=requirements,
            location=location,
            salary_min=salary_min,
            salary_max=salary_max,
            job_type=job_type,
            experience_level=experience_level,
            skills_required=skills_required,
            company_id=company_id,
            created_by=current_user.id,
        )
        db.session.add(job)
        db.session.commit()
        flash("Job posting created successfully.", "success")
        return redirect(url_for("jobs.job_detail", id=job.id))

    return render_template("jobs/create.html", companies=companies, active="jobs")


@bp.route("/<int:id>/edit", methods=["GET", "POST"])
@login_required
def edit_job(id):
    job = JobPosting.query.get_or_404(id)

    if job.created_by != current_user.id:
        flash("You do not have permission to edit this job.", "danger")
        return redirect(url_for("jobs.job_detail", id=job.id))

    companies = Company.query.all()

    if request.method == "POST":
        job.title = request.form.get("title", "").strip()
        job.description = request.form.get("description", "").strip()
        job.requirements = request.form.get("requirements", "").strip()
        job.location = request.form.get("location", "").strip()
        job.salary_min = request.form.get("salary_min", type=int)
        job.salary_max = request.form.get("salary_max", type=int)
        job.job_type = request.form.get("job_type", "").strip()
        job.experience_level = request.form.get("experience_level", "").strip()
        job.skills_required = request.form.get("skills_required", "").strip()

        db.session.commit()
        flash("Job posting updated successfully.", "success")
        return redirect(url_for("jobs.job_detail", id=job.id))

    return render_template(
        "jobs/edit.html", job=job, companies=companies, active="jobs"
    )


@bp.route("/<int:id>/delete", methods=["POST"])
@login_required
def delete_job(id):
    job = JobPosting.query.get_or_404(id)

    if job.created_by != current_user.id:
        flash("You do not have permission to delete this job.", "danger")
        return redirect(url_for("jobs.job_detail", id=job.id))

    db.session.delete(job)
    db.session.commit()
    flash("Job posting deleted.", "success")
    return redirect(url_for("jobs.list_jobs"))


@bp.route("/<int:id>/apply", methods=["POST"])
@login_required
def apply_job(id):
    job = JobPosting.query.get_or_404(id)

    existing = Application.query.filter_by(
        job_id=job.id, user_id=current_user.id
    ).first()
    if existing:
        flash("You have already applied to this job.", "info")
        return redirect(url_for("jobs.job_detail", id=job.id))

    application = Application(
        job_id=job.id, user_id=current_user.id
    )
    db.session.add(application)
    db.session.commit()
    flash("Application submitted successfully.", "success")
    return redirect(url_for("jobs.job_detail", id=job.id))
