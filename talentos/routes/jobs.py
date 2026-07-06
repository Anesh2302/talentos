from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from ..models import JobPosting, Company, Application, SavedJob, User, db
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


import base64

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

    cover_letter = request.form.get("cover_letter", "").strip()
    resume_data = ""
    resume_filename = ""
    resume_mime = ""
    if "resume" in request.files:
        f = request.files["resume"]
        if f.filename:
            f.seek(0, 2)
            if f.tell() > 10 * 1024 * 1024:
                flash("Resume must be under 10MB", "error")
                return redirect(url_for("jobs.job_detail", id=job.id))
            f.seek(0)
            try:
                resume_data = base64.b64encode(f.read()).decode()
                resume_filename = f.filename
                resume_mime = f.content_type or "application/octet-stream"
            except Exception:
                flash("Failed to process resume. Try a different file.", "error")
                return redirect(url_for("jobs.job_detail", id=job.id))

    application = Application(
        job_id=job.id, user_id=current_user.id,
        cover_letter=cover_letter if cover_letter else None,
        resume_data=resume_data, resume_filename=resume_filename,
        resume_mime=resume_mime,
    )
    db.session.add(application)
    db.session.commit()
    flash("Application submitted successfully.", "success")
    return redirect(url_for("jobs.job_detail", id=job.id))


@bp.route("/saved")
@login_required
def saved_jobs():
    saved = SavedJob.query.filter_by(user_id=current_user.id).order_by(SavedJob.created_at.desc()).all()
    return render_template("jobs/saved.html", saved=saved, active="saved")


@bp.route("/<int:id>/save", methods=["POST"])
@login_required
def toggle_save(id):
    job = JobPosting.query.get_or_404(id)
    existing = SavedJob.query.filter_by(user_id=current_user.id, job_id=id).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        return jsonify({"saved": False, "message": "Job unsaved"})
    SavedJob(user_id=current_user.id, job_id=id)
    db.session.commit()
    return jsonify({"saved": True, "message": "Job saved"})
