from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from ..models import Company, JobPosting, User, CompanyReview, db

bp = Blueprint("company", __name__, url_prefix="/companies")


@bp.route("/")
def index():
    companies = Company.query.order_by(Company.name).all()
    return render_template(
        "company/list.html",
        companies=companies,
        active="companies",
    )


@bp.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        website = request.form.get("website")
        logo_url = request.form.get("logo_url")
        industry = request.form.get("industry")
        location = request.form.get("location")
        size = request.form.get("size")

        comp = Company(
            name=name,
            description=description,
            website=website,
            logo_url=logo_url,
            industry=industry,
            location=location,
            size=size,
            created_by=current_user.id,
        )
        db.session.add(comp)
        db.session.commit()
        flash("Company created successfully.", "success")
        return redirect(url_for("company.view", id=comp.id))

    return render_template(
        "company/create.html",
        active="companies",
    )


@bp.route("/<int:id>")
def view(id):
    comp = Company.query.get_or_404(id)
    jobs = JobPosting.query.filter_by(company_id=id).order_by(JobPosting.created_at.desc()).all()
    reviews = CompanyReview.query.filter_by(company_id=id).order_by(CompanyReview.created_at.desc()).all()
    return render_template(
        "company/view.html",
        company=comp,
        jobs=jobs,
        reviews=reviews,
        active="companies",
        title=comp.name,
        heading=comp.name,
    )


@bp.route("/<int:id>/edit", methods=["GET", "POST"])
@login_required
def edit(id):
    comp = Company.query.get_or_404(id)
    if comp.created_by != current_user.id and current_user.role != 'admin':
        flash("You do not have permission to edit this company.", "danger")
        return redirect(url_for("company.view", id=comp.id))

    if request.method == "POST":
        comp.name = request.form.get("name")
        comp.description = request.form.get("description")
        comp.website = request.form.get("website")
        comp.logo_url = request.form.get("logo_url")
        comp.industry = request.form.get("industry")
        comp.location = request.form.get("location")
        comp.size = request.form.get("size")
        db.session.commit()
        flash("Company updated successfully.", "success")
        return redirect(url_for("company.view", id=comp.id))

    return render_template(
        "company/edit.html",
        company=comp,
        active="companies",
    )


@bp.route("/<int:id>/delete", methods=["POST"])
@login_required
def delete(id):
    comp = Company.query.get_or_404(id)
    if comp.created_by != current_user.id and current_user.role != 'admin':
        flash("You do not have permission to delete this company.", "danger")
        return redirect(url_for("company.view", id=comp.id))

    db.session.delete(comp)
    db.session.commit()
    flash("Company deleted successfully.", "success")
    return redirect(url_for("company.index"))


@bp.route("/<int:id>/review", methods=["POST"])
@login_required
def add_review(id):
    comp = Company.query.get_or_404(id)
    existing = CompanyReview.query.filter_by(user_id=current_user.id, company_id=id).first()
    if existing:
        flash("You already reviewed this company", "info")
        return redirect(url_for("company.view", id=id))
    rating = request.form.get("rating", 5, type=int)
    title = request.form.get("title", "")
    content = request.form.get("content", "")
    review = CompanyReview(user_id=current_user.id, company_id=id, rating=rating, title=title, content=content)
    db.session.add(review)
    db.session.commit()
    flash("Review submitted", "success")
    return redirect(url_for("company.view", id=id))
