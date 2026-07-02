from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from ..models import User, UserSkill, Skill, db

bp = Blueprint("profile", __name__, url_prefix="/profile")


@bp.route("")
@login_required
def view_profile():
    return render_template("profile/view.html", active="profile")


@bp.route("/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        current_user.name = request.form.get("name", current_user.name)
        current_user.headline = request.form.get("headline", "")
        current_user.summary = request.form.get("summary", "")
        current_user.location = request.form.get("location", "")
        current_user.phone = request.form.get("phone", "")
        current_user.profile_pic = request.form.get("profile_pic", "")
        db.session.commit()

        skills_str = request.form.get("skills", "")
        if skills_str:
            UserSkill.query.filter_by(user_id=current_user.id).delete()
            for s in skills_str.split(","):
                s = s.strip()
                if s:
                    skill = Skill.query.filter_by(name=s.lower()).first()
                    if not skill:
                        skill = Skill(name=s.lower())
                        db.session.add(skill)
                        db.session.flush()
                    db.session.add(UserSkill(user_id=current_user.id, skill_id=skill.id))
            db.session.commit()

        flash("Profile updated", "success")
        return redirect(url_for("profile.view_profile"))
    return render_template("profile/edit.html", active="profile")


@bp.route("/<int:user_id>")
def public_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template("profile/public.html", profile=user)
