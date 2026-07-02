from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user, logout_user
from ..models import User, UserSkill, Skill, db, generate_session_token
from ..otp import generate_secret

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


@bp.route("/face")
@login_required
def face_setup():
    return render_template("profile/face.html", active="profile")


@bp.route("/<int:user_id>")
def public_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template("profile/public.html", profile=user)


@bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")

    if not current_user.check_password(current_pw):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("profile.edit_profile"))

    if new_pw != confirm_pw:
        flash("New passwords do not match.", "error")
        return redirect(url_for("profile.edit_profile"))

    if len(new_pw) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("profile.edit_profile"))

    current_user.set_password(new_pw)
    current_user.session_token = generate_session_token()
    db.session.commit()
    logout_user()
    flash("Password changed. Please log in again.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/enable-otp", methods=["POST"])
@login_required
def enable_otp():
    pw = request.form.get("password", "")
    if not current_user.check_password(pw):
        flash("Invalid password.", "error")
        return redirect(url_for("profile.edit_profile"))
    current_user.otp_secret = generate_secret()
    current_user.otp_enabled = True
    db.session.commit()
    flash("OTP two-factor authentication enabled.", "success")
    return redirect(url_for("profile.edit_profile"))


@bp.route("/disable-otp", methods=["POST"])
@login_required
def disable_otp():
    pw = request.form.get("password", "")
    if not current_user.check_password(pw):
        flash("Invalid password.", "error")
        return redirect(url_for("profile.edit_profile"))
    current_user.otp_enabled = False
    db.session.commit()
    flash("OTP two-factor authentication disabled.", "success")
    return redirect(url_for("profile.edit_profile"))
