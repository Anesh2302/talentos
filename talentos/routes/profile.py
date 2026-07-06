import base64
import re
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user, logout_user
from ..models import User, UserSkill, Skill, Notification, db, generate_session_token
from ..otp import generate_secret

bp = Blueprint("profile", __name__, url_prefix="/profile")


def _validate_password(pw):
    if len(pw) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", pw):
        return "Password must contain an uppercase letter"
    if not re.search(r"[a-z]", pw):
        return "Password must contain a lowercase letter"
    if not re.search(r"[0-9]", pw):
        return "Password must contain a number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+]", pw):
        return "Password must contain a special character"
    return None


@bp.route("")
@login_required
def view_profile():
    _check_incomplete()
    return render_template("profile/view.html", active="profile")


def _check_incomplete():
    user = current_user
    missing = []
    if not user.headline: missing.append("headline")
    if not user.summary: missing.append("summary")
    if not user.location: missing.append("location")
    if not user.phone: missing.append("phone")
    if not user.profile_pic and not user.profile_pic_data: missing.append("profile picture")
    if not user.skills or len(user.skills) == 0: missing.append("skills")
    if missing:
        existing = Notification.query.filter_by(user_id=user.id, type="incomplete", link="/profile/edit").first()
        if not existing:
            msg = f"Your profile is incomplete — missing: {', '.join(missing)}. Complete it now!"
            n = Notification(user_id=user.id, type="incomplete", message=msg, link="/profile/edit")
            db.session.add(n)
            db.session.commit()


@bp.route("/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        current_user.name = request.form.get("name", current_user.name)
        current_user.headline = request.form.get("headline", "")
        current_user.summary = request.form.get("summary", "")
        current_user.location = request.form.get("location", "")
        current_user.phone = request.form.get("phone", "")
        current_user.linkedin = request.form.get("linkedin", "")
        current_user.github = request.form.get("github", "")
        current_user.website = request.form.get("website", "")
        MAX_FILE = 5 * 1024 * 1024
        if "resume" in request.files and request.files["resume"].filename:
            f = request.files["resume"]
            f.seek(0, 2)
            if f.tell() > MAX_FILE:
                flash("Resume must be under 5MB", "error")
                return redirect(url_for("profile.edit_profile"))
            f.seek(0)
            try:
                current_user.default_resume_data = base64.b64encode(f.read()).decode()
                current_user.default_resume_filename = f.filename
                current_user.default_resume_mime = f.content_type or "application/octet-stream"
            except Exception:
                flash("Failed to upload resume. Try a different file.", "error")
                return redirect(url_for("profile.edit_profile"))
        if "profile_pic_file" in request.files and request.files["profile_pic_file"].filename:
            f = request.files["profile_pic_file"]
            f.seek(0, 2)
            if f.tell() > MAX_FILE:
                flash("Profile picture must be under 5MB", "error")
                return redirect(url_for("profile.edit_profile"))
            f.seek(0)
            try:
                current_user.profile_pic_data = base64.b64encode(f.read()).decode()
                current_user.profile_pic = ""
            except Exception:
                flash("Failed to upload profile picture. Try a different image.", "error")
                return redirect(url_for("profile.edit_profile"))
        elif request.form.get("profile_pic", ""):
            current_user.profile_pic = request.form.get("profile_pic", "")
            current_user.profile_pic_data = ""
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

        Notification.query.filter_by(user_id=current_user.id, type="incomplete").delete()
        db.session.commit()
        flash("Profile updated", "success")
        return redirect(url_for("profile.view_profile"))
    return render_template("profile/edit.html", active="profile")


@bp.route("/face")
@login_required
def face_setup():
    return render_template("profile/face.html", active="profile")


@bp.route("/resume/download")
@login_required
def download_resume():
    import io
    from flask import send_file
    if not current_user.default_resume_data:
        flash("No resume uploaded", "error")
        return redirect(url_for("profile.view_profile"))
    data = base64.b64decode(current_user.default_resume_data)
    return send_file(
        io.BytesIO(data),
        mimetype=current_user.default_resume_mime or "application/octet-stream",
        as_attachment=True,
        download_name=current_user.default_resume_filename or "resume.pdf",
    )


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

    err = _validate_password(new_pw)
    if err:
        flash(err, "error")
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
    flash("OTP is mandatory and cannot be disabled.", "error")
    return redirect(url_for("profile.edit_profile"))


def profile_completeness(user):
    score = 0
    total = 7
    if user.name: score += 1
    if user.headline: score += 1
    if user.summary: score += 1
    if user.location: score += 1
    if user.phone: score += 1
    if user.profile_pic or user.profile_pic_data: score += 1
    if user.skills and len(user.skills) > 0: score += 1
    return int((score / total) * 100)
