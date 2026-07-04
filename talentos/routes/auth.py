import base64
import secrets
import json
import re
import math
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User, PasswordResetToken, LoginHistory, BackupCode, FaceVerification, generate_session_token
from ..otp import generate_secret, generate_otp, verify_otp, send_otp_email
from .. import db
from flask import session as flask_session

bp = Blueprint("auth", __name__, url_prefix="/auth")


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


@bp.route("/register", methods=["POST"])
def register():
    if request.is_json:
        data = request.get_json(force=True, silent=True) or {}
    else:
        data = request.form.to_dict()
    if not data or "email" not in data:
        return jsonify({"error": "Invalid JSON body"}), 400
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already registered"}), 400

    pw = data.get("password", "")
    err = _validate_password(pw)
    if err:
        return jsonify({"error": err}), 400

    user = User(
        email=data["email"],
        name=data["name"],
        role=data.get("role", "candidate"),
        phone=data.get("phone", ""),
        linkedin=data.get("linkedin", ""),
        github=data.get("github", ""),
        website=data.get("website", ""),
        otp_secret=generate_secret(),
        is_verified=True,
    )
    if "resume" in request.files and request.files["resume"].filename:
        f = request.files["resume"]
        user.default_resume_data = base64.b64encode(f.read()).decode()
        user.default_resume_filename = f.filename
        user.default_resume_mime = f.content_type or "application/octet-stream"
    user.set_password(pw)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Registered successfully.", "user_id": user.id}), 201


@bp.route("/signup")
def signup_page():
    return render_template("signup.html")


@bp.route("/verify-email", methods=["POST"])
def verify_email():
    data = request.get_json(force=True, silent=True)
    if not data or "user_id" not in data or "code" not in data:
        return jsonify({"error": "Invalid request"}), 400
    user = User.query.get(data["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404
    if verify_otp(user.otp_secret, data["code"]):
        user.is_verified = True
        db.session.commit()
        return jsonify({"message": "Email verified"})
    return jsonify({"error": "Invalid or expired OTP"}), 400


def _record_login(email, success, user_id=None):
    entry = LoginHistory(
        user_id=user_id,
        email=email,
        ip_address=request.remote_addr or "",
        user_agent=request.headers.get("User-Agent", "")[:500],
        success=success,
    )
    db.session.add(entry)
    db.session.commit()


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    data = request.get_json(force=True, silent=True)
    if not data or "email" not in data:
        return jsonify({"error": "Invalid JSON body"}), 400

    user = User.query.filter_by(email=data["email"]).first()

    if not user or not user.check_password(data["password"]):
        _record_login(data.get("email", "?"), False)
        return jsonify({"error": "Invalid credentials"}), 401

    if user.is_locked():
        _record_login(user.email, False, user.id)
        return jsonify({"error": "Account locked. Try again later."}), 423

    if not user.is_verified:
        user.is_verified = True
        db.session.commit()

    if user.otp_enabled and not user.otp_secret:
        user.otp_secret = generate_secret()
        db.session.commit()

    otp_input = data.get("otp")
    backup_input = data.get("backup_code")

    if user.otp_enabled and not otp_input and not backup_input:
        code = generate_otp(user.otp_secret)
        try:
            send_otp_email(user.email, code)
        except Exception:
            print(f"[SMTP] Login OTP to {user.email} failed")
        return jsonify({"otp_required": True, "message": "OTP sent to email"})

    if user.otp_enabled:
        if backup_input:
            code = BackupCode.query.filter_by(user_id=user.id, code=backup_input, used=False).first()
            if not code:
                user.record_failed_login()
                _record_login(user.email, False, user.id)
                db.session.commit()
                return jsonify({"error": "Invalid backup code"}), 401
            code.used = True
        elif not verify_otp(user.otp_secret, otp_input):
            user.record_failed_login()
            _record_login(user.email, False, user.id)
            db.session.commit()
            return jsonify({"error": "Invalid OTP"}), 401

    user.login_attempts = 0

    if user.face_descriptor and not data.get("skip_face"):
        flask_session["pending_face_uid"] = user.id
        flask_session["face_purpose"] = "login"
        db.session.commit()
        return jsonify({"face_redirect": url_for("auth.verify_face_page")})

    flask_session.pop("_flashes", None)
    user.session_token = generate_session_token()
    db.session.commit()
    _record_login(user.email, True, user.id)
    login_user(user)
    return jsonify({"message": "Login successful", "user": user.name})


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@bp.route("/setup-otp", methods=["POST"])
@login_required
def setup_otp():
    data = request.get_json(force=True, silent=True) or {}
    if data.get("password") and not current_user.check_password(data["password"]):
        return jsonify({"error": "Invalid password"}), 401
    current_user.otp_enabled = True
    current_user.otp_secret = generate_secret()
    db.session.commit()
    return jsonify({"message": "OTP enabled", "secret": current_user.otp_secret})


@bp.route("/disable-otp", methods=["POST"])
@login_required
def disable_otp():
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("password") or not current_user.check_password(data["password"]):
        return jsonify({"error": "Invalid password"}), 401
    current_user.otp_enabled = False
    db.session.commit()
    return jsonify({"message": "OTP disabled"})


@bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json(force=True, silent=True) or {}
    user = User.query.filter_by(email=data.get("email", "")).first()
    if not user:
        return jsonify({"message": "If that email exists, a reset link has been sent."})

    token = secrets.token_urlsafe(48)
    reset = PasswordResetToken(
        user_id=user.id,
        token=token,
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.session.add(reset)
    db.session.commit()

    from ..otp import send_reset_email
    send_reset_email(user.email, token)
    return jsonify({"message": "If that email exists, a reset link has been sent."})


@bp.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(force=True, silent=True) or {}
    reset = PasswordResetToken.query.filter_by(token=data.get("token", ""), used=False).first()
    if not reset or reset.is_expired():
        return jsonify({"error": "Invalid or expired reset token"}), 400

    user = reset.user
    user.set_password(data["password"])
    reset.used = True
    db.session.commit()
    return jsonify({"message": "Password reset successful"})


@bp.route("/change-email", methods=["POST"])
@login_required
def change_email():
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("password") or not current_user.check_password(data["password"]):
        return jsonify({"error": "Invalid password"}), 401

    new_email = data.get("new_email", "")
    if User.query.filter_by(email=new_email).first():
        return jsonify({"error": "Email already in use"}), 400

    current_user.email = new_email
    current_user.is_verified = False
    db.session.commit()

    code = generate_otp(current_user.otp_secret)
    send_otp_email(current_user.email, code)
    return jsonify({"message": "Email changed. Verify with OTP sent to new address."})


@bp.route("/login-history")
@login_required
def my_login_history():
    entries = LoginHistory.query.filter_by(user_id=current_user.id)\
        .order_by(LoginHistory.timestamp.desc()).limit(50).all()
    return jsonify([{
        "ip": e.ip_address,
        "user_agent": e.user_agent,
        "success": e.success,
        "timestamp": e.timestamp.isoformat(),
    } for e in entries])


@bp.route("/generate-backup-codes", methods=["POST"])
@login_required
def generate_backup_codes():
    data = request.get_json(force=True, silent=True) or {}
    if not data.get("password") or not current_user.check_password(data["password"]):
        return jsonify({"error": "Invalid password"}), 401

    BackupCode.query.filter_by(user_id=current_user.id).delete()
    codes = []
    for _ in range(5):
        code = secrets.token_hex(5).upper()
        db.session.add(BackupCode(user_id=current_user.id, code=code))
        codes.append(code)
    db.session.commit()
    return jsonify({"message": "Backup codes generated", "codes": codes})


def cosine_similarity(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0
    return dot / (na * nb)


@bp.route("/verify-face")
def verify_face_page():
    uid = flask_session.get("pending_face_uid")
    purpose = flask_session.get("face_purpose", "login")
    user = User.query.get(uid) if uid else None
    if not user:
        return redirect(url_for("auth.login"))
    return render_template("verify_face.html", purpose=purpose)


@bp.route("/face-login", methods=["POST"])
def face_login_init():
    data = request.get_json(force=True, silent=True) or {}
    email = data.get("email", "").strip()
    if not email:
        return jsonify({"error": "Email is required"}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not user.face_descriptor:
        return jsonify({"error": "No face enrolled for this account",
                        "redirect": url_for("auth.login")}), 400
    flask_session["pending_face_uid"] = user.id
    flask_session["face_purpose"] = "login"
    return jsonify({"face_redirect": url_for("auth.verify_face_page")})


@bp.route("/face/capture", methods=["POST"])
def face_capture():
    uid = flask_session.get("pending_face_uid")
    purpose = flask_session.get("face_purpose", "login")
    if not uid:
        return jsonify({"error": "No pending login"}), 401
    user = User.query.get(uid)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json(force=True, silent=True)
    if not data or "descriptor" not in data:
        return jsonify({"error": "No face data provided"}), 400

    descriptor = data["descriptor"]
    image_data = data.get("image", "")

    if purpose == "enroll":
        if user.face_descriptor:
            return jsonify({"error": "Face already enrolled"}), 400
        user.face_descriptor = json.dumps(descriptor)
        user.face_image = image_data
        user.face_verified = True
        fv = FaceVerification(user_id=user.id, face_encoding=json.dumps(descriptor),
                              image_data=image_data, verified=True)
        db.session.add(fv)
        db.session.commit()
        flask_session.pop("pending_face_uid", None)
        flask_session.pop("face_purpose", None)
        user.session_token = generate_session_token()
        db.session.commit()
        _record_login(user.email, True, user.id)
        login_user(user)
        return jsonify({"match": True, "message": "Face enrolled and logged in"})

    if not user.face_descriptor:
        return jsonify({"error": "No face enrolled", "redirect": url_for("auth.skip_alternatives_page")}), 400

    stored = json.loads(user.face_descriptor)
    score = cosine_similarity(descriptor, stored)
    if score < 0.5:
        user.face_fail_count = (user.face_fail_count or 0) + 1
        db.session.commit()
        if user.face_fail_count >= 5:
            return jsonify({"error": "Too many failed attempts", "locked": True,
                            "redirect": url_for("auth.skip_alternatives_page")}), 429
        fv = FaceVerification(user_id=user.id, face_encoding=json.dumps(descriptor),
                              image_data=image_data, liveness_score=round(score, 3), verified=False)
        db.session.add(fv)
        db.session.commit()
        return jsonify({"match": False, "score": round(score, 3),
                        "remaining": 5 - (user.face_fail_count or 0)}), 401

    user.face_fail_count = 0
    user.face_verified = True
    fv = FaceVerification(user_id=user.id, face_encoding=json.dumps(descriptor),
                          image_data=image_data, liveness_score=round(score, 3), verified=True)
    db.session.add(fv)
    flask_session.pop("pending_face_uid", None)
    flask_session.pop("face_purpose", None)
    user.session_token = generate_session_token()
    db.session.commit()
    _record_login(user.email, True, user.id)
    login_user(user)
    return jsonify({"match": True, "message": "Face verified, logged in"})


@bp.route("/skip-all")
def skip_all():
    uid = flask_session.get("pending_face_uid")
    flask_session.pop("pending_face_uid", None)
    flask_session.pop("face_purpose", None)
    user = User.query.get(uid) if uid else None
    if not user:
        return redirect(url_for("auth.login"))
    user.face_fail_count = 0
    user.session_token = generate_session_token()
    db.session.commit()
    _record_login(user.email, True, user.id)
    login_user(user)
    return redirect(url_for("main.dashboard"))


@bp.route("/skip-alternatives")
def skip_alternatives_page():
    uid = flask_session.get("pending_face_uid")
    user = User.query.get(uid) if uid else None
    if not user:
        return redirect(url_for("auth.login"))
    otp_sent = flask_session.pop("alt_otp_sent", False)
    return render_template("skip_alternatives.html", otp_sent=otp_sent)


@bp.route("/skip-alternatives/otp", methods=["POST"])
def skip_alternatives_otp():
    uid = flask_session.get("pending_face_uid")
    user = User.query.get(uid) if uid else None
    if not user:
        return jsonify({"error": "Session expired"}), 401

    data = request.get_json(force=True, silent=True) or {}
    if data.get("send"):
        code = generate_otp(user.otp_secret)
        try:
            send_otp_email(user.email, code)
        except Exception:
            pass
        flask_session["alt_otp_sent"] = True
        return jsonify({"message": "OTP sent"})

    otp_input = data.get("otp", "")
    if not verify_otp(user.otp_secret, otp_input):
        return jsonify({"error": "Invalid OTP"}), 401
    flask_session.pop("pending_face_uid", None)
    flask_session.pop("face_purpose", None)
    user.face_fail_count = 0
    user.session_token = generate_session_token()
    db.session.commit()
    _record_login(user.email, True, user.id)
    login_user(user)
    return jsonify({"message": "Verified via OTP", "redirect": url_for("main.dashboard")})


@bp.route("/skip-alternatives/photo", methods=["POST"])
def skip_alternatives_photo():
    uid = flask_session.get("pending_face_uid")
    user = User.query.get(uid) if uid else None
    if not user:
        return jsonify({"error": "Session expired"}), 401
    if "photo" not in request.files:
        return jsonify({"error": "No photo uploaded"}), 400
    f = request.files["photo"]
    img_data = base64.b64encode(f.read()).decode()
    fv = FaceVerification(user_id=user.id, image_data=img_data, verified=False)
    db.session.add(fv)
    flask_session.pop("pending_face_uid", None)
    flask_session.pop("face_purpose", None)
    user.face_fail_count = 0
    user.session_token = generate_session_token()
    db.session.commit()
    _record_login(user.email, True, user.id)
    login_user(user)
    return jsonify({"message": "Photo submitted, logged in", "redirect": url_for("main.dashboard")})


@bp.route("/magic-link", methods=["POST"])
def send_magic_link():
    data = request.get_json(force=True, silent=True) or {}
    email = data.get("email", "").strip()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "If that email exists, a magic link has been sent."})
    token = secrets.token_urlsafe(48)
    user.login_token = token
    db.session.commit()
    from flask import url_for as fl_url
    link = f"https://talentos-simonpetercys-4786s-projects.vercel.app/auth/magic/{token}"
    from ..otp import send_otp_email as send_email
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(f"Click to log in: {link}\nThis link expires in 15 minutes.")
        msg["Subject"] = "TalentOS — Magic Login Link"
        msg["From"] = current_app.config.get("MAIL_USERNAME", "noreply@talentos.app")
        msg["To"] = email
        with smtplib.SMTP(current_app.config.get("MAIL_SERVER", "smtp.gmail.com"),
                          current_app.config.get("MAIL_PORT", 587), timeout=15) as s:
            s.starttls()
            s.login(current_app.config["MAIL_USERNAME"], current_app.config["MAIL_PASSWORD"])
            s.sendmail(msg["From"], [email], msg.as_string())
    except Exception as e:
        print(f"[SMTP] Magic link email to {email} failed: {e}")
    return jsonify({"message": "If that email exists, a magic link has been sent."})


@bp.route("/magic/<token>")
def magic_login(token):
    user = User.query.filter_by(login_token=token).first()
    if not user:
        flash("Invalid or expired magic link", "error")
        return redirect(url_for("auth.login"))
    user.login_token = ""
    user.session_token = generate_session_token()
    db.session.commit()
    login_user(user)
    _record_login(user.email, True, user.id)
    return redirect(url_for("main.dashboard"))
