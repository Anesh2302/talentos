import secrets
import json
import math
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User, PasswordResetToken, LoginHistory, BackupCode, generate_session_token
from ..otp import generate_secret, generate_otp, verify_otp, send_otp_email
from .. import db

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(force=True, silent=True)
    if not data or "email" not in data:
        return jsonify({"error": "Invalid JSON body"}), 400
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already registered"}), 400

    user = User(
        email=data["email"],
        name=data["name"],
        role=data.get("role", "candidate"),
        otp_secret=generate_secret(),
        is_verified=True,
    )
    user.set_password(data["password"])
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

    if not user.otp_secret:
        user.otp_secret = generate_secret()
        db.session.commit()

    otp_input = data.get("otp")
    backup_input = data.get("backup_code")

    if not otp_input and not backup_input:
        code = generate_otp(user.otp_secret)
        send_otp_email(user.email, code)
        return jsonify({"otp_required": True, "message": "OTP sent to email", "code": code})

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
        user.face_login_token = generate_session_token()
        db.session.commit()
        return jsonify({
            "face_required": True,
            "face_token": user.face_login_token,
            "message": "Face verification required"
        })

    user.session_token = generate_session_token()
    db.session.commit()
    _record_login(user.email, True, user.id)
    login_user(user)
    return jsonify({"message": "Login successful", "user": user.name})


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login_page"))


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


@bp.route("/face-login")
def face_login_page():
    return render_template("face_login.html")


@bp.route("/face/enroll", methods=["POST"])
@login_required
def face_enroll():
    data = request.get_json(force=True, silent=True)
    if not data or "descriptor" not in data:
        return jsonify({"error": "No face data provided"}), 400
    current_user.face_descriptor = json.dumps(data["descriptor"])
    current_user.face_image = data.get("image", "")
    db.session.commit()
    return jsonify({"message": "Face registered successfully"})


@bp.route("/face/status")
@login_required
def face_status():
    return jsonify({"enrolled": bool(current_user.face_descriptor)})


@bp.route("/face/verify", methods=["POST"])
def face_verify():
    data = request.get_json(force=True, silent=True)
    if not data or "descriptor" not in data:
        return jsonify({"error": "No face data"}), 400
    descriptor = data["descriptor"]
    email = data.get("email", "").strip()
    user = User.query.filter_by(email=email).first() if email else None
    if not user or not user.face_descriptor:
        return jsonify({"error": "No face registered for this account", "match": False})

    stored = json.loads(user.face_descriptor)
    score = cosine_similarity(descriptor, stored)
    threshold = data.get("threshold", 0.5)
    match = score >= threshold

    if match:
        return jsonify({"match": True, "score": round(score, 3), "user_id": user.id, "name": user.name})
    return jsonify({"match": False, "score": round(score, 3)})


@bp.route("/face/complete-login", methods=["POST"])
def face_complete_login():
    data = request.get_json(force=True, silent=True)
    if not data or "descriptor" not in data or "email" not in data or "face_token" not in data:
        return jsonify({"error": "Missing face data, email, or token"}), 400
    user = User.query.filter_by(email=data["email"].strip()).first()
    if not user or not user.face_descriptor:
        return jsonify({"error": "No face registered"}), 401
    if user.face_login_token != data["face_token"]:
        return jsonify({"error": "Invalid or expired face token"}), 401
    stored = json.loads(user.face_descriptor)
    score = cosine_similarity(data["descriptor"], stored)
    if score < 0.5:
        return jsonify({"match": False, "error": "Face does not match", "score": round(score, 3)}), 401
    user.face_login_token = ""
    user.session_token = generate_session_token()
    db.session.commit()
    _record_login(user.email, True, user.id)
    login_user(user)
    return jsonify({"match": True, "message": "Login successful", "user": user.name})


@bp.route("/face/login", methods=["POST"])
def face_login():
    data = request.get_json(force=True, silent=True)
    if not data or "descriptor" not in data or "email" not in data:
        return jsonify({"error": "Missing face data or email"}), 400
    descriptor = data["descriptor"]
    user = User.query.filter_by(email=data["email"].strip()).first()
    if not user or not user.face_descriptor:
        return jsonify({"error": "No face registered", "match": False}), 401
    stored = json.loads(user.face_descriptor)
    score = cosine_similarity(descriptor, stored)
    if score >= 0.5:
        user.session_token = generate_session_token()
        db.session.commit()
        login_user(user)
        return jsonify({"match": True, "message": "Face login successful", "user": user.name})
    return jsonify({"match": False, "error": "Face does not match", "score": round(score, 3)}), 401
