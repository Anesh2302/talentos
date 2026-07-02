import secrets
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User, PasswordResetToken, LoginHistory, BackupCode
from ..otp import generate_secret, generate_otp, verify_otp, send_otp_email
from .. import db

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already registered"}), 400

    user = User(
        email=data["email"],
        name=data["name"],
        role=data.get("role", "candidate"),
        otp_secret=generate_secret(),
    )
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()

    code = generate_otp(user.otp_secret)
    send_otp_email(user.email, code)
    return jsonify({"message": "Registered. Check email for OTP.", "user_id": user.id}), 201


@bp.route("/verify-email", methods=["POST"])
def verify_email():
    data = request.get_json()
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


@bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not user.check_password(data["password"]):
        _record_login(data.get("email", "?"), False)
        return jsonify({"error": "Invalid credentials"}), 401

    if user.is_locked():
        _record_login(user.email, False, user.id)
        return jsonify({"error": "Account locked. Try again later."}), 423

    if not user.is_verified:
        code = generate_otp(user.otp_secret)
        send_otp_email(user.email, code)
        _record_login(user.email, False, user.id)
        return jsonify({"error": "Email not verified. OTP resent."}), 403

    if user.otp_enabled:
        otp_input = data.get("otp")
        backup_input = data.get("backup_code")

        if not otp_input and not backup_input:
            code = generate_otp(user.otp_secret)
            send_otp_email(user.email, code)
            return jsonify({"otp_required": True, "message": "OTP sent to email"})

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
    db.session.commit()
    _record_login(user.email, True, user.id)
    login_user(user)
    return jsonify({"message": "Login successful", "user": user.name})


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out"})


@bp.route("/setup-otp", methods=["POST"])
@login_required
def setup_otp():
    data = request.get_json() or {}
    if data.get("password") and not current_user.check_password(data["password"]):
        return jsonify({"error": "Invalid password"}), 401
    current_user.otp_enabled = True
    current_user.otp_secret = generate_secret()
    db.session.commit()
    return jsonify({"message": "OTP enabled", "secret": current_user.otp_secret})


@bp.route("/disable-otp", methods=["POST"])
@login_required
def disable_otp():
    data = request.get_json() or {}
    if not data.get("password") or not current_user.check_password(data["password"]):
        return jsonify({"error": "Invalid password"}), 401
    current_user.otp_enabled = False
    db.session.commit()
    return jsonify({"message": "OTP disabled"})


@bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
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
    data = request.get_json()
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
    data = request.get_json() or {}
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
    data = request.get_json() or {}
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
