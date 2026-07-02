from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User
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


@bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not user.check_password(data["password"]):
        return jsonify({"error": "Invalid credentials"}), 401

    if user.is_locked():
        return jsonify({"error": "Account locked. Try again later."}), 423

    if not user.is_verified:
        code = generate_otp(user.otp_secret)
        send_otp_email(user.email, code)
        return jsonify({"error": "Email not verified. OTP resent."}), 403

    if user.otp_enabled:
        if not data.get("otp"):
            code = generate_otp(user.otp_secret)
            send_otp_email(user.email, code)
            return jsonify({"otp_required": True, "message": "OTP sent to email"})
        if not verify_otp(user.otp_secret, data["otp"]):
            user.record_failed_login()
            db.session.commit()
            return jsonify({"error": "Invalid OTP"}), 401

    user.login_attempts = 0
    db.session.commit()
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
    current_user.otp_enabled = True
    db.session.commit()
    return jsonify({"message": "OTP enabled", "secret": current_user.otp_secret})
