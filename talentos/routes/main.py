from flask import Blueprint, jsonify
from flask_login import login_required, current_user

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return jsonify({"message": "Talentos API", "version": "1.0.0"})


@bp.route("/profile")
@login_required
def profile():
    return jsonify({
        "name": current_user.name,
        "email": current_user.email,
        "role": current_user.role,
        "verified": current_user.is_verified,
        "otp_enabled": current_user.otp_enabled,
    })
