from flask import Blueprint, jsonify, render_template
from flask_login import login_required, current_user
from ..models import Notification, db

bp = Blueprint("notifications", __name__, url_prefix="/notifications")


def add_notification(user_id, type, message, link=""):
    n = Notification(user_id=user_id, type=type, message=message, link=link)
    db.session.add(n)
    db.session.commit()


@bp.route("")
@login_required
def list_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc()).limit(50).all()
    return render_template("notifications/list.html", notifications=notifications, active="notifications")


@bp.route("/unread-count")
@login_required
def unread_count():
    count = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    return jsonify({"count": count})


@bp.route("/read/<int:id>", methods=["POST"])
@login_required
def mark_read(id):
    n = Notification.query.get_or_404(id)
    if n.user_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403
    n.read = True
    db.session.commit()
    return jsonify({"ok": True})


@bp.route("/read-all", methods=["POST"])
@login_required
def mark_all_read():
    Notification.query.filter_by(user_id=current_user.id, read=False).update({"read": True})
    db.session.commit()
    return jsonify({"ok": True})
