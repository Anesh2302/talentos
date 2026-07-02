from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask_login import login_required, current_user
from ..models import db, Post, PostLike, Comment, Follow, User

bp = Blueprint("social", __name__, url_prefix="/social")


@bp.route("/feed")
@login_required
def feed():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("social/feed.html", posts=posts, active="social")


@bp.route("/post", methods=["POST"])
@login_required
def create_post():
    data = request.get_json(force=True, silent=True)
    if not data or not data.get("content", "").strip():
        return jsonify({"error": "Content is required"}), 400
    post = Post(user_id=current_user.id, content=data["content"].strip(), image_url=data.get("image_url", ""))
    db.session.add(post)
    db.session.commit()
    return jsonify({"message": "Post created", "id": post.id})


@bp.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    db.session.delete(post)
    db.session.commit()
    return jsonify({"message": "Post deleted"})


@bp.route("/post/<int:post_id>/like", methods=["POST"])
@login_required
def toggle_like(post_id):
    post = Post.query.get_or_404(post_id)
    existing = PostLike.query.filter_by(post_id=post_id, user_id=current_user.id).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        return jsonify({"liked": False, "count": PostLike.query.filter_by(post_id=post_id).count()})
    like = PostLike(post_id=post_id, user_id=current_user.id)
    db.session.add(like)
    db.session.commit()
    return jsonify({"liked": True, "count": PostLike.query.filter_by(post_id=post_id).count()})


@bp.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    data = request.get_json(force=True, silent=True)
    if not data or not data.get("content", "").strip():
        return jsonify({"error": "Comment content is required"}), 400
    comment = Comment(post_id=post_id, user_id=current_user.id, content=data["content"].strip())
    db.session.add(comment)
    db.session.commit()
    return jsonify({
        "message": "Comment added",
        "comment": {
            "id": comment.id,
            "content": comment.content,
            "user": {"name": current_user.name, "id": current_user.id},
            "created_at": comment.created_at.isoformat()
        }
    })


@bp.route("/user/<int:user_id>/follow", methods=["POST"])
@login_required
def toggle_follow(user_id):
    if user_id == current_user.id:
        return jsonify({"error": "Cannot follow yourself"}), 400
    target = User.query.get_or_404(user_id)
    existing = Follow.query.filter_by(follower_id=current_user.id, followed_id=user_id).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        return jsonify({"following": False})
    follow = Follow(follower_id=current_user.id, followed_id=user_id)
    db.session.add(follow)
    db.session.commit()
    return jsonify({"following": True})


@bp.route("/users")
@login_required
def user_list():
    users = User.query.filter(User.id != current_user.id).order_by(User.name).all()
    following_ids = {f.followed_id for f in Follow.query.filter_by(follower_id=current_user.id).all()}
    return render_template("social/users.html", users=users, following_ids=following_ids, active="social")


@bp.route("/user/<int:user_id>")
@login_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    posts = Post.query.filter_by(user_id=user_id).order_by(Post.created_at.desc()).all()
    follower_count = Follow.query.filter_by(followed_id=user_id).count()
    following_count = Follow.query.filter_by(follower_id=user_id).count()
    is_following = Follow.query.filter_by(follower_id=current_user.id, followed_id=user_id).first() is not None
    return render_template("social/user_profile.html", user=user, posts=posts,
        follower_count=follower_count, following_count=following_count, is_following=is_following, active="social")