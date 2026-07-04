from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from ..models import Message, Conversation, ConversationParticipant, User, db
from datetime import datetime

bp = Blueprint("messages", __name__, url_prefix="/messages")


@bp.route("/")
@login_required
def list_conversations():
    participant_ids = (
        db.session.query(ConversationParticipant.conversation_id)
        .filter(ConversationParticipant.user_id == current_user.id)
        .subquery()
    )
    conversations = (
        Conversation.query.filter(Conversation.id.in_(participant_ids))
        .order_by(Conversation.updated_at.desc())
        .all()
    )
    return render_template(
        "messages/list.html",
        conversations=conversations,
        active="messages",
    )


@bp.route("/<int:id>")
@login_required
def view_conversation(id):
    conversation = Conversation.query.get_or_404(id)
    is_participant = ConversationParticipant.query.filter_by(
        conversation_id=id, user_id=current_user.id
    ).first()
    if not is_participant:
        flash("You are not a participant in this conversation.", "danger")
        return redirect(url_for("messages.list_conversations"))
    unread_messages = Message.query.filter_by(
        conversation_id=id, read=False
    ).filter(Message.sender_id != current_user.id).all()
    for msg in unread_messages:
        msg.read = True
    db.session.commit()
    messages = (
        Message.query.filter_by(conversation_id=id)
        .order_by(Message.created_at.asc())
        .all()
    )
    other_participant = (
        User.query
        .join(ConversationParticipant)
        .filter(ConversationParticipant.conversation_id == id, User.id != current_user.id)
        .first()
    )
    return render_template(
        "messages/chat.html",
        conversation=conversation,
        messages=messages,
        other=other_participant,
        active="messages",
    )


@bp.route("/<int:id>/send", methods=["POST"])
@login_required
def send_message(id):
    conversation = Conversation.query.get_or_404(id)
    is_participant = ConversationParticipant.query.filter_by(
        conversation_id=id, user_id=current_user.id
    ).first()
    if not is_participant:
        flash("You are not a participant in this conversation.", "danger")
        return redirect(url_for("messages.list_conversations"))
    content = request.form.get("content", "").strip()
    if not content:
        flash("Message cannot be empty.", "warning")
        return redirect(url_for("messages.view_conversation", id=id))
    message = Message(
        conversation_id=id,
        sender_id=current_user.id,
        content=content,
        read=False,
        created_at=datetime.utcnow(),
    )
    conversation.updated_at = datetime.utcnow()
    db.session.add(message)
    db.session.commit()
    return redirect(url_for("messages.view_conversation", id=id) + "#bottom")


@bp.route("/new/<int:user_id>", methods=["GET", "POST"])
@login_required
def new_conversation(user_id):
    if user_id == current_user.id:
        flash("You cannot start a conversation with yourself.", "warning")
        return redirect(url_for("messages.list_conversations"))
    recipient = User.query.get_or_404(user_id)
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        content = request.form.get("content", "").strip()
        if not content:
            flash("Message cannot be empty.", "warning")
            return render_template(
                "messages/new.html",
                recipient=recipient,
                active="messages",
            )
        conversation = Conversation(
            subject=subject or f"Conversation with {recipient.name}",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.session.add(conversation)
        db.session.flush()
        for uid in (current_user.id, user_id):
            participant = ConversationParticipant(
                conversation_id=conversation.id, user_id=uid
            )
            db.session.add(participant)
        message = Message(
            conversation_id=conversation.id,
            sender_id=current_user.id,
            content=content,
            read=False,
            created_at=datetime.utcnow(),
        )
        db.session.add(message)
        db.session.commit()
        flash("Conversation started.", "success")
        return redirect(url_for("messages.view_conversation", id=conversation.id))
    return render_template(
        "messages/new.html",
        recipient=recipient,
        active="messages",
    )


@bp.route("/start/<int:user_id>", methods=["POST"])
@login_required
def start_or_find_conversation(user_id):
    if user_id == current_user.id:
        return jsonify({"error": "Cannot chat with yourself"}), 400
    recipient = User.query.get_or_404(user_id)
    my_conv_ids = [p.conversation_id for p in ConversationParticipant.query.filter_by(user_id=current_user.id).all()]
    for cid in my_conv_ids:
        other = ConversationParticipant.query.filter_by(conversation_id=cid, user_id=user_id).first()
        if other:
            participants_count = ConversationParticipant.query.filter_by(conversation_id=cid).count()
            if participants_count == 2:
                return jsonify({"redirect": url_for("messages.view_conversation", id=cid)})
    conversation = Conversation(
        subject=f"Chat with {recipient.name}",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.session.add(conversation)
    db.session.flush()
    for uid in (current_user.id, user_id):
        participant = ConversationParticipant(conversation_id=conversation.id, user_id=uid)
        db.session.add(participant)
    db.session.commit()
    return jsonify({"redirect": url_for("messages.view_conversation", id=conversation.id)})
