from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    if ":" in user_id:
        uid, token = user_id.split(":", 1)
        user = User.query.get(int(uid))
        if user and user.session_token == token:
            return user
        return None
    return User.query.get(int(user_id))

def generate_session_token():
    import secrets
    return secrets.token_hex(32)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default="candidate")
    headline = db.Column(db.String(200), default="")
    summary = db.Column(db.Text, default="")
    location = db.Column(db.String(100), default="")
    phone = db.Column(db.String(20), default="")
    profile_pic = db.Column(db.String(500), default="")
    profile_pic_data = db.Column(db.Text, default="")
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=True)
    otp_secret = db.Column(db.String(32), default="")
    otp_enabled = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    face_descriptor = db.Column(db.Text, default="")
    face_image = db.Column(db.Text, default="")
    face_login_token = db.Column(db.String(64), default="")
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    session_token = db.Column(db.String(64), default="")
    login_token = db.Column(db.String(128), default="")
    linkedin = db.Column(db.String(500), default="")
    github = db.Column(db.String(500), default="")
    website = db.Column(db.String(500), default="")
    default_resume_data = db.Column(db.Text, default="")
    default_resume_filename = db.Column(db.String(200), default="")
    default_resume_mime = db.Column(db.String(100), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    face_verified = db.Column(db.Boolean, default=False)
    face_fail_count = db.Column(db.Integer, default=0)
    last_seen = db.Column(db.DateTime, nullable=True)

    company = db.relationship("Company", foreign_keys=[company_id], lazy=True)
    skills = db.relationship("UserSkill", lazy=True)

    def get_id(self):
        return f"{self.id}:{self.session_token}"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        self.login_attempts = 0
        self.locked_until = None
        return False

    def record_failed_login(self):
        self.login_attempts = (self.login_attempts or 0) + 1
        if self.login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)


class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20))
    resume_url = db.Column(db.String(500))
    status = db.Column(db.String(30), default="new")
    skills = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    department = db.Column(db.String(100))
    location = db.Column(db.String(100))
    status = db.Column(db.String(30), default="open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")
    status = db.Column(db.String(20), default="pending")
    priority = db.Column(db.String(10), default="medium")
    scheduled_time = db.Column(db.String(10), default="")
    due_date = db.Column(db.Date, nullable=True)
    reminder_sent = db.Column(db.Boolean, default=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    assignee = db.relationship("User", foreign_keys=[assigned_to], lazy=True)
    creator = db.relationship("User", foreign_keys=[created_by], lazy=True)


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(128), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", lazy=True)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at


class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    email = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), default="")
    user_agent = db.Column(db.String(500), default="")
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", lazy=True)


class BackupCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    code = db.Column(db.String(16), nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", lazy=True)


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    website = db.Column(db.String(200))
    logo_url = db.Column(db.String(500))
    industry = db.Column(db.String(100))
    location = db.Column(db.String(200))
    size = db.Column(db.String(50))
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    creator = db.relationship("User", foreign_keys=[created_by], lazy=True)
    jobs = db.relationship("JobPosting", backref="company", lazy=True)


class JobPosting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    requirements = db.Column(db.Text)
    location = db.Column(db.String(200))
    salary_min = db.Column(db.Integer)
    salary_max = db.Column(db.Integer)
    job_type = db.Column(db.String(50), default="full-time")
    experience_level = db.Column(db.String(50))
    skills_required = db.Column(db.Text)
    status = db.Column(db.String(20), default="open")
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    creator = db.relationship("User", foreign_keys=[created_by], lazy=True)


class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("job_posting.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    cover_letter = db.Column(db.Text)
    resume_url = db.Column(db.String(500))
    resume_data = db.Column(db.Text, default="")
    resume_filename = db.Column(db.String(200), default="")
    resume_mime = db.Column(db.String(50), default="")
    status = db.Column(db.String(30), default="applied")
    score = db.Column(db.Float, default=0.0)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    job = db.relationship("JobPosting", backref="applications", lazy=True)
    applicant = db.relationship("User", foreign_keys=[user_id], lazy=True)


class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


class UserSkill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    skill_id = db.Column(db.Integer, db.ForeignKey("skill.id"), nullable=False)
    proficiency = db.Column(db.String(20), default="intermediate")

    user = db.relationship("User", foreign_keys=[user_id], lazy=True, overlaps="skills")
    skill = db.relationship("Skill", lazy=True)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200))
    job_id = db.Column(db.Integer, db.ForeignKey("job_posting.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    job = db.relationship("JobPosting", lazy=True)


class ConversationParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    conversation = db.relationship("Conversation", lazy=True)
    user = db.relationship("User", lazy=True)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    conversation = db.relationship("Conversation", backref="messages", lazy=True)
    sender = db.relationship("User", foreign_keys=[sender_id], lazy=True)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", foreign_keys=[user_id], lazy=True)
    likes = db.relationship("PostLike", backref="post", lazy=True)
    comments = db.relationship("Comment", backref="post", lazy=True)


class PostLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", foreign_keys=[user_id], lazy=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", foreign_keys=[user_id], lazy=True)


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    follower = db.relationship("User", foreign_keys=[follower_id], lazy=True)
    followed = db.relationship("User", foreign_keys=[followed_id], lazy=True)


class SavedJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey("job_posting.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", foreign_keys=[user_id], lazy=True)
    job = db.relationship("JobPosting", lazy=True)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    type = db.Column(db.String(50), default="info")
    message = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(500), default="")
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", foreign_keys=[user_id], lazy=True)


class CompanyReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=False)
    rating = db.Column(db.Integer, default=5)
    title = db.Column(db.String(200), default="")
    content = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", foreign_keys=[user_id], lazy=True)
    company_rel = db.relationship("Company", lazy=True)


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    type = db.Column(db.String(50), default="action")
    description = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(500), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", foreign_keys=[user_id], lazy=True)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    target_type = db.Column(db.String(50), default="")
    target_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", foreign_keys=[user_id], lazy=True)


class Interview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey("application.id"), nullable=False)
    scheduled_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(30), default="scheduled")
    notes = db.Column(db.Text, default="")
    location = db.Column(db.String(200), default="")
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    application = db.relationship("Application", lazy=True)
    creator = db.relationship("User", foreign_keys=[created_by], lazy=True)


class FaceVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    face_encoding = db.Column(db.Text, default="")
    image_data = db.Column(db.Text, default="")
    liveness_score = db.Column(db.Float, default=0.0)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", foreign_keys=[user_id], lazy=True)
