import sqlalchemy as sa
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()


def _migrate_schema(engine):
    if "postgresql" not in str(engine.url) and "postgres" not in str(engine.url):
        return
    inspector = sa.inspect(engine)
    for table in db.metadata.sorted_tables:
        tname = table.name
        existing = {c["name"] for c in inspector.get_columns(tname)}
        for col in table.columns:
            if col.name in existing or col.primary_key:
                continue
            nullable = "NULL" if col.nullable else "NOT NULL"
            default = col.default.arg if col.default else None
            col_type = _pg_type(col)
            default_clause = f" DEFAULT {default}" if default is not None else ""
            if default is not None:
                if isinstance(default, str):
                    default_clause = f" DEFAULT '{default}'"
                else:
                    default_clause = f" DEFAULT {default}"
            if col.foreign_keys:
                fk = next(iter(col.foreign_keys))
                ref = f"{fk.column.table.name}({fk.column.name})"
                db.session.execute(sa.text(
                    f'ALTER TABLE "{tname}" ADD COLUMN {col.name} {col_type} REFERENCES {ref}'
                ))
            else:
                db.session.execute(sa.text(
                    f'ALTER TABLE "{tname}" ADD COLUMN {col.name} {col_type}{default_clause} {nullable}'
                ))
        db.session.commit()


def _pg_type(col):
    t = col.type
    if isinstance(t, sa.Integer):
        return "INTEGER"
    if isinstance(t, sa.String):
        return f"VARCHAR({t.length or 255})"
    if isinstance(t, sa.Text):
        return "TEXT"
    if isinstance(t, sa.Boolean):
        return "BOOLEAN"
    if isinstance(t, sa.DateTime):
        return "TIMESTAMP"
    if isinstance(t, sa.Date):
        return "DATE"
    if isinstance(t, sa.Float):
        return "FLOAT"
    return "TEXT"


def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    if "postgres" in str(app.config.get("SQLALCHEMY_DATABASE_URI", "")):
        app.config.setdefault("SQLALCHEMY_ENGINE_OPTIONS", {
            "pool_pre_ping": True,
            "pool_recycle": 300,
            "connect_args": {"sslmode": "require"},
        })

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = ""
    login_manager.login_message_category = "info"

    from .routes import auth, main, admin, company, jobs, messages, applications, profile, social, notifications
    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(company.bp)
    app.register_blueprint(jobs.bp)
    app.register_blueprint(messages.bp)
    app.register_blueprint(applications.bp)
    app.register_blueprint(profile.bp)
    app.register_blueprint(social.bp)
    app.register_blueprint(notifications.bp)

    with app.app_context():
        db.create_all()
        _migrate_schema(db.engine)
        from werkzeug.security import generate_password_hash
        from .models import User
        simon = User.query.filter_by(email="simonpetercys@gmail.com").first()
        if simon:
            simon.role = "admin"
            simon.otp_enabled = True
            if not simon.otp_secret:
                from .otp import generate_secret
                simon.otp_secret = generate_secret()
            db.session.add(simon)
            db.session.commit()

    return app
