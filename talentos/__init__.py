import logging, sys
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, force=True)

from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()


def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    login_manager.login_view = "auth.login"

    @app.before_request
    def log_request():
        if request.method == "POST":
            import logging
            ct = request.content_type or "none"
            cl = request.content_length or -1
            logging.getLogger("app").info(f"POST {request.path} ct={ct} cl={cl}")

    @app.errorhandler(500)
    def handle_500(e):
        import traceback, logging
        tb = traceback.format_exc()
        logging.getLogger("app").error(f"500 on {request.method} {request.path}:\n{tb}")
        return {"error": "Internal server error"}, 500

    from .routes import auth, main, admin, company, jobs, messages, applications, profile
    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(company.bp)
    app.register_blueprint(jobs.bp)
    app.register_blueprint(messages.bp)
    app.register_blueprint(applications.bp)
    app.register_blueprint(profile.bp)

    with app.app_context():
        db.create_all()

    return app
