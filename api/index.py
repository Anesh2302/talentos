import sys
import os
from urllib.parse import urlparse, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if os.environ.get("VERCEL"):
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url or db_url.startswith("sqlite:///"):
        pg_url = os.environ.get("POSTGRES_URL_NON_POOLING") or os.environ.get("POSTGRES_URL") or ""
        if pg_url:
            parsed = urlparse(pg_url)
            if parsed.scheme.startswith("postgres"):
                os.environ["DATABASE_URL"] = urlunparse(parsed._replace(scheme="postgresql"))
            else:
                os.environ["DATABASE_URL"] = "sqlite:////tmp/talentos.db"
        else:
            os.environ["DATABASE_URL"] = "sqlite:////tmp/talentos.db"
    if not os.environ.get("SECRET_KEY"):
        os.environ["SECRET_KEY"] = "talentos-vercel-fallback-key"

try:
    from talentos import create_app
    app = create_app()
except Exception as e:
    from flask import Flask, jsonify
    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def catch_all(path):
        return jsonify({"message": "Talentos API", "version": "1.0.0", "error": str(e), "status": "deploying"}), 200
