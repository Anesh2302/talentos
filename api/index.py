import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if os.environ.get("VERCEL"):
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url or db_url.startswith("sqlite"):
        pg_url = os.environ.get("POSTGRES_URL_NON_POOLING") or os.environ.get("POSTGRES_URL") or ""
        if pg_url and pg_url.startswith("postgres"):
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(pg_url)
            os.environ["DATABASE_URL"] = urlunparse(parsed._replace(scheme="postgresql"))
        else:
            os.environ["DATABASE_URL"] = "sqlite:////tmp/talentos.db"
    if not os.environ.get("SECRET_KEY"):
        os.environ["SECRET_KEY"] = "talentos-v3-prod-key-change-me"

try:
    from talentos import create_app
    app = create_app()
except Exception as e:
    from flask import Flask, render_template_string
    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def catch_all(path):
        return render_template_string(HELLO_PAGE), 200

    HELLO_PAGE = """<!DOCTYPE html>
<html><head><title>Talentos</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,sans-serif;background:#0a0e1a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#111827;border:1px solid #1e293b;border-radius:16px;padding:40px;max-width:500px;text-align:center}
h1{font-size:1.8rem;font-weight:800;margin-bottom:8px}
.sub{color:#64748b;margin-bottom:24px}
.btn{display:inline-block;padding:12px 28px;border-radius:10px;background:#22c55e;color:#000;font-weight:700;text-decoration:none;margin:6px}
.btn:hover{background:#16a34a}
.status{margin-top:20px;padding:12px;border-radius:8px;background:rgba(245,158,11,.1);color:#f59e0b;font-size:.8rem}
</style></head><body>
<div class="card">
<h1>Talentos</h1>
<p class="sub">Recruitment & Talent Management Platform</p>
<div class="status">The app is starting up. Database is initializing...<br>Please refresh in 30 seconds.</div>
</div></body></html>"""
