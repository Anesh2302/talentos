from flask import Flask, render_template_string

app = Flask(__name__)

LANDING = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Talentos — Recruitment Platform</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e1a;--surface:#111827;--border:#1e293b;--text:#e2e8f0;--muted:#64748b;--accent:#00d4ff;--green:#22c55e;--gold:#f59e0b}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{max-width:700px;padding:40px;text-align:center}
.logo{width:72px;height:72px;border-radius:18px;background:linear-gradient(135deg,var(--accent),var(--green));display:inline-flex;align-items:center;justify-content:center;font-size:1.6rem;font-weight:900;color:#000;margin-bottom:20px}
h1{font-size:2.2rem;font-weight:900;margin-bottom:8px}
h1 span{color:var(--accent)}
.sub{color:var(--muted);font-size:1rem;margin-bottom:30px;line-height:1.6}
.features{display:grid;grid-template-columns:1fr 1fr;gap:12px;text-align:left;margin-bottom:30px}
.feature{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px}
.feature h3{font-size:.85rem;font-weight:700;margin-bottom:4px}
.feature p{font-size:.75rem;color:var(--muted)}
.btn{display:inline-block;padding:14px 32px;border-radius:12px;font-weight:700;text-decoration:none;font-size:.9rem;margin:6px;transition:all .2s}
.btn-primary{background:var(--green);color:#000}.btn-primary:hover{background:#16a34a}
.btn-outline{border:1px solid var(--border);color:var(--muted)}.btn-outline:hover{border-color:var(--accent);color:var(--accent)}
.footer{margin-top:30px;font-size:.7rem;color:var(--muted)}
</style>
</head>
<body>
<div class="container">
  <div class="logo">T</div>
  <h1>Talent<span>os</span></h1>
  <p class="sub">Recruitment & Talent Management Platform<br>OTP verification, TOTP 2FA, role-based access, job management, messaging, social feed</p>
  <div class="features">
    <div class="feature"><h3>Job Management</h3><p>Post, search, filter, and apply to jobs with resume upload</p></div>
    <div class="feature"><h3>Face Recognition</h3><p>3-layer security with TOTP 2FA and face verification</p></div>
    <div class="feature"><h3>Social Feed</h3><p>Posts, comments, follows, and real-time messaging</p></div>
    <div class="feature"><h3>Admin Dashboard</h3><p>Analytics, security reports, user management, audit logs</p></div>
  </div>
  <a href="https://github.com/Anesh2302/talentos" target="_blank" class="btn btn-primary">View on GitHub</a>
  <a href="https://anesh2302.github.io/portfolio/" class="btn btn-outline">Back to Portfolio</a>
  <p class="footer">Built by Anesh G J — Flask + PostgreSQL + Face Recognition</p>
</div>
</body>
</html>"""

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def landing(path):
    return render_template_string(LANDING), 200
