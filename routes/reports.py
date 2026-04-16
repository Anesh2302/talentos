from flask import Blueprint, render_template, session, redirect, url_for, jsonify, send_file
from models.db import get_db
import json
import csv
from io import StringIO
from datetime import datetime

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/')
def index():
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    
    db = get_db()
    scans = db.execute(
        'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    
    return render_template('reports.html', scans=scans)

@reports_bp.route('/<int:scan_id>')
def view_report(scan_id):
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    
    db = get_db()
    scan = db.execute(
        'SELECT * FROM scans WHERE id = ? AND user_id = ?',
        (scan_id, session['user_id'])
    ).fetchone()
    
    if not scan:
        return "Report not found", 404
    
    results = json.loads(scan['results']) if scan['results'] else {}
    
    return render_template('report_detail.html', scan=scan, results=results)

@reports_bp.route('/<int:scan_id>/export')
def export_csv(scan_id):
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    
    db = get_db()
    scan = db.execute(
        'SELECT * FROM scans WHERE id = ? AND user_id = ?',
        (scan_id, session['user_id'])
    ).fetchone()
    
    if not scan:
        return "Report not found", 404
    
    results = json.loads(scan['results']) if scan['results'] else {}
    
    output = StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['Scan Report Export'])
    writer.writerow(['Target URL', scan['target_url']])
    writer.writerow(['Risk Score', scan['risk_score']])
    writer.writerow(['Scan Date', scan['created_at']])
    writer.writerow([])
    writer.writerow(['Vulnerabilities'])
    writer.writerow(['Module', 'Severity', 'Issue', 'Recommendation'])
    
    vulns = results.get('vulnerabilities', [])
    for vuln in vulns:
        writer.writerow([
            vuln.get('module', ''),
            vuln.get('severity', ''),
            vuln.get('issue', ''),
            vuln.get('recommendation', '')
        ])
    
    output.seek(0)
    return send_file(
        StringIO(output.getvalue()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"scan_report_{scan_id}.csv"
    )
