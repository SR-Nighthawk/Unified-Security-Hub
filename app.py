import os, time, json
from pathlib import Path
from flask import Flask, render_template, jsonify, redirect, url_for
from backend.extensions import db, socketio
from backend.models import APTGroup, GroupLink, LinkStatusHistory, DiscoveryLog
from backend.apt_worker import start_scheduler
from backend.core.config import DEFAULT_ZAP_PATH, REPORTS_DIR, CHATS_DIR
from backend.core.tasks import SCAN_TASKS
from backend.core.helpers import get_report_data

# Dark Web Logic
from backend.dark_web_logic.routes import dark_web_bp

# VAPT Modules
from backend.modules.nmap_module import nmap_bp as network_scanner_bp
from backend.modules.zap_module import zap_bp as web_scanner_bp
from backend.modules.ai_module import ai_bp
from backend.modules.analytics_module import analytics_bp
from backend.modules.pentest_module import pentest_bp
from backend.modules.ransomware_module import ransomware_bp

app = Flask(__name__, template_folder='frontend/templates', static_folder='frontend/static')

# Database Setup — use absolute path relative to project root (not CWD)
# This ensures the DB is found correctly in Docker, Gunicorn, and dev
BASE_DIR = Path(__file__).resolve().parent
db_path = BASE_DIR / 'database' / 'apt_intel.db'
db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
# Ensure directory is writable
import os
os.chmod(db_path.parent, 0o755)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "super-secret-default-key-dev-only")

db.init_app(app)
socketio.init_app(app)

from backend.extensions import login_manager
login_manager.init_app(app)

from backend.models import User
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Register Blueprints
from backend.modules.auth_module import auth_bp
app.register_blueprint(auth_bp)
app.register_blueprint(dark_web_bp)
app.register_blueprint(network_scanner_bp)
app.register_blueprint(web_scanner_bp)
app.register_blueprint(ai_bp)
app.register_blueprint(analytics_bp)
app.register_blueprint(pentest_bp)
app.register_blueprint(ransomware_bp)

# Background scheduler for DarkWeb
start_scheduler(app)

# Wrap Blueprint routes centrally (optional, instead applying @login_required at handler level inside views or app layer)
from flask_login import login_required, current_user

# ═══════════════════════════════════════════════════════
# Global Routes (Unified Dashboard)
# ═══════════════════════════════════════════════════════

# Inject current_user into all templates
@app.context_processor
def inject_user():
    return dict(current_user=current_user)

@app.route("/")
def landing_page():
    if current_user.is_authenticated:
        return render_template("dashboard.html")
    return render_template("landing.html")

@app.route("/login")
def login_page_redirect():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('auth.html')

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/network-scanner")
@login_required
def network_scanner_page():
    return render_template("vapt_views/nmap.html")

@app.route("/web-scanner")
@login_required
def web_scanner_page():
    return render_template("vapt_views/zap.html", default_zap_path=DEFAULT_ZAP_PATH)

@app.route("/ai-chat")
@login_required
def ai_chat_page():
    return render_template("vapt_views/ai_chat.html")

@app.route("/ransomware")
@login_required
def ransomware_page():
    return render_template("ransomware_views/dashboard.html")

@app.route("/ai-pentest")
@login_required
def ai_pentest_page():
    return render_template("pentest_views/pentest.html")

@app.route("/ai-pentest/report/<session_id>")
@login_required
def pentest_report_page(session_id):
    return render_template("pentest_views/pentest_report.html", session_id=session_id)

@app.route("/reports")
@login_required
def reports_history():
    reports = []
    # Fetch VAPT Reports
    for f in REPORTS_DIR.glob("*.json"):
        try:
            data = get_report_data(f.stem)
            if data and data.get("owner_id") == current_user.id:
                reports.append({
                    "id": f.stem,
                    "tool": data.get("tool", "Unknown"),
                    "target": data.get("data", {}).get("target", "Unknown"),
                    "time": time.ctime(f.stat().st_mtime)
                })
        except: pass
    reports.sort(key=lambda x: x["time"], reverse=True)
    return render_template("vapt_views/reports.html", reports=reports)

@app.route("/report/<report_id>")
@login_required
def view_report(report_id):
    data = get_report_data(report_id)
    if not data or data.get('owner_id') != current_user.id: 
        return "Report not found or access denied", 404
    return render_template("vapt_views/report.html", scan_tool=data.get("tool"), data=data.get("data"))

@app.route("/api/report-data/<report_id>")
@login_required
def get_report_json(report_id):
    data = get_report_data(report_id)
    if not data: return jsonify({"success": False, "error": "Report not found"}), 404
    return jsonify({"success": True, "data": data})

@app.route("/api/task-status/<task_id>")
def get_task_status(task_id):
    task = SCAN_TASKS.get(task_id)
    if not task: return jsonify({"success": False, "error": "Task not found"}), 404
    return jsonify({"success": True, "data": task})

# ═══════════════════════════════════════════════════════
# Dashboard Stats API
# ═══════════════════════════════════════════════════════

@app.route("/api/dashboard-stats")
@login_required
def dashboard_stats():
    """Returns real-time stats for the main dashboard."""
    # Count reports
    total_scans = 0
    recent_scans = []
    for f in REPORTS_DIR.glob("*.json"):
        try:
            data = get_report_data(f.stem)
            if data and data.get("owner_id") == current_user.id:
                total_scans += 1
                recent_scans.append({
                    "id": f.stem,
                    "tool": data.get("tool", "Unknown"),
                    "target": data.get("data", {}).get("target", "Unknown"),
                    "time": time.ctime(f.stat().st_mtime)
                })
        except: pass
    recent_scans.sort(key=lambda x: x["time"], reverse=True)

    # APT stats
    apt_groups = APTGroup.query.count()
    active_links = GroupLink.query.filter_by(status='ACTIVE').count()

    # AI sessions
    ai_sessions = 0
    try:
        ai_sessions = len(list(CHATS_DIR.glob("*.json")))
    except: pass

    # APT feed (top 10 groups)
    apt_feed = []
    groups = APTGroup.query.limit(10).all()
    for g in groups:
        active = sum(1 for l in g.links if l.status == 'ACTIVE')
        apt_feed.append({
            "id": g.id,
            "name": g.name,
            "country": g.origin_country or "Unknown",
            "threat": g.threat_level or "MEDIUM",
            "links": len(g.links),
            "active": active > 0
        })

    return jsonify({
        "total_scans": total_scans,
        "apt_groups": apt_groups,
        "active_links": active_links,
        "ai_sessions": ai_sessions,
        "recent_scans": recent_scans[:5],
        "apt_feed": apt_feed
    })

# ═══════════════════════════════════════════════════════════════
# WSGI Export for Gunicorn
# ═══════════════════════════════════════════════════════════════
# Gunicorn imports this as `app:app`
application = app

if __name__ == "__main__":
    # Local development: run with Flask's built-in server
    # Production: use `gunicorn --config gunicorn.conf.py app:app`
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
