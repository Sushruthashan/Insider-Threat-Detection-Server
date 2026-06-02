from flask import Flask, request, jsonify, render_template
import sqlite3
from flask_socketio import SocketIO
from datetime import datetime
import os
import sys
import subprocess
import json

# ===============================
# PATH SETUP
# ===============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ML_PATH = os.path.normpath(os.path.join(BASE_DIR, "../ml"))
sys.path.append(ML_PATH)

from risk_scoring import calculate_risk_scores

# ===============================
# FLASK APP SETUP
# ===============================
app = Flask(
    __name__,
    template_folder="../dashboard/templates",
    static_folder="../dashboard/static"
)

socketio = SocketIO(app, cors_allowed_origins="*")

DB_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "database", "itds.db"))

# ===============================
# ANSI CODES
# ===============================
R      = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
WHITE  = "\033[97m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"

# ===============================
# TERMINAL LOGGING
# ===============================
SEP = f"{DIM}{'─' * 72}{R}"

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def print_banner():
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════════╗{R}")
    print(f"{BOLD}{CYAN}║         ITDS — Insider Threat Detection System  │  Server Active     ║{R}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════════════╝{R}\n")

def log_event(user, event_type, value):
    # Truncate long values for readability
    display_value = str(value)
    if len(display_value) > 60:
        display_value = display_value[:57] + "..."
    print(SEP)
    print(f"  {DIM}{ts()}{R}  {CYAN}{BOLD}{'EVENT':<18}{R}  "
          f"{WHITE}{user:<28}{R}  {BLUE}{event_type:<25}{R}")
    print(f"  {DIM}{'':>19}  value  :{R} {display_value}")

def log_alert(username, alert_type, details, severity):
    if severity == "HIGH":
        color, icon = RED,    "!!! ALERT"
    elif severity == "MEDIUM":
        color, icon = YELLOW, "!!  ALERT"
    else:
        color, icon = GREEN,  "!   ALERT"

    print(f"  {DIM}{ts()}{R}  {color}{BOLD}{icon:<18}{R}  "
          f"{WHITE}{username:<28}{R}  {color}{severity:<10}{R}  {alert_type}")
    print(f"  {DIM}{'':>19}  detail :{R} {details}")

def log_detector(line):
    print(f"  {DIM}{ts()}  {'':>5} detector :{R} {DIM}{line}{R}")

def log_error(context, message):
    print(f"  {DIM}{ts()}{R}  {RED}{BOLD}{'ERROR':<18}{R}  "
          f"{RED}[{context}]{R} {message}")

def log_info(message):
    print(f"  {DIM}{ts()}{R}  {MAGENTA}{'INFO':<18}{R}  {message}")

# ===============================
# DB INSERT: EVENT
# ===============================
def insert_event(user, event_type, value):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if isinstance(value, (dict, list)):
        value = json.dumps(value)
    else:
        value = str(value)

    user = user.strip().lower() if user else "unknown"

    cursor.execute("""
        INSERT INTO events (username, event_type, timestamp, value)
        VALUES (?, ?, ?, ?)
    """, (
        user,
        event_type,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        value
    ))

    conn.commit()
    conn.close()

# ===============================
# FETCH LATEST ALERT FOR DISPLAY
# ===============================
def fetch_latest_alert(user):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, alert_type, details, anomaly_score, severity
        FROM alerts
        WHERE username = ?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (user,))

    row = cursor.fetchone()
    conn.close()
    return row

# ===============================
# LOG RECEIVER
# ===============================
@app.route("/log", methods=["POST"])
def receive_log():
    data = request.get_json()

    user       = (data.get("user") or "").strip().lower()
    event_type = data.get("event_type")
    value      = data.get("value", "")

    log_event(user, event_type, value)

    try:
        insert_event(user, event_type, value)

        result = subprocess.run([
            sys.executable,
            os.path.join(BASE_DIR, "../ml/anomaly_detector.py"),
            str(user),
            str(event_type),
            str(value)
        ], capture_output=True, text=True, timeout=15)

        if result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                log_detector(line)

        if result.stderr.strip():
            for line in result.stderr.strip().splitlines():
                log_error("DETECTOR", line)

        latest = fetch_latest_alert(user)
        if latest:
            username, alert_type, details, anomaly_score, severity = latest
            log_alert(username, alert_type, details, severity)

        socketio.emit('new_log', {"user": user, "event": event_type})
        return jsonify({"status": "success"}), 200

    except subprocess.TimeoutExpired:
        log_error("DETECTOR", f"Subprocess timed out for user={user}")
        return jsonify({"status": "error", "message": "detector timeout"}), 500

    except Exception as e:
        log_error("SERVER", str(e))
        return jsonify({"status": "error", "message": str(e)}), 500

# ===============================
# DASHBOARD
# ===============================
@app.route("/")
def dashboard():
    return render_template("index.html")

# ===============================
# ALERTS
# ===============================
@app.route("/alerts")
def get_alerts():
    cleanup_old_alerts()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, alert_type, details, anomaly_score, severity, timestamp
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)

# ===============================
# SYSTEM STATS
# ===============================
@app.route("/system_stats")
def system_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM events WHERE event_type='login_activity'")
    logins = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events WHERE event_type LIKE '%file%'")
    files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events WHERE event_type='network_connection'")
    network = cursor.fetchone()[0]

    conn.close()
    return jsonify({"logins": logins, "files": files, "network": network})

# ===============================
# RISK SCORES
# ===============================
@app.route("/risk_scores")
def get_risk_scores():
    data = calculate_risk_scores()
    return jsonify(data)

# ===============================
# ALERTS OVER TIME
# ===============================
@app.route("/alerts_over_time")
def alerts_over_time():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT DATE(timestamp), COUNT(*)
        FROM alerts
        GROUP BY DATE(timestamp)
        ORDER BY DATE(timestamp)
    """)

    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)

# ===============================
# CLEANUP OLD ALERTS
# ===============================
def cleanup_old_alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM alerts
        WHERE timestamp < datetime('now', '-15 minutes')
    """)

    conn.commit()
    conn.close()

# ===============================
# RUN SERVER
# ===============================
if __name__ == "__main__":
    print_banner()
    log_info(f"DB path  : {DB_PATH}")
    log_info("Listening on 0.0.0.0:5000")
    print(SEP + "\n")
    socketio.run(app, host="0.0.0.0", port=5000)
