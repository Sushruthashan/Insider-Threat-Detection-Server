from flask import Flask, request, jsonify, render_template
import sqlite3
from flask_socketio import SocketIO
from datetime import datetime
import os
import sys
import subprocess

# Fix import path for ML module
sys.path.append(os.path.abspath("../ml"))
from risk_scoring import calculate_risk_scores

# Fix Flask static + template folders
app = Flask(
    __name__,
    template_folder="../dashboard/templates",
    static_folder="../dashboard/static"
)

socketio = SocketIO(app, cors_allowed_origins="*")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "database", "itds.db")


# ---------------- DB FUNCTION ----------------
def insert_event(user, event_type, value):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO events (username, event_type, timestamp, value)
        VALUES (?, ?, ?, ?)
    """, (user, event_type, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), value))

    conn.commit()
    conn.close()


# ---------------- LOG RECEIVER ----------------
@app.route("/log", methods=["POST"])
def receive_log():
    data = request.get_json()
    user = data.get("user")
    event_type = data.get("event_type")
    value = data.get("value", "")
    
    print(f"[LOG RECEIVED] {user} | {event_type} | {value}")

    # 1. Save to DB
    insert_event(user, event_type, value)

    # 2. Optimized Trigger: Pass data as CLI arguments
    # sys.executable ensures we use the same python environment
    subprocess.Popen([
        sys.executable, 
        os.path.join(BASE_DIR, "../ml/anomaly_detector.py"),
        str(user), 
        str(event_type), 
        str(value)
    ])

    socketio.emit('new_log', {"user": user, "event": event_type})
    return jsonify({"status": "success"}), 200


# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    return render_template("index.html")


# ---------------- ALERTS ----------------
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


# ---------------- SYSTEM STATS ----------------
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

    return jsonify({
        "logins": logins,
        "files": files,
        "network": network
    })


# ---------------- RISK SCORES (ML) ----------------
@app.route("/risk_scores")
def get_risk_scores():
    data = calculate_risk_scores()
    return jsonify(data)

# ---------------- ALERTS OVER TIME ----------------
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

def cleanup_old_alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    DELETE FROM alerts
    WHERE timestamp < datetime('now', '-15 minutes')
    """)

    conn.commit()
    conn.close()


# ---------------- RUN SERVER ----------------
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
