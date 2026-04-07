import sqlite3
import json
import os
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "../database/itds.db")
BASELINE_PATH = os.path.join(BASE_DIR, "baseline.json")

def load_baseline():
    with open(BASELINE_PATH, "r") as f:
        return json.load(f)

def insert_alert(username, alert_type, details, score):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Consistent Severity Mapping
    if score >= 5: severity = "HIGH"
    elif score >= 2: severity = "MEDIUM"
    else: severity = "LOW"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # ADDED 'details' column to the INSERT (your table schema likely has it)
    cursor.execute("""
    INSERT INTO alerts (username, alert_type, details, anomaly_score, severity, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (username, alert_type, details, score, severity, timestamp))

    conn.commit()
    conn.close()

# ... (inside the loop for user in df['username'].unique())

    # Fix for file anomaly math
    avg_files = base.get("average_files_per_hour", 0)
    std_files = base.get("files_per_hour_std", 0) or 1 # Avoid division by zero
    
    threshold = avg_files + (3 * std_files)

    if current_rate > threshold and current_rate > 5: # Added minimum noise floor
        score = (current_rate - avg_files) / std_files
        insert_alert(user, "High File Access", f"Rate: {current_rate}", round(score, 2))

def run_detection(user, event_type, value):
    baseline = load_baseline()
    if user not in baseline:
        return

    user_base = baseline[user]
    now = datetime.now()
    current_hour = now.hour

    # --- 1. Login Time Anomaly ---
    if event_type == "login_activity":
        avg_login = user_base.get("average_login_hour")
        if avg_login is not None:
            deviation = abs(current_hour - avg_login)
            if deviation > 3:
                score = round(deviation / 2, 2)
                insert_alert(user, "Login Time Anomaly", f"Logged in at {current_hour}:00", score)

    # --- 2. High File Access (Burst Detection) ---
    if "file" in event_type.lower():
        # Check how many files this user accessed in the last 60 seconds
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM events 
            WHERE username = ? AND event_type LIKE '%file%' 
            AND timestamp > datetime('now', '-1 minute')
        """, (user,))
        recent_count = cursor.fetchone()[0]
        conn.close()

        threshold = user_base["average_files_per_hour"] / 10 # heuristic for 1-minute burst
        if recent_count > threshold and recent_count > 5:
            score = round(recent_count / threshold, 2)
            insert_alert(user, "File Access Burst", f"{recent_count} files in 1 min", score)

if __name__ == "__main__":
    # Accept arguments from server.py
    if len(sys.argv) > 3:
        run_detection(sys.argv[1], sys.argv[2], sys.argv[3])
