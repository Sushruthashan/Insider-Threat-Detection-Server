import sqlite3
import json
import os
import sys
from datetime import datetime

# ===============================
# PATHS
# ===============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.normpath(os.path.join(BASE_DIR, "../database/itds.db"))
BASELINE_PATH = os.path.join(BASE_DIR, "baseline.json")

# ===============================
# HELPER FUNCTIONS
# ===============================

def load_baseline():
    if not os.path.exists(BASELINE_PATH):
        print(f"Baseline file missing at {BASELINE_PATH}")
        return {}
    with open(BASELINE_PATH, "r") as f:
        return json.load(f)

def insert_alert(username, alert_type, details, score):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Severity Mapping
    if score >= 5:
        severity = "HIGH"
    elif score >= 2:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO alerts (username, alert_type, details, anomaly_score, severity, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (username, alert_type, details, score, severity, timestamp))

    conn.commit()
    conn.close()

def recently_alerted(user, alert_type):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE username=? AND alert_type=?
        AND timestamp > datetime('now', '-2 minutes')
    """, (user, alert_type))

    count = cursor.fetchone()[0]
    conn.close()

    return count > 0

# ===============================
# DETECTION LOGIC
# ===============================

def run_detection(user, event_type, value):
    baseline = load_baseline()
    if user not in baseline:
        return

    user_base = baseline[user]
    now = datetime.now()
    current_hour = now.hour

    # ===============================
    # 1. LOGIN TIME ANOMALY
    # ===============================
    if event_type == "login_activity":
        avg_login = user_base.get("average_login_hour")
        if avg_login is not None:
            deviation = abs(current_hour - avg_login)

            if deviation > 3:
                score = round(deviation / 2, 2)

                if not recently_alerted(user, "Login Time Anomaly"):
                    insert_alert(
                        user,
                        "Login Time Anomaly",
                        f"Logged in at {current_hour}:00, baseline {avg_login}:00",
                        score
                    )

    # ===============================
    # 2. HIGH FILE ACCESS (BURST)
    # ===============================
    if "file" in event_type.lower():
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*) FROM events
            WHERE username=? AND event_type LIKE '%file%'
            AND timestamp > datetime('now', '-1 minute')
        """, (user,))
        recent_count = cursor.fetchone()[0]
        conn.close()

        avg_files = user_base.get("average_files_per_hour", 0)
        std_files = user_base.get("files_per_hour_std", 1) or 1

        threshold = (avg_files + (3 * std_files)) / 10
        threshold = max(5, threshold)

        if recent_count > threshold:
            score = round(recent_count / (threshold + 0.1), 2)

            if not recently_alerted(user, "High File Access Rate"):
                insert_alert(
                    user,
                    "High File Access Rate",
                    f"{recent_count} files in 1 min. Threshold {round(threshold,2)}",
                    score
                )

    # ===============================
    # 3. LOGIN FREQUENCY SPIKE
    # ===============================
    if event_type == "login_activity":
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*) FROM events
            WHERE username=? AND event_type='login_activity'
            AND timestamp > datetime('now', '-5 minutes')
        """, (user,))
        login_count = cursor.fetchone()[0]
        conn.close()

        if login_count > 10:
            score = 2.5

            if not recently_alerted(user, "Login Frequency Spike"):
                insert_alert(
                    user,
                    "Login Frequency Spike",
                    f"{login_count} logins in last 5 minutes",
                    score
                )

    # ===============================
    # 4. OFF-HOURS LOGIN
    # ===============================
    if event_type == "login_activity":
        if current_hour < 6 or current_hour > 22:

            if not recently_alerted(user, "Off-Hours Login"):
                insert_alert(
                    user,
                    "Off-Hours Login",
                    f"Login at unusual hour: {current_hour}:00",
                    4.5
                )

    # ===============================
    # 5. SENSITIVE FILE ACCESS
    # ===============================
    sensitive_keywords = ["password", "secret", "confidential", "admin", ".env"]

    if "file" in event_type.lower():
        for keyword in sensitive_keywords:
            if keyword in value.lower():

                if not recently_alerted(user, "Sensitive File Access"):
                    insert_alert(
                        user,
                        "Sensitive File Access",
                        f"Accessed sensitive file: {value}",
                        5.5
                    )
                break

    # ===============================
    # 6. POST-LOGIN FILE SURGE
    # ===============================
    if "file" in event_type.lower():
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp FROM events
            WHERE username=? AND event_type='login_activity'
            ORDER BY timestamp DESC LIMIT 1
        """, (user,))
        last_login = cursor.fetchone()

        if last_login:
            cursor.execute("""
                SELECT COUNT(*) FROM events
                WHERE username=? AND event_type LIKE '%file%'
                AND timestamp > ?
            """, (user, last_login[0]))

            file_count = cursor.fetchone()[0]
            conn.close()

            if file_count > 10:
                if not recently_alerted(user, "Post-Login File Surge"):
                    insert_alert(
                        user,
                        "Post-Login File Surge",
                        f"{file_count} files accessed after login",
                        4.8
                    )
        else:
            conn.close()

    # ===============================
    # 7. SUSPICIOUS MOUSE BEHAVIOR
    # ===============================
    if event_type == "mouse_activity":

        try:
            parts = value.split(",")
            clicks = int(parts[0].split(":")[1])
            moves = int(parts[1].split(":")[1])
        except:
            return

        # Condition 1: Too many clicks (possible automation)
        if clicks > 100:
            if not recently_alerted(user, "High Click Rate"):
                insert_alert(
                    user,
                    "High Click Rate",
                    f"{clicks} clicks in 10 seconds",
                    4.5
                )    

        # Condition 2: High activity but low movement (script behavior)
        if clicks > 50 and moves < 20:
            if not recently_alerted(user, "Scripted Interaction"):
                insert_alert(
                    user,
                    "Scripted Interaction",
                    f"{clicks} clicks but only {moves} movements",
                    5.0
                )

        # Condition 3: No user interaction but system activity (ghost activity)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*) FROM events
            WHERE username=? AND timestamp > datetime('now', '-10 seconds')
            AND event_type != 'mouse_activity'
         """, (user,))

        other_events = cursor.fetchone()[0]
        conn.close()

        if clicks == 0 and moves == 0 and other_events > 5:
            if not recently_alerted(user, "Background Activity Without Interaction"):
                insert_alert(
                    user,
                    "Background Activity Without Interaction",
                    f"{other_events} events without user interaction",
                    5.5
                )
    # ===============================
    # 8. FAILED LOGIN BURST (BRUTE FORCE)
    # ===============================
    if event_type == "failed_login":
       conn = sqlite3.connect(DB_PATH)
       cursor = conn.cursor()

       cursor.execute("""
           SELECT COUNT(*) FROM events
           WHERE username=? AND event_type='failed_login'
           AND timestamp > datetime('now', '-5 minutes')
       """, (user,))

       failed_count = cursor.fetchone()[0]
       conn.close()

       if failed_count >= 5:
           score = round(failed_count / 2, 2)

           if not recently_alerted(user, "Multiple Failed Logins"):
               insert_alert(
                   user,
                   "Multiple Failed Logins",
                   f"{failed_count} failed login attempts in 5 minutes",
                   score
               )

# ===============================
# ENTRY POINT
# ===============================

if __name__ == "__main__":
    if len(sys.argv) > 3:
        run_detection(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("Anomaly Detector: Not enough arguments provided.")
