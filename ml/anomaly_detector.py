import sqlite3
import pandas as pd
import json
import os
from datetime import datetime

# ===============================
# PATHS
# ===============================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "../database/itds.db")
BASELINE_PATH = os.path.join(BASE_DIR, "baseline.json")
# anomaly_detector.py

# ===============================
# LOAD DATABASE
# ===============================

conn = sqlite3.connect(DB_PATH)
df = pd.read_sql_query("SELECT * FROM events", conn)
conn.close()

if df.empty:
    print("No data found.")
    exit()

def calculate_score(current_hour, baseline_hour, file_count, baseline_files):

    login_score = abs(current_hour - baseline_hour)

    file_score = file_count / baseline_files if baseline_files > 0 else 0

    score = login_score + file_score

    return score

def insert_alert(username, alert_type, details,  score):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if score > 5:
        severity = "HIGH"
    elif score > 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    cursor.execute("""
    INSERT INTO alerts (username, alert_type, anomaly_score, severity, timestamp)
    VALUES (?, ?, ?, ?, ?)
    """, (username, alert_type, score, severity, timestamp))

    conn.commit()
    conn.close()

# ===============================
# LOAD BASELINE
# ===============================

with open(BASELINE_PATH, "r") as f:
    baseline = json.load(f)

df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['date'] = df['timestamp'].dt.date

alerts = []

def display_alerts():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, alert_type, details, anomaly_score, timestamp
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()
    conn.close()

    print("\n========== ALERTS TABLE ==========\n")

    if not rows:
        print("No alerts stored.")
        return

    for row in rows:
        username, alert_type, details, score, timestamp = row

        print(f"User: {username}")
        print(f"Type: {alert_type}")
        print(f"Details: {details}")
        print(f"Score: {score}")
        print(f"Time: {timestamp}")
        print("----------------------------------")

# ===============================
# FEATURE ENGINEERING
# ===============================

for user in df['username'].unique():

    user_df = df[df['username'] == user]

    if user not in baseline:
        continue

    base = baseline[user]

    # -------- LOGIN ANOMALY --------
    login_df = user_df[user_df['event_type'] == "login_activity"]

    if not login_df.empty and base["average_login_hour"]:

        current_login_hour = login_df.iloc[-1]['hour']

        deviation = abs(current_login_hour - base["average_login_hour"])

        print("Deviation value:", deviation)
        print("Is deviation > 3 ?", deviation > 3)

        if deviation > 3:  # 3 hour deviation threshold
            score = deviation / 6
            insert_alert(
                user,
                "Login Time Anomaly",
                f"Login at {current_login_hour} deviates from baseline {base['average_login_hour']}",
                round(score, 2)
            )

    print("Latest login timestamp:", login_df.iloc[-1]['timestamp'])
    print("Latest login hour:", login_df.iloc[-1]['hour'])
    print("Baseline avg login hour:", base["average_login_hour"])

    # -------- FILE ANOMALY --------
    file_df = user_df[user_df['event_type'].str.contains("file", case=False, na=False)]

    if not file_df.empty:

        files_per_hour = file_df.groupby(['date', 'hour']).size()
        current_rate = files_per_hour.iloc[-1]

        threshold = base["average_files_per_hour"] + (3 * base["files_per_hour_std"])

        if current_rate > threshold:
            score = current_rate / threshold
            insert_alert(
                user,
                "High File Access Rate",
                f"{current_rate} files accessed. Threshold {round(threshold,2)}",
                round(score, 2)
	    )

def get_severity(score):

    if score < 1:
        return "LOW"

    elif score < 3:
        return "MEDIUM"

    else:
        return "HIGH"

# ===============================
# OUTPUT RESULTS
# ===============================

print("\nAnomaly detection completed.\n")
display_alerts()
