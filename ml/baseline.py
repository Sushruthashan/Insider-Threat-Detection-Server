import sqlite3
import pandas as pd
import json
import os

# ===============================
# DATABASE CONNECTION
# ===============================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "database", "itds.db"))

conn = sqlite3.connect(DB_PATH)

df = pd.read_sql_query("SELECT * FROM events", conn)

conn.close()

if df.empty:
    print("No logs found in database.")
    exit()

# ===============================
# PREPROCESSING
# ===============================

df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['day_of_week'] = df['timestamp'].dt.dayofweek  # Monday=0
df['date'] = df['timestamp'].dt.date

users = df['username'].unique()

baseline = {}

# ===============================
# STANDARD IT COMPANY SETTINGS
# ===============================

STANDARD_WORK_START = 8
STANDARD_WORK_END = 19
WORKING_DAYS = [0, 1, 2, 3, 4]  # Monday to Friday

# ===============================
# BUILD BASELINE PER USER
# ===============================

for user in users:

    user_df = df[df['username'] == user]

    # ----- Login Behaviour -----
    login_df = user_df[user_df['event_type'] == "login_activity"]

    if not login_df.empty:
        avg_login_hour = login_df['hour'].mean()
        login_std = login_df['hour'].std()
    else:
        avg_login_hour = None
        login_std = None

    # ----- File Activity -----
    file_df = user_df[user_df['event_type'].str.contains("file", case=False, na=False)]

    if not file_df.empty:
        files_per_hour = file_df.groupby(['date', 'hour']).size()
        avg_files_per_hour = files_per_hour.mean()
        file_std = files_per_hour.std()
    else:
        avg_files_per_hour = 0
        file_std = 0

    # ----- Weekend Activity -----
    weekend_activity = user_df[~user_df['day_of_week'].isin(WORKING_DAYS)]
    weekend_events_count = len(weekend_activity)

    # ----- Build User Baseline -----
    baseline[user] = {
        "standard_work_hours": {
            "start": STANDARD_WORK_START,
            "end": STANDARD_WORK_END
        },
        "average_login_hour": round(avg_login_hour, 2) if avg_login_hour else None,
        "login_hour_std": round(login_std, 2) if login_std else None,
        "average_files_per_hour": round(avg_files_per_hour, 2),
        "files_per_hour_std": round(file_std, 2) if file_std else 0,
        "weekend_activity_count": weekend_events_count
    }

# ===============================
# SAVE BASELINE
# ===============================

BASELINE_PATH = os.path.join(BASE_DIR, "baseline.json")

with open(BASELINE_PATH, "w") as f:
    json.dump(baseline, f, indent=4)

# ===============================
# PRINT RESULTS
# ===============================

print("\n========== BASELINE CREATED ==========\n")

for user, data in baseline.items():
    print(f"User: {user}")
    for key, value in data.items():
        print(f"   {key}: {value}")
    print()

print("Baseline saved to baseline.json\n")
