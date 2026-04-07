import sqlite3
import os

def calculate_risk_scores():

    import os

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(BASE_DIR, "..", "database", "itds.db")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""

    SELECT username,

    SUM(
        CASE severity
            WHEN 'LOW' THEN 1
            WHEN 'MEDIUM' THEN 2
            WHEN 'HIGH' THEN 3
            ELSE 0
        END
    ) as risk_score

    FROM alerts

    GROUP BY username

    ORDER BY risk_score DESC

    """)

    rows = cursor.fetchall()
    conn.close()

    result = []

    for r in rows:
        result.append({
            "username": r[0],
            "risk_score": r[1]
        })

    return result
