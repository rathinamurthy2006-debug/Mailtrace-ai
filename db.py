import psycopg2
from datetime import datetime

DB_CONFIG = {
    "dbname": "mailtrace_db",
    "user": "mailtrace",
    "password": "mailtrace123",
    "host": "localhost",
    "port": "5432",
}


def init_db():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id SERIAL PRIMARY KEY,
                case_id TEXT UNIQUE NOT NULL,
                original_filename TEXT,
                risk_score INTEGER,
                threat_category TEXT,
                ips TEXT,
                evidence_sha256 TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Database init failed (app will continue without DB): {e}")


def save_case(case_id, original_filename, risk_score, threat_category, ips, evidence_sha256):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO cases (case_id, original_filename, risk_score, threat_category, ips, evidence_sha256)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (case_id) DO NOTHING;
            """,
            (case_id, original_filename, risk_score, threat_category, ", ".join(ips), evidence_sha256),
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"Case {case_id} saved to PostgreSQL.")
    except Exception as e:
        print(f"Warning: could not save case to PostgreSQL: {e}")
