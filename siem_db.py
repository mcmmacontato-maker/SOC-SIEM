"""
siem_db.py — Camada de persistência SQLite do SIEM
Gerencia eventos, alertas e incidentes.
"""
import sqlite3
import os
import json
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "siem.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            source_ip   TEXT,
            dest_ip     TEXT,
            event_type  TEXT NOT NULL,
            severity    TEXT NOT NULL DEFAULT 'INFO',
            category    TEXT,
            raw         TEXT,
            metadata    TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            rule_name   TEXT NOT NULL,
            description TEXT,
            severity    TEXT NOT NULL,
            source_ip   TEXT,
            event_ids   TEXT,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            status      TEXT NOT NULL DEFAULT 'OPEN',
            incident_id INTEGER
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL,
            title        TEXT NOT NULL,
            severity     TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'OPEN',
            alert_ids    TEXT,
            playbook     TEXT,
            timeline     TEXT,
            analyst      TEXT DEFAULT 'SOC-Bot',
            report       TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    """)
    conn.commit()
    conn.close()


def insert_event(timestamp, source_ip, dest_ip, event_type, severity, category, raw, metadata=None):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO events (timestamp, source_ip, dest_ip, event_type, severity, category, raw, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, source_ip, dest_ip, event_type, severity, category, raw,
         json.dumps(metadata) if metadata else None)
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def insert_alert(rule_name, description, severity, source_ip, event_ids, mitre_tactic, mitre_technique):
    conn = get_conn()
    cur = conn.cursor()
    ts = datetime.now(timezone.utc).isoformat()
    cur.execute(
        "INSERT INTO alerts (timestamp, rule_name, description, severity, source_ip, event_ids, mitre_tactic, mitre_technique) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, rule_name, description, severity, source_ip,
         json.dumps(event_ids), mitre_tactic, mitre_technique)
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def insert_incident(title, severity, alert_ids, playbook, timeline):
    conn = get_conn()
    cur = conn.cursor()
    ts = datetime.now(timezone.utc).isoformat()
    cur.execute(
        "INSERT INTO incidents (created_at, updated_at, title, severity, alert_ids, playbook, timeline) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, ts, title, severity, json.dumps(alert_ids), playbook, json.dumps(timeline))
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def update_incident_report(incident_id, report_md):
    conn = get_conn()
    cur = conn.cursor()
    ts = datetime.now(timezone.utc).isoformat()
    cur.execute(
        "UPDATE incidents SET report=?, updated_at=? WHERE id=?",
        (report_md, ts, incident_id)
    )
    conn.commit()
    conn.close()


def update_alert_incident(alert_id, incident_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE alerts SET incident_id=?, status='ESCALATED' WHERE id=?", (incident_id, alert_id))
    conn.commit()
    conn.close()


def get_recent_events(limit=100, offset=0):
    conn = get_conn()
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_events_by_ip(ip, minutes=5):
    conn = get_conn()
    cur = conn.cursor()
    cutoff = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    rows = cur.execute(
        "SELECT * FROM events WHERE source_ip=? AND timestamp >= ? ORDER BY timestamp DESC",
        (ip, cutoff[:16])
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alerts(status=None, limit=50):
    conn = get_conn()
    cur = conn.cursor()
    if status:
        rows = cur.execute(
            "SELECT * FROM alerts WHERE status=? ORDER BY timestamp DESC LIMIT ?", (status, limit)
        ).fetchall()
    else:
        rows = cur.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_incidents(limit=20):
    conn = get_conn()
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_incident(incident_id):
    conn = get_conn()
    cur = conn.cursor()
    row = cur.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_stats():
    conn = get_conn()
    cur = conn.cursor()

    total_events = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    active_alerts = cur.execute("SELECT COUNT(*) FROM alerts WHERE status='OPEN'").fetchone()[0]
    open_incidents = cur.execute("SELECT COUNT(*) FROM incidents WHERE status='OPEN'").fetchone()[0]

    events_last_min = cur.execute(
        "SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now','-1 minute')"
    ).fetchone()[0]

    top_ips = cur.execute(
        "SELECT source_ip, COUNT(*) as cnt FROM events WHERE source_ip IS NOT NULL "
        "GROUP BY source_ip ORDER BY cnt DESC LIMIT 5"
    ).fetchall()

    top_attack_types = cur.execute(
        "SELECT event_type, COUNT(*) as cnt FROM events "
        "GROUP BY event_type ORDER BY cnt DESC LIMIT 6"
    ).fetchall()

    alerts_by_sev = cur.execute(
        "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
    ).fetchall()

    # events per minute for last 15 minutes
    events_timeline = cur.execute(
        """
        SELECT strftime('%H:%M', timestamp) as minute, COUNT(*) as cnt
        FROM events
        WHERE timestamp >= datetime('now', '-15 minutes')
        GROUP BY minute
        ORDER BY minute
        """
    ).fetchall()

    conn.close()
    return {
        "total_events": total_events,
        "active_alerts": active_alerts,
        "open_incidents": open_incidents,
        "events_last_min": events_last_min,
        "top_ips": [dict(r) for r in top_ips],
        "top_attack_types": [dict(r) for r in top_attack_types],
        "alerts_by_severity": [dict(r) for r in alerts_by_sev],
        "events_timeline": [dict(r) for r in events_timeline],
    }


def clear_all():
    """Limpa o banco — usado para reset de demo."""
    conn = get_conn()
    conn.executescript("DELETE FROM events; DELETE FROM alerts; DELETE FROM incidents;")
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print(f"[DB] Banco inicializado em: {DB_PATH}")
