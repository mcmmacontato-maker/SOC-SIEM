"""
rules_engine.py — Motor de regras de detecção SIGMA-like
Avalia eventos no banco e gera alertas quando regras disparam.
"""
import json
import sqlite3
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import siem_db

# ── Definição de Regras ───────────────────────────────────────────────────
RULES = [
    {
        "id": "SSH-001",
        "name": "SSH Brute-Force Detected",
        "description": "Mais de 5 tentativas de login SSH falhas em 60 segundos pelo mesmo IP.",
        "severity": "HIGH",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001 - Brute Force: Password Guessing",
        "event_type": "SSH_LOGIN_FAILURE",
        "threshold": 5,
        "window_seconds": 60,
    },
    {
        "id": "SSH-002",
        "name": "Successful Login After Brute-Force",
        "description": "Login SSH bem-sucedido após múltiplas falhas — possível credential stuffing.",
        "severity": "CRITICAL",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "event_type": "SSH_LOGIN_SUCCESS",
        "requires_prior": "SSH_LOGIN_FAILURE",
        "prior_threshold": 3,
        "window_seconds": 300,
    },
    {
        "id": "WEB-001",
        "name": "SQL Injection Attempt",
        "description": "Tentativa de injeção SQL detectada nos parâmetros de requisição HTTP.",
        "severity": "HIGH",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "event_type": "SQL_INJECTION",
        "threshold": 1,
        "window_seconds": 3600,
    },
    {
        "id": "WEB-002",
        "name": "XSS Attack Attempt",
        "description": "Script malicioso detectado em parâmetro de requisição HTTP.",
        "severity": "MEDIUM",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1059.007 - Command and Scripting Interpreter: JavaScript",
        "event_type": "XSS",
        "threshold": 1,
        "window_seconds": 3600,
    },
    {
        "id": "WEB-003",
        "name": "Path Traversal Attempt",
        "description": "Tentativa de traversal de diretórios (../../etc/passwd).",
        "severity": "HIGH",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1083 - File and Directory Discovery",
        "event_type": "PATH_TRAVERSAL",
        "threshold": 1,
        "window_seconds": 3600,
    },
    {
        "id": "WEB-004",
        "name": "Webshell Access Detected",
        "description": "Acesso a arquivo PHP suspeito que pode ser um webshell.",
        "severity": "CRITICAL",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1505.003 - Server Software Component: Web Shell",
        "event_type": "WEBSHELL_ACCESS",
        "threshold": 1,
        "window_seconds": 3600,
    },
    {
        "id": "WEB-005",
        "name": "Sensitive File Reconnaissance",
        "description": "Tentativa de acesso a arquivos sensíveis (.env, phpmyadmin).",
        "severity": "MEDIUM",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1595 - Active Scanning",
        "event_type": "RECON_SENSITIVE_FILE",
        "threshold": 1,
        "window_seconds": 3600,
    },
    {
        "id": "NET-001",
        "name": "Port Scan Detected",
        "description": "Varredura de portas SYN detectada — mais de 10 portas em 30 segundos.",
        "severity": "MEDIUM",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1046 - Network Service Discovery",
        "event_type": "PORT_SCAN",
        "threshold": 10,
        "window_seconds": 30,
    },
    {
        "id": "IOT-001",
        "name": "MQTT Topic Anomaly",
        "description": "Publicação em tópico MQTT suspeito (path traversal, tópico administrativo).",
        "severity": "MEDIUM",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1210 - Exploitation of Remote Services",
        "event_type": "MQTT_TOPIC_ANOMALY",
        "threshold": 3,
        "window_seconds": 60,
    },
]


def _get_recent_events_by_type(conn, event_type, source_ip, window_seconds):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat(timespec="seconds")
    rows = conn.execute(
        "SELECT id, timestamp, source_ip, event_type FROM events "
        "WHERE event_type=? AND source_ip=? AND timestamp >= ?",
        (event_type, source_ip, cutoff)
    ).fetchall()
    return rows


def _alert_already_exists(conn, rule_name, source_ip, window_seconds=300):
    """Evita alertas duplicados para mesma regra+IP em janela recente."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat(timespec="seconds")
    count = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE rule_name=? AND source_ip=? AND timestamp >= ?",
        (rule_name, source_ip, cutoff)
    ).fetchone()[0]
    return count > 0


def _get_distinct_attacker_ips(conn):
    rows = conn.execute(
        "SELECT DISTINCT source_ip FROM events WHERE source_ip IS NOT NULL"
    ).fetchall()
    return [r[0] for r in rows if r[0]]


def evaluate_rules():
    """Avalia todas as regras e insere alertas para violações."""
    conn = siem_db.get_conn()
    new_alerts = []

    distinct_ips = _get_distinct_attacker_ips(conn)

    for rule in RULES:
        rule_name = rule["name"]
        event_type = rule["event_type"]
        threshold = rule.get("threshold", 1)
        window = rule.get("window_seconds", 60)
        severity = rule["severity"]

        if "requires_prior" in rule:
            # Rule SSH-002: success after prior failures
            success_events = conn.execute(
                "SELECT id, source_ip, timestamp FROM events "
                "WHERE event_type=? ORDER BY timestamp DESC LIMIT 200",
                (event_type,)
            ).fetchall()

            for ev in success_events:
                ip = ev["source_ip"]
                cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window)).isoformat(timespec="seconds")
                prior_count = conn.execute(
                    "SELECT COUNT(*) FROM events WHERE event_type=? AND source_ip=? AND timestamp >= ?",
                    (rule["requires_prior"], ip, cutoff)
                ).fetchone()[0]

                if prior_count >= rule["prior_threshold"]:
                    if not _alert_already_exists(conn, rule_name, ip):
                        aid = siem_db.insert_alert(
                            rule_name=rule_name,
                            description=rule["description"],
                            severity=severity,
                            source_ip=ip,
                            event_ids=[ev["id"]],
                            mitre_tactic=rule["mitre_tactic"],
                            mitre_technique=rule["mitre_technique"],
                        )
                        new_alerts.append(aid)
                        print(f"  [ALERT] {severity} | {rule['id']} | {rule_name} | IP={ip}")
        else:
            for ip in distinct_ips:
                matching = _get_recent_events_by_type(conn, event_type, ip, window)
                if len(matching) >= threshold:
                    if not _alert_already_exists(conn, rule_name, ip):
                        event_ids = [r["id"] for r in matching]
                        aid = siem_db.insert_alert(
                            rule_name=rule_name,
                            description=rule["description"],
                            severity=severity,
                            source_ip=ip,
                            event_ids=event_ids,
                            mitre_tactic=rule["mitre_tactic"],
                            mitre_technique=rule["mitre_technique"],
                        )
                        new_alerts.append(aid)
                        print(f"  [ALERT] {severity} | {rule['id']} | {rule_name} | IP={ip}")

    conn.close()
    return new_alerts


if __name__ == "__main__":
    siem_db.init_db()
    print("[RULES] Avaliando regras de detecção...")
    alerts = evaluate_rules()
    print(f"[RULES] {len(alerts)} novo(s) alerta(s) gerado(s).")
