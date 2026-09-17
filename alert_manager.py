"""
alert_manager.py — Gerenciador de alertas e escalada para incidentes
"""
import json
from datetime import datetime, timezone

import siem_db
import incident_responder


SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Alertas com esta severidade viram incidentes automaticamente
AUTO_ESCALATE_THRESHOLD = {"HIGH", "CRITICAL"}


def process_new_alerts(alert_ids: list):
    """Processa lista de IDs de alertas recém-gerados e escalada se necessário."""
    for aid in alert_ids:
        alerts = siem_db.get_alerts()
        alert = next((a for a in alerts if a["id"] == aid), None)
        if not alert:
            continue

        print(f"  [ALERT_MGR] Processando alerta #{aid} — {alert['severity']} — {alert['rule_name']}")

        if alert["severity"] in AUTO_ESCALATE_THRESHOLD:
            incident_id = incident_responder.create_incident_from_alert(alert)
            siem_db.update_alert_incident(aid, incident_id)
            print(f"  [ALERT_MGR] Alerta #{aid} escalado para Incidente #{incident_id}")


def get_alert_summary():
    """Retorna resumo de alertas por severidade."""
    alerts = siem_db.get_alerts()
    summary = {}
    for a in alerts:
        sev = a["severity"]
        summary[sev] = summary.get(sev, 0) + 1
    return summary


if __name__ == "__main__":
    siem_db.init_db()
    import rules_engine
    print("[ALERT_MGR] Avaliando regras...")
    new_alert_ids = rules_engine.evaluate_rules()
    process_new_alerts(new_alert_ids)
    print(f"[ALERT_MGR] Resumo de alertas: {get_alert_summary()}")
