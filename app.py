"""
app.py — Servidor Flask: API REST + Dashboard Web do SOC-SIEM
"""
import json
import threading
import time
import random
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request, Response
from flask_cors import CORS

import siem_db
import log_generator
import rules_engine
import alert_manager
import siem_config

app = Flask(__name__)
CORS(app)

# ── Background engine loop ───────────────────────────────────────────────
_engine_running = False

def _engine_loop():
    """Avalia regras de detecção continuamente a cada 10s."""
    while _engine_running:
        try:
            new_alerts = rules_engine.evaluate_rules()
            if new_alerts:
                alert_manager.process_new_alerts(new_alerts)
        except Exception as e:
            print(f"[ENGINE] Erro: {e}")
        time.sleep(10)

# ── Routes ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    limit  = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    events = siem_db.get_recent_events(limit=limit, offset=offset)
    return jsonify(events)


@app.route("/api/alerts")
def api_alerts():
    status = request.args.get("status", None)
    alerts = siem_db.get_alerts(status=status)
    return jsonify(alerts)


@app.route("/api/incidents")
def api_incidents():
    incidents = siem_db.get_incidents()
    return jsonify(incidents)


@app.route("/api/stats")
def api_stats():
    stats = siem_db.get_stats()
    return jsonify(stats)


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    """Dispara um cenário de ataque sintético e roda o motor de regras."""
    data     = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "all")
    ip       = data.get("ip", None) or log_generator.ATTACK_IPS[random.randint(0, 4)]

    if scenario == "ssh":
        log_generator.gen_ssh_bruteforce(ip, count=25)
    elif scenario == "web":
        log_generator.gen_web_attack(ip, count=30)
    elif scenario == "mqtt":
        log_generator.gen_mqtt_anomaly(ip, count=15)
    elif scenario == "portscan":
        log_generator.gen_port_scan(ip, count=20)
    else:
        log_generator.run_all_scenarios(count=150)

    # Avalia regras imediatamente após ingestão
    new_alerts = rules_engine.evaluate_rules()
    alert_manager.process_new_alerts(new_alerts)

    return jsonify({
        "status": "ok",
        "scenario": scenario,
        "ip": ip,
        "new_alerts": len(new_alerts),
    })


@app.route("/api/report/<int:incident_id>")
def api_report(incident_id):
    """Retorna relatório de incidente em Markdown."""
    incident = siem_db.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "Incidente não encontrado"}), 404
    report = incident.get("report") or "Relatório ainda não gerado."
    return Response(report, mimetype="text/plain; charset=utf-8")


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Limpa o banco e reinicia a demo."""
    siem_db.clear_all()
    return jsonify({"status": "reset ok"})


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """
    Endpoint de ingestação push — VPS e agentes externos enviam linhas de log aqui.
    Segurança:
      • Autenticação por API Key (header Authorization: Bearer <key>)
      • Allowlist de IP (opcional, configurada em .env)
      • Limite de eventos por requisição
      • Sanitização de input
    """
    try:
        from vps_collector import parse_line
    except ImportError:
        return jsonify({"error": "vps_collector.py não encontrado"}), 500

    # ── 1. Autentição por API Key ─────────────────────────
    auth_header = request.headers.get("Authorization", "")
    expected    = f"Bearer {siem_config.get_api_key()}"
    if auth_header != expected:
        return jsonify({"error": "Unauthorized"}), 401

    # ── 2. Allowlist de IP ─────────────────────────────
    allowed_ip = siem_config.get_allowed_ip()
    if allowed_ip:
        remote_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if remote_ip not in (allowed_ip, "127.0.0.1", "::1"):
            return jsonify({"error": "Forbidden"}), 403

    # ── 3. Parse do body ──────────────────────────────
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON inválido"}), 400

    items = data if isinstance(data, list) else [data]
    limit = siem_config.get_ingest_limit()
    if len(items) > limit:
        return jsonify({"error": f"Máximo de {limit} eventos por requisição"}), 413

    # ── 4. Processa + sanitiza ─────────────────────────
    inserted = 0
    for item in items:
        raw = str(item.get("raw", ""))[:2048]   # max 2 KB por linha
        raw = raw.replace("\x00", "").strip()    # strip null bytes
        if not raw:
            continue
        ev = parse_line(raw)
        if ev:
            siem_db.insert_event(**ev)
            inserted += 1

    if inserted:
        new_alerts = rules_engine.evaluate_rules()
        alert_manager.process_new_alerts(new_alerts)

    return jsonify({"status": "ok", "inserted": inserted})

# ── Startup ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    siem_db.init_db()
    print("[SOC-SIEM] Banco inicializado.")

    # Popula com dados iniciais se banco vazio
    stats = siem_db.get_stats()
    if stats["total_events"] == 0:
        print("[SOC-SIEM] Gerando dados iniciais de demonstração...")
        log_generator.run_all_scenarios(count=300)
        new_alerts = rules_engine.evaluate_rules()
        alert_manager.process_new_alerts(new_alerts)
        print(f"[SOC-SIEM] {stats['total_events']} eventos, {len(new_alerts)} alertas gerados.")

    # Inicia loop de detecção em background
    _engine_running = True
    t = threading.Thread(target=_engine_loop, daemon=True)
    t.start()
    print("[SOC-SIEM] Motor de detecção iniciado em background.")
    print("[SOC-SIEM] Dashboard disponível em: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
