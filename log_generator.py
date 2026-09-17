"""
log_generator.py — Gerador de logs sintéticos realistas para o SIEM
Cenários: SSH Brute-Force, Web Attacks, MQTT Anomalies
"""
import random
import time
import argparse
from datetime import datetime, timezone, timedelta
from faker import Faker

import siem_db

fake = Faker("pt_BR")

# ── Constantes ─────────────────────────────────────────────────────────────
SSH_USERS = ["root", "admin", "ubuntu", "pi", "oracle", "guest", "deploy", "test", "maria", "user"]
SSH_DEST   = "192.168.1.10"
WEB_DEST   = "192.168.1.20"
MQTT_DEST  = "192.168.1.30"

WEB_PATHS_NORMAL = ["/", "/index.html", "/about", "/contact", "/api/users", "/api/products"]
WEB_PATHS_ATTACK = [
    "/login?user=admin'--",
    "/search?q=<script>alert(1)</script>",
    "/../../../etc/passwd",
    "/admin/config.php",
    "/wp-login.php",
    "/.env",
    "/api/users?id=1 OR 1=1",
    "/login?user=admin&pass='+OR+'1'='1",
    "/phpmyadmin/",
    "/shell.php",
    "/cmd.php?cmd=id",
]
WEB_METHODS = ["GET", "POST", "PUT", "DELETE"]
WEB_STATUS_NORMAL = [200, 201, 301, 302]
WEB_STATUS_ATTACK = [400, 401, 403, 404, 500]

MQTT_TOPICS_NORMAL = ["home/sensor/temp", "home/sensor/humidity", "home/lights/status"]
MQTT_TOPICS_ATTACK = [
    "../../etc/passwd",
    "$SYS/broker/clients/total",
    "admin/config/update",
    "device/000000/cmd",
    "../factory/reset",
]

ATTACK_IPS = [fake.ipv4() for _ in range(6)]  # attacker IPs (fixed set)


def utcnow(offset_seconds=0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return dt.isoformat(timespec="seconds")


# ── SSH Brute-Force ─────────────────────────────────────────────────────────
def gen_ssh_bruteforce(attacker_ip: str, count: int = 20, base_offset: int = 0):
    """Gera sequência de falhas SSH + eventual sucesso (credstuff)."""
    events = []
    for i in range(count):
        success = (i == count - 1) and random.random() < 0.3
        status  = "Accepted" if success else "Failed"
        sev     = "HIGH" if success else "MEDIUM"
        user    = random.choice(SSH_USERS)
        raw     = (
            f"sshd[{random.randint(1000,9999)}]: {status} password for {user} "
            f"from {attacker_ip} port {random.randint(30000,65000)} ssh2"
        )
        eid = siem_db.insert_event(
            timestamp  = utcnow(base_offset - i * 3),
            source_ip  = attacker_ip,
            dest_ip    = SSH_DEST,
            event_type = "SSH_LOGIN_SUCCESS" if success else "SSH_LOGIN_FAILURE",
            severity   = sev,
            category   = "authentication",
            raw        = raw,
            metadata   = {"user": user, "port": random.randint(30000, 65000), "protocol": "ssh2"}
        )
        events.append(eid)
        if not success:
            time.sleep(0.01)
    return events


# ── Web Attacks ─────────────────────────────────────────────────────────────
def gen_web_attack(attacker_ip: str, count: int = 15, base_offset: int = 0):
    """Gera logs Apache-style com ataques (SQLi, XSS, path traversal)."""
    events = []
    for i in range(count):
        is_attack = random.random() < 0.7
        path      = random.choice(WEB_PATHS_ATTACK if is_attack else WEB_PATHS_NORMAL)
        method    = "POST" if "login" in path or "cmd" in path else random.choice(WEB_METHODS)
        status    = random.choice(WEB_STATUS_ATTACK if is_attack else WEB_STATUS_NORMAL)
        ua        = random.choice([
            "sqlmap/1.7.8", "nikto/2.1.6", "python-requests/2.28",
            "Mozilla/5.0 (compatible; Googlebot/2.1)", "curl/7.88.1"
        ]) if is_attack else fake.user_agent()

        attack_type = "NORMAL"
        if "'" in path or "OR" in path:
            attack_type = "SQL_INJECTION"
        elif "<script>" in path:
            attack_type = "XSS"
        elif "../" in path or "etc/passwd" in path:
            attack_type = "PATH_TRAVERSAL"
        elif ".php" in path and status != 404:
            attack_type = "WEBSHELL_ACCESS"
        elif path in ["/.env", "/phpmyadmin/"]:
            attack_type = "RECON_SENSITIVE_FILE"

        raw = (
            f'{attacker_ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"{method} {path} HTTP/1.1" {status} {random.randint(100,5000)} '
            f'"-" "{ua}"'
        )
        sev = "HIGH" if attack_type not in ["NORMAL"] else "INFO"
        eid = siem_db.insert_event(
            timestamp  = utcnow(base_offset - i * 2),
            source_ip  = attacker_ip,
            dest_ip    = WEB_DEST,
            event_type = attack_type,
            severity   = sev,
            category   = "web",
            raw        = raw,
            metadata   = {"method": method, "path": path, "status": status, "user_agent": ua}
        )
        events.append(eid)
    return events


# ── MQTT Anomaly ─────────────────────────────────────────────────────────────
def gen_mqtt_anomaly(attacker_ip: str, count: int = 10, base_offset: int = 0):
    """Gera anomalias em tópicos MQTT (path traversal, system topics)."""
    events = []
    for i in range(count):
        is_anomaly = random.random() < 0.6
        topic      = random.choice(MQTT_TOPICS_ATTACK if is_anomaly else MQTT_TOPICS_NORMAL)
        payload    = (
            '{"cmd":"reboot","auth":"none"}' if is_anomaly
            else f'{{"value":{round(random.uniform(20,40),1)}}}'
        )
        attack_type = "MQTT_TOPIC_ANOMALY" if is_anomaly else "MQTT_NORMAL"
        raw = f"MQTT PUBLISH from {attacker_ip} topic='{topic}' qos=1 payload={payload}"
        eid = siem_db.insert_event(
            timestamp  = utcnow(base_offset - i * 5),
            source_ip  = attacker_ip,
            dest_ip    = MQTT_DEST,
            event_type = attack_type,
            severity   = "MEDIUM" if is_anomaly else "INFO",
            category   = "iot",
            raw        = raw,
            metadata   = {"topic": topic, "payload": payload}
        )
        events.append(eid)
    return events


# ── Port Scan ────────────────────────────────────────────────────────────────
def gen_port_scan(attacker_ip: str, count: int = 20, base_offset: int = 0):
    """Simula scan de portas (SYN scan)."""
    common_ports = [22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, 6667]
    events = []
    for i, port in enumerate(random.sample(range(1, 1025), min(count, 100))):
        raw = f"firewall: DROP TCP {attacker_ip}:{random.randint(40000,65000)} -> {SSH_DEST}:{port} SYN"
        eid = siem_db.insert_event(
            timestamp  = utcnow(base_offset - i),
            source_ip  = attacker_ip,
            dest_ip    = SSH_DEST,
            event_type = "PORT_SCAN",
            severity   = "MEDIUM",
            category   = "network",
            raw        = raw,
            metadata   = {"dest_port": port, "flags": "SYN"}
        )
        events.append(eid)
    return events


# ── Normal background traffic ─────────────────────────────────────────────
def gen_normal_traffic(count: int = 50, base_offset: int = 0):
    for i in range(count):
        ip  = fake.ipv4_private()
        path = random.choice(WEB_PATHS_NORMAL)
        siem_db.insert_event(
            timestamp  = utcnow(base_offset - i * 10),
            source_ip  = ip,
            dest_ip    = WEB_DEST,
            event_type = "HTTP_REQUEST",
            severity   = "INFO",
            category   = "web",
            raw        = f'{ip} - - "GET {path} HTTP/1.1" 200 {random.randint(500,5000)}',
            metadata   = {"path": path, "status": 200}
        )


def run_all_scenarios(count: int = 200):
    """Gera conjunto completo de logs sintéticos."""
    print(f"[GEN] Gerando {count} eventos sintéticos...")
    attacker1 = ATTACK_IPS[0]
    attacker2 = ATTACK_IPS[1]
    attacker3 = ATTACK_IPS[2]

    gen_ssh_bruteforce(attacker1, count=min(30, count // 4))
    gen_web_attack(attacker2, count=min(40, count // 3))
    gen_mqtt_anomaly(attacker3, count=min(20, count // 5))
    gen_port_scan(attacker2, count=min(30, count // 4))
    gen_normal_traffic(count=max(20, count // 4))
    print("[GEN] Geração concluída.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gerador de logs sintéticos SOC-SIEM")
    parser.add_argument("--scenario", choices=["ssh","web","mqtt","portscan","all"], default="all")
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--ip", type=str, default=None)
    args = parser.parse_args()

    siem_db.init_db()
    ip = args.ip or ATTACK_IPS[0]

    if args.scenario == "all":
        run_all_scenarios(args.count)
    elif args.scenario == "ssh":
        gen_ssh_bruteforce(ip, count=args.count)
    elif args.scenario == "web":
        gen_web_attack(ip, count=args.count)
    elif args.scenario == "mqtt":
        gen_mqtt_anomaly(ip, count=args.count)
    elif args.scenario == "portscan":
        gen_port_scan(ip, count=args.count)

    print(f"[GEN] Stats: {siem_db.get_stats()['total_events']} eventos no banco.")
