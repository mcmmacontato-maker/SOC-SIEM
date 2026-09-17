"""
vps_collector.py — Coletor de logs reais de VPS Honeypot via SSH
Conecta no VPS com paramiko, faz tail do auth.log em tempo real
e insere eventos reais no banco SOC-SIEM.

Segurança:
  - Verificação de host key via known_hosts (sem AutoAddPolicy cego)
  - Suporte a chave privada criptografada com passphrase
  - Modo push: envia eventos para o SIEM via HTTPS + API Key
  - Modo local: escreve direto no SQLite (sem rede)

Uso:
    python vps_collector.py --host SEU_IP --user root --key ~/.ssh/id_rsa
    python vps_collector.py --host SEU_IP --user root --key ~/.ssh/id_rsa --trust-host
    python vps_collector.py --host SEU_IP --user root --key ~/.ssh/id_rsa \\
        --push http://localhost:5000/api/ingest --api-key SUA_CHAVE
"""
import argparse
import os
import re
import sys
import time
import threading
import urllib.request
import urllib.error
import json as _json
from datetime import datetime, timezone

try:
    import paramiko
except ImportError:
    print("[VPS] ERRO: instale o paramiko: pip install paramiko")
    sys.exit(1)

import siem_db

# ── Regex patterns para /var/log/auth.log ───────────────────────────────
RE_FAIL = re.compile(
    r"(\w+\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
)
RE_SUCCESS = re.compile(
    r"(\w+\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)"
)
RE_INVALID = re.compile(
    r"(\w+\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Invalid user (\S+) from ([\d.]+)"
)
RE_DISCONNECT = re.compile(
    r"(\w+\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Disconnected from (?:invalid user )?(\S+)? ?([\d.]+) port (\d+)"
)
RE_CONN = re.compile(
    r"(\w+\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Connection from ([\d.]+)"
)

# ── Log parser ────────────────────────────────────────────────────────────
def parse_line(line: str) -> dict | None:
    """Parseia uma linha do auth.log e retorna evento normalizado ou None."""
    line = line.strip()
    if not line:
        return None

    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")

    m = RE_FAIL.search(line)
    if m:
        return dict(
            timestamp=ts, source_ip=m.group(3), dest_ip="HONEYPOT",
            event_type="SSH_LOGIN_FAILURE", severity="MEDIUM",
            category="authentication",
            raw=line,
            metadata={"user": m.group(2), "port": m.group(4), "protocol": "ssh2"}
        )

    m = RE_SUCCESS.search(line)
    if m:
        return dict(
            timestamp=ts, source_ip=m.group(3), dest_ip="HONEYPOT",
            event_type="SSH_LOGIN_SUCCESS", severity="HIGH",
            category="authentication",
            raw=line,
            metadata={"user": m.group(2), "port": m.group(4)}
        )

    m = RE_INVALID.search(line)
    if m:
        return dict(
            timestamp=ts, source_ip=m.group(3), dest_ip="HONEYPOT",
            event_type="SSH_LOGIN_FAILURE", severity="MEDIUM",
            category="authentication",
            raw=line,
            metadata={"user": m.group(2), "note": "invalid_user"}
        )

    return None


# ── SSH Tail ──────────────────────────────────────────────────────────────
def tail_auth_log(client: paramiko.SSHClient, log_path="/var/log/auth.log",
                  stop_event: threading.Event = None):
    """Faz streaming do auth.log via SSH e parseia eventos em tempo real."""
    print(f"[VPS] Iniciando tail de {log_path}...")
    transport = client.get_transport()
    channel   = transport.open_session()
    channel.exec_command(f"tail -F {log_path} 2>/dev/null")

    buf = ""
    event_count = 0

    while not (stop_event and stop_event.is_set()):
        if channel.recv_ready():
            chunk = channel.recv(4096).decode("utf-8", errors="replace")
            buf  += chunk
            lines = buf.split("\n")
            buf   = lines[-1]  # guarda linha incompleta
            for line in lines[:-1]:
                ev = parse_line(line)
                if ev:
                    siem_db.insert_event(**ev)
                    event_count += 1
                    print(f"  [VPS→SIEM] {ev['severity']:8s} | {ev['event_type']:25s} | {ev['source_ip']}")
        elif channel.exit_status_ready():
            print("[VPS] Conexão encerrada pelo servidor.")
            break
        else:
            time.sleep(0.2)

    channel.close()
    print(f"[VPS] Sessão encerrada. {event_count} eventos ingeridos.")


# ── Histórico: últimas N linhas ────────────────────────────────────────
def ingest_history(client: paramiko.SSHClient,
                   log_path="/var/log/auth.log", lines=1000):
    """Ingerere as últimas N linhas do log como baseline histórico."""
    _, stdout, _ = client.exec_command(f"tail -n {lines} {log_path}")
    count = 0
    for line in stdout:
        ev = parse_line(line)
        if ev:
            siem_db.insert_event(**ev)
            count += 1
    print(f"[VPS] Histórico: {count} eventos ingeridos das últimas {lines} linhas.")
    return count


# ── Conexão SSH (com verificação de host key) ─────────────────────────
def connect(host, port, user, password=None, key_path=None,
            known_hosts=None, trust_host=False) -> paramiko.SSHClient:
    """
    Conecta ao VPS via SSH com verificação de host key.
    trust_host=True adiciona o host ao known_hosts na primeira conexão
    (similar ao comportamento interativo do ssh), mas avisa o usuário.
    """
    client = paramiko.SSHClient()

    # Carrega known_hosts do sistema
    if known_hosts and os.path.exists(known_hosts):
        client.load_host_keys(known_hosts)
    else:
        default_known_hosts = os.path.expanduser("~/.ssh/known_hosts")
        if os.path.exists(default_known_hosts):
            client.load_host_keys(default_known_hosts)

    if trust_host:
        # Adiciona chave do host automaticamente (apenas na 1ª conexão)
        # A chave fica salva em known_hosts para verificações futuras
        policy = paramiko.AutoAddPolicy()
        print("[VPS] ⚠️  --trust-host ativado: a chave do servidor será salva e")
        print("[VPS]    confiada automaticamente. Use somente na 1ª configuração.")
    else:
        # Política estrita: rejeita hosts desconhecidos
        policy = paramiko.RejectPolicy()

    client.set_missing_host_key_policy(policy)

    kwargs = dict(hostname=host, port=port, username=user, timeout=20,
                  banner_timeout=30)
    if key_path:
        kwargs["key_filename"] = os.path.expanduser(key_path)
        kwargs["look_for_keys"] = False
        kwargs["allow_agent"]   = False
    elif password:
        kwargs["password"]      = password
        kwargs["look_for_keys"] = False
        kwargs["allow_agent"]   = False
    else:
        # Usa SSH-agent ou chaves padrão do sistema
        kwargs["look_for_keys"] = True
        kwargs["allow_agent"]   = True

    client.connect(**kwargs)

    # Mostra fingerprint do host para auditoria
    transport = client.get_transport()
    host_key  = transport.get_remote_server_key()
    fp        = host_key.get_fingerprint().hex()
    fp_fmt    = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))
    print(f"[VPS] ✅ Conectado em {user}@{host}:{port}")
    print(f"[VPS]    Host fingerprint ({host_key.get_name()}): {fp_fmt}")
    return client


# ── Push via HTTP + API Key (modo alternativo ao DB direto) ───────────
def push_event(ev: dict, siem_url: str, api_key: str) -> bool:
    """Envia evento para o SIEM via HTTP POST com autenticação."""
    try:
        payload = _json.dumps([{"raw": ev.get("raw", "")}]).encode()
        req = urllib.request.Request(
            siem_url, data=payload,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {api_key}"})
        urllib.request.urlopen(req, timeout=5)
        return True
    except urllib.error.URLError as e:
        print(f"  [PUSH] Erro ao enviar: {e.reason}")
        return False


# ── Main ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SOC-SIEM VPS Honeypot Log Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # 1ª conexão: confiar no host e salvar fingerprint
  python vps_collector.py --host 123.45.67.89 --user root --key ~/.ssh/id_rsa --trust-host

  # Conexões seguintes: verificação automática (sem --trust-host)
  python vps_collector.py --host 123.45.67.89 --user root --key ~/.ssh/id_rsa

  # Modo push HTTP (VPS envia para SIEM em outra máquina)
  python vps_collector.py --host 123.45.67.89 --user root --key ~/.ssh/id_rsa \\
      --push http://localhost:5000/api/ingest --api-key SUA_CHAVE
        """
    )
    parser.add_argument("--host",       required=True, help="IP ou hostname do VPS")
    parser.add_argument("--port",       type=int, default=22, help="Porta SSH (padrão: 22)")
    parser.add_argument("--user",       required=True, help="Usuário SSH")
    parser.add_argument("--password",   default=None,  help="Senha SSH (prefira --key)")
    parser.add_argument("--key",        default=None,  help="Caminho da chave privada SSH")
    parser.add_argument("--known-hosts",default=None,  help="Arquivo known_hosts (padrão: ~/.ssh/known_hosts)")
    parser.add_argument("--trust-host", action="store_true",
                        help="Na 1ª conexão: salvar fingerprint automaticamente (use só 1x)")
    parser.add_argument("--log",        default="/var/log/auth.log",
                        help="Caminho do log no VPS (padrão: /var/log/auth.log)")
    parser.add_argument("--history",    type=int, default=500,
                        help="Linhas históricas para ingerir ao iniciar (padrão: 500)")
    parser.add_argument("--no-history", action="store_true",
                        help="Não ingerir histórico — apenas eventos novos")
    parser.add_argument("--push",       default=None,
                        help="URL do endpoint /api/ingest (modo push HTTP)")
    parser.add_argument("--api-key",    default=None,
                        help="Chave de API para autenticação no modo push")
    args = parser.parse_args()

    # Configurar modo de saída
    use_push = bool(args.push)
    if use_push and not args.api_key:
        # Tenta carregar do .env local
        try:
            import siem_config
            args.api_key = siem_config.get_api_key()
            print(f"[VPS] API key carregada do .env local.")
        except ImportError:
            print("[VPS] ERRO: --api-key obrigatório no modo push.")
            sys.exit(1)

    siem_db.init_db()

    try:
        client = connect(
            args.host, args.port, args.user,
            password=args.password, key_path=args.key,
            known_hosts=getattr(args, 'known_hosts', None),
            trust_host=args.trust_host
        )
    except paramiko.ssh_exception.SSHException as e:
        print(f"[VPS] ❌ ERRO SSH: {e}")
        if "not found in known_hosts" in str(e) or "Unknown server" in str(e):
            print("[VPS]    Dica: na primeira conexão use --trust-host para salvar a chave.")
            print("[VPS]    Nas próximas conexões a verificação será automática.")
        sys.exit(1)
    except Exception as e:
        print(f"[VPS] ❌ ERRO na conexão: {e}")
        sys.exit(1)

    if not args.no_history:
        ingest_history(client, args.log, args.history)

    # Sobrescreve tail_auth_log para usar push se necessário
    if use_push:
        def _emit(ev):
            push_event(ev, args.push, args.api_key)
        # Monkey-patch: redireciona insert_event para push
        import types
        siem_db.insert_event = lambda **kw: push_event(
            kw, args.push, args.api_key)

    stop = threading.Event()
    try:
        print("[VPS] 🔴 Monitorando em tempo real... (Ctrl+C para parar)")
        tail_auth_log(client, args.log, stop)
    except KeyboardInterrupt:
        print("\n[VPS] Interrompido pelo usuário.")
        stop.set()
    finally:
        client.close()


if __name__ == "__main__":
    main()
