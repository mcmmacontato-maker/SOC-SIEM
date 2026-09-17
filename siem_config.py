"""
siem_config.py — Carrega configurações seguras do .env
"""
import os
import secrets
import pathlib

_ENV_FILE = pathlib.Path(__file__).parent / ".env"

def _load_env():
    """Carrega variáveis do .env se existir (sem dependência de python-dotenv)."""
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip())

_load_env()

def get_api_key() -> str:
    """Retorna a chave de API configurada ou gera e salva uma automaticamente."""
    key = os.environ.get("SIEM_API_KEY", "")
    if not key or key == "TROQUE_POR_UMA_CHAVE_GERADA":
        # Auto-gera uma chave segura e persiste no .env
        key = secrets.token_hex(32)
        _save_api_key(key)
        print(f"\n[CONFIG] ✅ Chave de API gerada automaticamente.")
        print(f"[CONFIG]    Salve em .env: SIEM_API_KEY={key}")
        print(f"[CONFIG]    Use no coletor: --api-key {key}\n")
    return key

def _save_api_key(key: str):
    """Persiste a chave gerada no .env."""
    content = f"# Auto-gerado pelo SOC-SIEM\nSIEM_API_KEY={key}\nVPS_ALLOWED_IP=\nINGEST_MAX_EVENTS_PER_REQUEST=500\nSIEM_PORT=5000\nSIEM_PUBLIC=0\n"
    _ENV_FILE.write_text(content, encoding="utf-8")

def get_allowed_ip() -> str | None:
    ip = os.environ.get("VPS_ALLOWED_IP", "").strip()
    return ip if ip else None

def get_ingest_limit() -> int:
    try:
        return int(os.environ.get("INGEST_MAX_EVENTS_PER_REQUEST", "500"))
    except ValueError:
        return 500

def get_port() -> int:
    try:
        return int(os.environ.get("SIEM_PORT", "5000"))
    except ValueError:
        return 5000

def is_public() -> bool:
    return os.environ.get("SIEM_PUBLIC", "0").strip() == "1"
