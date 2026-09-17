# Catálogo de Regras de Detecção — SOC-SIEM

> Regras estilo SIGMA para detecção de ameaças no SIEM caseiro. Cada regra é validada contra os eventos normalizados no banco SQLite.

---

## SSH-001 — SSH Brute-Force Detected

| Campo | Valor |
|-------|-------|
| **Severidade** | HIGH |
| **MITRE Tática** | Credential Access |
| **MITRE Técnica** | T1110.001 — Brute Force: Password Guessing |
| **Threshold** | 5+ falhas em 60 segundos do mesmo IP |

**Lógica de Detecção:**
```sql
SELECT source_ip, COUNT(*) as cnt
FROM events
WHERE event_type = 'SSH_LOGIN_FAILURE'
  AND timestamp >= datetime('now', '-60 seconds')
GROUP BY source_ip
HAVING cnt >= 5
```

**Resposta:** Bloquear IP no firewall → instalar Fail2Ban → auditar auth.log

---

## SSH-002 — Successful Login After Brute-Force

| Campo | Valor |
|-------|-------|
| **Severidade** | CRITICAL |
| **MITRE Tática** | Initial Access |
| **MITRE Técnica** | T1078 — Valid Accounts |
| **Threshold** | 1 sucesso após 3+ falhas em 300s |

**Lógica:** Correlaciona `SSH_LOGIN_SUCCESS` com `SSH_LOGIN_FAILURE` do mesmo IP na janela de 5 minutos.

**Resposta:** Isolamento imediato → preservação de evidências → revogação de credenciais

---

## WEB-001 — SQL Injection Attempt

| Campo | Valor |
|-------|-------|
| **Severidade** | HIGH |
| **MITRE Tática** | Initial Access |
| **MITRE Técnica** | T1190 — Exploit Public-Facing Application |
| **Threshold** | 1 evento |

**Indicadores:** Presença de `'--`, `OR 1=1`, `UNION SELECT` em parâmetros HTTP.

---

## WEB-002 — XSS Attack Attempt

| Campo | Valor |
|-------|-------|
| **Severidade** | MEDIUM |
| **MITRE Tática** | Initial Access |
| **MITRE Técnica** | T1059.007 — JavaScript |

**Indicadores:** Tags `<script>`, `javascript:`, `onerror=` em parâmetros de URL/body.

---

## WEB-003 — Path Traversal Attempt

| Campo | Valor |
|-------|-------|
| **Severidade** | HIGH |
| **MITRE Tática** | Discovery |
| **MITRE Técnica** | T1083 — File and Directory Discovery |

**Indicadores:** Sequências `../` ou acesso a `/etc/passwd`, `/etc/shadow`.

---

## WEB-004 — Webshell Access Detected

| Campo | Valor |
|-------|-------|
| **Severidade** | CRITICAL |
| **MITRE Tática** | Persistence |
| **MITRE Técnica** | T1505.003 — Web Shell |

**Indicadores:** Acesso a arquivos `.php` com parâmetros de execução de comandos (`?cmd=`, `?exec=`).

---

## WEB-005 — Sensitive File Reconnaissance

| Campo | Valor |
|-------|-------|
| **Severidade** | MEDIUM |
| **MITRE Tática** | Reconnaissance |
| **MITRE Técnica** | T1595 — Active Scanning |

**Indicadores:** Requisições para `/.env`, `/phpmyadmin/`, `/.git/config`, `/wp-config.php`.

---

## NET-001 — Port Scan Detected

| Campo | Valor |
|-------|-------|
| **Severidade** | MEDIUM |
| **MITRE Tática** | Reconnaissance |
| **MITRE Técnica** | T1046 — Network Service Discovery |
| **Threshold** | 10+ portas distintas em 30 segundos |

**Indicadores:** Múltiplos pacotes SYN bloqueados no firewall do mesmo IP origem.

---

## IOT-001 — MQTT Topic Anomaly

| Campo | Valor |
|-------|-------|
| **Severidade** | MEDIUM |
| **MITRE Tática** | Lateral Movement |
| **MITRE Técnica** | T1210 — Exploitation of Remote Services |
| **Threshold** | 3+ publicações em tópicos suspeitos em 60s |

**Indicadores:** Tópicos com `../`, `$SYS/`, `/admin/config/`, `/cmd`.

---

## Como Adicionar uma Nova Regra

1. Abrir `rules_engine.py`
2. Adicionar entrada na lista `RULES`:
```python
{
    "id": "XXX-000",
    "name": "Nome da Regra",
    "description": "O que detecta",
    "severity": "HIGH",  # INFO|LOW|MEDIUM|HIGH|CRITICAL
    "mitre_tactic": "Nome da Tática",
    "mitre_technique": "TXXXX — Descrição",
    "event_type": "TIPO_DO_EVENTO",
    "threshold": 1,
    "window_seconds": 60,
}
```
3. Garantir que o `log_generator.py` produza eventos com o `event_type` correspondente
