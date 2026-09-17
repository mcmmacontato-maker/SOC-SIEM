"""
incident_responder.py — Fluxo de resposta a incidentes
Cria incidentes, gera playbooks e relatórios de IR em Markdown.
"""
import json
from datetime import datetime, timezone

import siem_db

# ── Playbooks por tipo de ataque ─────────────────────────────────────────
PLAYBOOKS = {
    "SSH Brute-Force Detected": """
## 🛡️ Playbook: SSH Brute-Force

### Contenção Imediata
1. **Bloquear IP atacante no firewall:**
   ```bash
   sudo ufw deny from {source_ip} to any
   # ou iptables:
   sudo iptables -A INPUT -s {source_ip} -j DROP
   ```
2. **Verificar logins bem-sucedidos:**
   ```bash
   grep "Accepted" /var/log/auth.log | grep {source_ip}
   ```
3. **Verificar sessões ativas:**
   ```bash
   who; w; last | head -20
   ```

### Erradicação
4. **Rotacionar credenciais SSH comprometidas**
5. **Forçar autenticação por chave pública (desabilitar senha):**
   ```bash
   # Em /etc/ssh/sshd_config:
   PasswordAuthentication no
   ```
6. **Instalar e configurar Fail2Ban:**
   ```bash
   sudo apt install fail2ban
   ```

### Recuperação
7. **Auditar arquivos modificados nas últimas 24h:**
   ```bash
   find / -newer /tmp/reference_file -type f 2>/dev/null
   ```
8. **Verificar crontabs e serviços instalados:**
   ```bash
   crontab -l; systemctl list-units --state=running
   ```
""",
    "Successful Login After Brute-Force": """
## 🚨 Playbook: Credential Stuffing / Account Compromise

### Contenção Imediata — CRÍTICO
1. **Isolar host imediatamente:**
   ```bash
   sudo ufw default deny incoming; sudo ufw default deny outgoing
   ```
2. **Matar sessão suspeita:**
   ```bash
   pkill -u <usuario_comprometido>
   ```
3. **Bloquear IP no firewall:**
   ```bash
   sudo iptables -A INPUT -s {source_ip} -j DROP
   ```

### Investigação
4. **Coletar evidências (preservar antes de alterar):**
   ```bash
   cp /var/log/auth.log /evidence/auth.log.bak
   ps aux > /evidence/processes.txt
   netstat -antp > /evidence/connections.txt
   ```
5. **Verificar arquivos criados pelo usuário comprometido**
6. **Checar exfiltração de dados (netflow, transferências de arquivo)**

### Erradicação
7. **Revogar credenciais do usuário**
8. **Revogar tokens de API e sessões ativas**
9. **Resetar MFA se aplicável**
""",
    "SQL Injection Attempt": """
## 🛡️ Playbook: SQL Injection

### Contenção
1. **Bloquear IP no WAF/firewall de aplicação:**
   - Adicionar regra de bloqueio no nginx/Apache ou WAF
2. **Verificar se houve exfiltração de dados nos logs do banco**

### Investigação
3. **Analisar query executada e dados acessados**
4. **Verificar integridade da base de dados**

### Remediação
5. **Usar prepared statements em todas as queries**
6. **Implementar WAF com regras OWASP ModSecurity**
7. **Ativar logging detalhado do banco de dados**
""",
    "Webshell Access Detected": """
## 🚨 Playbook: Webshell — INCIDENTE CRÍTICO

### Contenção Imediata
1. **Isolar o servidor web:**
   ```bash
   sudo systemctl stop nginx  # ou apache2
   ```
2. **Identifcar e remover o webshell:**
   ```bash
   find /var/www -name "*.php" -newer /var/www/html/index.php
   ```

### Investigação Forense
3. **Preservar logs de acesso completos**
4. **Verificar comandos executados via webshell**
5. **Checar outros arquivos criados/modificados**

### Remediação
6. **Restaurar a partir de backup limpo**
7. **Implementar monitoramento de integridade de arquivos (AIDE/tripwire)**
""",
    "Port Scan Detected": """
## 🛡️ Playbook: Port Scan / Reconhecimento

### Contenção
1. **Bloquear IP atacante no firewall perimetral**
2. **Ativar rate limiting de conexões SYN**

### Investigação
3. **Correlacionar com outros eventos do mesmo IP**
4. **Verificar se o scan precedeu outro ataque**

### Mitigação
5. **Implementar honeypots em portas de alto risco**
6. **Revisar exposição de serviços na internet**
""",
    "default": """
## 🛡️ Playbook: Resposta Genérica

### Contenção
1. **Isolar o IP atacante no firewall:**
   ```bash
   sudo ufw deny from {source_ip} to any
   ```
2. **Coletar logs relevantes para análise**

### Investigação
3. **Correlacionar o evento com outros alertas do mesmo IP**
4. **Verificar integridade dos sistemas afetados**

### Remediação
5. **Aplicar patches e atualizações de segurança pendentes**
6. **Revisar e endurecer configurações de segurança**
""",
}


def _get_playbook(alert: dict) -> str:
    rule = alert.get("rule_name", "default")
    playbook = PLAYBOOKS.get(rule, PLAYBOOKS["default"])
    return playbook.replace("{source_ip}", alert.get("source_ip", "UNKNOWN_IP"))


def create_incident_from_alert(alert: dict) -> int:
    """Cria um incidente a partir de um alerta HIGH/CRITICAL."""
    title = f"[{alert['severity']}] {alert['rule_name']} — {alert.get('source_ip','?')}"
    playbook = _get_playbook(alert)

    timeline = [
        {
            "time": alert["timestamp"],
            "action": f"Alerta gerado: {alert['rule_name']}",
        },
        {
            "time": datetime.now(timezone.utc).isoformat(),
            "action": "Incidente criado automaticamente pelo SOC-Bot",
        },
    ]

    incident_id = siem_db.insert_incident(
        title=title,
        severity=alert["severity"],
        alert_ids=[alert["id"]],
        playbook=playbook,
        timeline=timeline,
    )

    # Gera relatório imediatamente
    report = generate_ir_report(incident_id, alert, playbook, timeline)
    siem_db.update_incident_report(incident_id, report)
    return incident_id


def generate_ir_report(incident_id: int, alert: dict, playbook: str, timeline: list) -> str:
    """Gera relatório de Incident Response em Markdown."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    mitre_tactic = alert.get("mitre_tactic", "—")
    mitre_technique = alert.get("mitre_technique", "—")
    source_ip = alert.get("source_ip", "Desconhecido")

    timeline_md = "\n".join(
        [f"| {t['time']} | {t['action']} |" for t in timeline]
    )

    report = f"""# Relatório de Incidente — IR-{incident_id:04d}

**Data de Geração:** {now}  
**Classificação:** {alert['severity']}  
**Status:** ABERTO  
**Analista Responsável:** SOC-Bot (automático)  

---

## 1. Sumário Executivo

O sistema SIEM detectou uma atividade maliciosa proveniente do endereço IP **{source_ip}**.
A regra de detecção **"{alert['rule_name']}"** foi disparada às `{alert['timestamp']}`.

**Impacto potencial:** {alert.get('description', '—')}

---

## 2. Detalhes do Incidente

| Campo              | Valor                        |
|--------------------|------------------------------|
| ID do Incidente    | IR-{incident_id:04d}         |
| Severidade         | {alert['severity']}          |
| IP de Origem       | {source_ip}                  |
| Regra Disparada    | {alert['rule_name']}         |
| Tática MITRE       | {mitre_tactic}               |
| Técnica MITRE      | {mitre_technique}            |
| Timestamp          | {alert['timestamp']}         |

---

## 3. Timeline do Incidente

| Timestamp | Ação |
|-----------|------|
{timeline_md}

---

## 4. Resposta e Contenção

{playbook}

---

## 5. Lições Aprendidas

- [ ] Revisar regras de firewall que permitiram o tráfego malicioso
- [ ] Atualizar playbook com informações do incidente
- [ ] Adicionar indicadores de comprometimento (IoCs) ao blocklist
- [ ] Realizar treinamento de conscientização se necessário

---

## 6. Indicadores de Comprometimento (IoCs)

| Tipo | Valor |
|------|-------|
| IP   | {source_ip} |
| Regra| {alert['rule_name']} |

---

*Relatório gerado automaticamente pelo SOC-SIEM Caseiro v1.0*
"""
    return report


if __name__ == "__main__":
    siem_db.init_db()
    alerts = siem_db.get_alerts(status="OPEN")
    print(f"[IR] {len(alerts)} alertas abertos para processamento.")
    for alert in alerts[:3]:
        if alert["severity"] in {"HIGH", "CRITICAL"}:
            iid = create_incident_from_alert(alert)
            print(f"[IR] Incidente IR-{iid:04d} criado para alerta #{alert['id']}")
