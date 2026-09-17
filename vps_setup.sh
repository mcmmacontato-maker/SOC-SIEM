#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  vps_setup.sh — Configuração do Honeypot SOC-SIEM
#  Execute UMA vez no VPS como root:
#     bash vps_setup.sh
# ═══════════════════════════════════════════════════════════
set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}[HONEYPOT] Iniciando configuração do honeypot SOC-SIEM...${NC}"

# ── 1. Atualiza o sistema ────────────────────────────────
echo -e "${YELLOW}[1/7] Atualizando pacotes...${NC}"
apt-get update -qq && apt-get upgrade -y -qq

# ── 2. Instala ferramentas úteis ─────────────────────────
echo -e "${YELLOW}[2/7] Instalando utilitários...${NC}"
apt-get install -y -qq \
    curl wget netcat-openbsd net-tools ufw \
    fail2ban rsyslog logrotate python3-pip \
    apache2 nginx 2>/dev/null || true

# ── 3. Configura SSH para atrair atacantes ───────────────
echo -e "${YELLOW}[3/7] Configurando SSH (logging detalhado + auth de senha habilitada)...${NC}"
cat >> /etc/ssh/sshd_config << 'EOF'

# SOC-SIEM Honeypot config
LogLevel VERBOSE
MaxAuthTries 10
PasswordAuthentication yes
PermitRootLogin yes
PubkeyAuthentication yes
X11Forwarding no
AllowTcpForwarding no
EOF

systemctl restart sshd
echo "  SSH reconfigurado: auth por senha HABILITADA para atrair ataques."

# ── 4. Configura rsyslog para logs detalhados ────────────
echo -e "${YELLOW}[4/7] Configurando rsyslog...${NC}"
cat > /etc/rsyslog.d/10-honeypot.conf << 'EOF'
# Log auth com timestamp preciso
$template PreciseTS,"%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg%\n"
auth,authpriv.*  /var/log/auth.log;PreciseTS
EOF
systemctl restart rsyslog 2>/dev/null || true

# ── 5. Desabilita fail2ban (queremos ver os ataques!) ────
echo -e "${YELLOW}[5/7] Desabilitando fail2ban (para honeypot capturar tudo)...${NC}"
systemctl stop fail2ban 2>/dev/null || true
systemctl disable fail2ban 2>/dev/null || true
echo "  fail2ban desabilitado — IPs não serão bloqueados."

# ── 6. Firewall: mantém portas abertas estratégicas ─────
echo -e "${YELLOW}[6/7] Configurando firewall (UFW)...${NC}"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment 'SSH Honeypot'
ufw allow 80/tcp    comment 'HTTP Honeypot'
ufw allow 443/tcp   comment 'HTTPS'
# Porta alternativa de gerenciamento seguro (troque se precisar)
ufw allow 2222/tcp  comment 'SSH Management'
ufw --force enable
echo "  Portas 22, 80, 443, 2222 abertas."

# ── 7. Script de monitoramento local no VPS ──────────────
echo -e "${YELLOW}[7/7] Criando script de status local...${NC}"
cat > /usr/local/bin/honeypot-status << 'SCRIPT'
#!/bin/bash
echo "=== HONEYPOT STATUS ==="
echo "Tentativas SSH (últimas 24h):"
grep "Failed password" /var/log/auth.log | grep "$(date '+%b %e')" | wc -l
echo ""
echo "Top IPs atacantes hoje:"
grep "Failed password" /var/log/auth.log | grep "$(date '+%b %e')" \
  | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -10
echo ""
echo "Usernames mais tentados:"
grep "Failed password" /var/log/auth.log | grep "$(date '+%b %e')" \
  | grep -oE 'for [a-zA-Z0-9_-]+' | sort | uniq -c | sort -rn | head -10
SCRIPT
chmod +x /usr/local/bin/honeypot-status

# ── Resumo ───────────────────────────────────────────────
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "UNKNOWN")
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          HONEYPOT CONFIGURADO COM SUCESSO!            ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  IP Público do VPS: ${PUBLIC_IP}"
echo ""
echo "  Próximo passo — execute LOCALMENTE no seu PC:"
echo ""
echo -e "  ${YELLOW}python vps_collector.py --host ${PUBLIC_IP} --user root --key ~/.ssh/id_rsa${NC}"
echo ""
echo "  Ataques SSH começarão a aparecer em minutos no dashboard!"
echo ""
echo "  Status local: honeypot-status"
